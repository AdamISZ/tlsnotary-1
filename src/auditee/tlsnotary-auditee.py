#!/usr/bin/env python
from __future__ import print_function

#Main auditee script.
#This script acts as 
#1. An installer, setting up keys, browser and browser extensions.
#2. A marshaller, passing messages between (a) the javascript/html
#   front end, (b) the Python back-end, including crypto functions
#   and (c) the peer messaging between auditor and auditee.
#3. Performs actual crypto audit functions.

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
from subprocess import Popen, check_output
import binascii, hmac, os, platform,  tarfile
import Queue, random, re, shutil, signal, sys, time
import SimpleHTTPServer, socket, threading, zipfile
try: import wingdbstub
except: pass

#file system setup.
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))
install_dir = os.path.dirname(os.path.dirname(data_dir))
sessions_dir = join(data_dir, 'sessions')
time_str = time.strftime('%d-%b-%Y-%H-%M-%S', time.gmtime())
current_session_dir = join(sessions_dir, time_str)
os.makedirs(current_session_dir)

#OS detection
m_platform = platform.system()
if m_platform == 'Windows': OS = 'mswin'
elif m_platform == 'Linux': OS = 'linux'
elif m_platform == 'Darwin': OS = 'macos'

#Globals
recv_queue = Queue.Queue() #all messages from the auditor are placed here by receiving_thread
ack_queue = Queue.Queue() #ack numbers are placed here
b_peer_connected = False #toggled to True when p2p connection is establishe
auditor_nick = '' #we learn auditor's nick as soon as we get a ao_hello signed by the auditor
my_nick = '' #our nick is randomly generated on connection
my_prv_key = my_pub_key = auditor_pub_key = None
firefox_pid = selftest_pid = 0
audit_no = 0 #we may be auditing multiple URLs. This var keeps track of how many
#successful audits there were so far and is used to index html files audited.
suspended_session = None #while FF validates the certificate
paillier_private_key = None #Auditee's private key. Used for paillier_scheme.
#Generated only once and is reused until the end of the auditing session
b_paillier_privkey_being_generated = True #toggled to False when finished generating the Paillier privkey
#Default values from the config file. Will be overridden after configfile is parsed
global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False

#TESTING only vars
testing = False #toggled when we are running a test suite (developer only)
randomtest = False #randomly toggle some options from ini file
test_driver_pid = 0 #testing only: testdriver's PID used to kill it at quit_clean()
test_auditor_pid = 0 #testing only: auditor's PID used to kill it at quit_clean()

#RSA key management for peer messaging
def import_auditor_pubkey(auditor_pubkey_b64modulus):
    global auditor_pub_key                      
    try:
        auditor_pubkey_modulus = b64decode(auditor_pubkey_b64modulus)
        auditor_pubkey_modulus_int =  shared.ba2int(auditor_pubkey_modulus)
        auditor_pub_key = rsa.PublicKey(auditor_pubkey_modulus_int, 65537)
        auditor_pubkey_pem = auditor_pub_key.save_pkcs1()
        with open(join(current_session_dir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        #also save the key as recent, so that they could be reused in the next session
        if not os.path.exists(join(data_dir, 'recentkeys')): os.makedirs(join(data_dir, 'recentkeys'))
        with open(join(data_dir, 'recentkeys' , 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
        return ('success')
    except Exception,e:
        print (e)
        return ('failure')

def newkeys():
    global my_prv_key,my_pub_key
    #Usually the auditee would reuse a keypair from the previous session
    #but for privacy reasons the auditee may want to generate a new key
    my_pub_key, my_prv_key = rsa.newkeys(1024)

    my_pem_pubkey = my_pub_key.save_pkcs1()
    my_pem_privkey = my_prv_key.save_pkcs1()
    with open(join(current_session_dir, 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(current_session_dir, 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    #also save the keys as recent, so that they could be reused in the next session
    if not os.path.exists(join(data_dir, 'recentkeys')): os.makedirs(join(data_dir, 'recentkeys'))
    with open(join(data_dir, 'recentkeys', 'myprivkey'), 'wb') as f: f.write(my_pem_privkey)
    with open(join(data_dir, 'recentkeys', 'mypubkey'), 'wb') as f: f.write(my_pem_pubkey)
    pubkey_export = b64encode(shared.bi2ba(my_pub_key.n))
    with open(join(data_dir, 'recentkeys', 'mypubkey_export'), 'wb') as f: f.write(pubkey_export)
    return pubkey_export


#Receive AES cleartext and send ciphertext to browser
class HandlerClass_aes(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      

    def do_HEAD(self):
        print ('aes_http received ' + self.path[:80] + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies

        if self.path.startswith('/ready_to_decrypt'):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "status, response, ciphertext, key, iv")
            self.send_header("response", "ready_to_decrypt")
            self.send_header("status", "success")
            #wait for sth to appear in the queue
            ciphertext, key, iv = aes_ciphertext_queue.get()
            self.send_header("ciphertext", b64encode(ciphertext))
            self.send_header("key", b64encode(key))
            self.send_header("iv", b64encode(iv))
            global b_awaiting_cleartext
            b_awaiting_cleartext = True            
            self.end_headers()
            return

        if self.path.startswith('/cleartext'):
            if not b_awaiting_cleartext:
                print ('OUT OF ORDER:' + self.path)
                raise Exception ('received a cleartext request out of order')
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "status, response")
            self.send_header("response", "cleartext")
            self.send_header("status", "success")
            cleartext = b64decode(self.path[len('/cleartext?b64cleartext='):])
            aes_cleartext_queue.put(cleartext)
            b_awaiting_cleartext = False            
            self.end_headers()
            return

    #overriding BaseHTTPServer.py's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          (fmt%args)[:80]))        


#Receive HTTP HEAD requests from FF addon
class HandleBrowserRequestsClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the http server just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = 'HTTP/1.0'

    def respond(self, headers):
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies                
        keys = [k for k in headers]
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Expose-Headers', ','.join(keys))
        for key in headers:
            self.send_header(key, headers[key])
        self.end_headers()        

    def new_keypair(self):
        pubkey_export = newkeys()
        self.respond({'response':'new_keypair', 'pubkey':pubkey_export,
                      'status':'success'})     

    def import_auditor_pubkey(self, args):
        if not args.startswith('pubkey='):
            self.respond({'response':'import_auditor_pubkey', 'status':'wrong HEAD parameter'})
            return
        #else
        auditor_pubkey_b64modulus = args[len('pubkey='):]            
        status = import_auditor_pubkey(auditor_pubkey_b64modulus)           
        self.respond({'response':'import_auditor_pubkey', 'status':status})
        return

    def start_peer_connection(self):
        if global_use_paillier:
            paillier_gen_privkey()
        rv = start_peer_messaging()
        rv2 = peer_handshake()
        global b_peer_connected
        b_peer_connected = True            
        self.respond({'response':'start_peer_connection', 'status':rv,'pms_status':rv2})
        return

    def stop_recording(self):
        rv = stop_recording()
        self.respond({'response':'stop_recording', 'status':rv,
                      'session_path':join(current_session_dir, 'mytrace')})
        return

    def get_certificate(self, args):
        if not args.startswith('b64headers='):
            self.respond({'response':'get_certificate', 'status':'wrong HEAD parameter'})
            return                    
        b64headers = args[len('b64headers='):]
        headers = b64decode(b64headers)
        server_name, modified_headers = parse_headers(headers)        
        print('Probing server to get its certificate')
        try:
            probe_session = shared.TLSNClientSession(server_name, tlsver=global_tlsver)
            probe_sock = shared.create_sock(probe_session.server_name,probe_session.ssl_port)
            probe_session.start_handshake(probe_sock)
        except shared.TLSNSSLError:
            shared.ssl_dump(probe_session)
            raise
        
        probe_sock.close()
        certBase64 = b64encode(probe_session.server_certificate.asn1cert)
        certhash = sha256(probe_session.server_certificate.asn1cert).hexdigest()
        self.respond({'response':'get_certificate', 'status':'success','certBase64':certBase64})
        return [server_name, modified_headers, certhash]


    def start_audit(self, args):
        global global_tlsver
        global global_use_gzip
        global global_use_slowaes
        global global_use_paillier
        global suspended_session

        arg1, arg2 = args.split('&')
        if  not arg1.startswith('server_modulus=') or not arg2.startswith('ciphersuite='):
            self.respond({'response':'start_audit', 'status':'wrong HEAD parameter'})
            return        
        server_modulus_hex = arg1[len('server_modulus='):]
        #modulus is lowercase hexdigest
        server_modulus = bytearray(server_modulus_hex.decode("hex"))
        cs = arg2[len('ciphersuite='):] #used for testing, empty otherwise
        server_name, modified_headers, certhash = suspended_session

        if not global_use_paillier:
            if testing: 
                tlsn_session = shared.TLSNClientSession(server_name, ccs=int(cs), tlsver=global_tlsver)
            else: 
                tlsn_session = shared.TLSNClientSession(server_name, tlsver=global_tlsver)
        else: #use_paillier_scheme
            if testing: 
                tlsn_session = shared.TLSNClientSession_Paillier(server_name, ccs=int(cs), tlsver=global_tlsver)
            else: 
                tlsn_session = shared.TLSNClientSession_Paillier(server_name, tlsver=global_tlsver)
        tlsn_session.server_modulus = shared.ba2int(server_modulus)
        tlsn_session.server_mod_length = shared.bi2ba(len(server_modulus))        
        
        print ('Preparing encrypted pre-master secret')
        if not global_use_paillier:
            #for RSA scheme we prepare encPMS inside prepare_pms()
            prepare_pms(tlsn_session)
        else: #use_paillier_scheme:
            paillier_prepare_encrypted_pms(tlsn_session)

        for i in range(10):
            try:
                print ('Performing handshake with server')
                tls_sock = shared.create_sock(tlsn_session.server_name,tlsn_session.ssl_port)
                tlsn_session.start_handshake(tls_sock)
                retval = negotiate_crippled_secrets(tlsn_session, tls_sock)
                if not retval == 'success': 
                    raise shared.TLSNSSLError('Failed to negotiate secrets: '+retval)                         
                #before sending any data to server compare this connection's cert to the
                #one which FF already validated earlier
                if sha256(tlsn_session.server_certificate.asn1cert).hexdigest() != certhash:
                    raise Exception('Certificate mismatch')   
                print ('Getting data from server')  
                response = make_tlsn_request(modified_headers,tlsn_session,tls_sock)
                #prefix response with number of to-be-ignored records, 
                #note: more than 256 unexpected records will cause a failure of audit. Just as well!
                response = shared.bi2ba(tlsn_session.unexpected_server_app_data_count,fixed=1) + response
                break
            except shared.TLSNSSLError:
                shared.ssl_dump(tlsn_session)
                raise 
            except Exception as e:
                print ('Exception caught while getting data from server, retrying...', e)
                if i == 9:
                    raise Exception('Audit failed')
                continue

        global audit_no
        audit_no += 1 #we want to increase only after server responded with data
        sf = str(audit_no)
        for i in range (10):
            try:
                pms2 = commit_session(tlsn_session, response,sf)
                break
            except Exception, e:
                if i == 9:
                    raise Exception('Audit failed')
                print ('Exception caught while sending a commit to peer, retrying...', e)
                continue

        rv = decrypt_html(pms2, tlsn_session, sf)
        if rv[0] == 'decrypt':
            ciphertexts = rv[1]
            ciphertext, key, iv = ciphertexts[0]
            b64blob = b64encode(iv)+';'+b64encode(key)+';'+b64encode(ciphertext)
            suspended_session = [tlsn_session, ciphertexts, [], 0, sf]
            self.respond({'response':'start_audit', 'status':'success', 
                          'next_action':'decrypt', 'argument':b64blob})
            return
        #else no browser decryption necessary
        html_paths = b64encode(rv[1])
        self.respond({'response':'start_audit', 'status':'success', 'next_action':'audit_finished', 'argument':html_paths})        
        if randomtest:
            randomize_settings()


    def process_cleartext(self, args):
        global suspended_session
        tlsn_session, ciphertexts, plaintexts, index, sf = suspended_session
        raw_cleartext = b64decode(args[len('b64cleartext='):])
        #crypto-js removes pkcs7 padding. There is still an extra byte which we remove it manually
        plaintexts.append(raw_cleartext[:-1])
        if (index+1) < len(ciphertexts):
            index = index + 1
            ciphertext, key, iv = ciphertexts[index]
            b64blob = b64encode(iv)+';'+b64encode(key)+';'+b64encode(ciphertext)
            suspended_session = [tlsn_session, ciphertexts, plaintexts, index, sf]
            self.respond({'response':'cleartext', 'next_action':'decrypt', 
                          'argument':b64blob, 'status':'success'})
            return
        #else this was the last decrypted ciphertext
        plaintext = tlsn_session.mac_check_plaintexts(plaintexts)
        rv = decrypt_html_stage2(plaintext, tlsn_session, sf)
        self.respond({'response':'cleartext', 'status':'success', 'next_action':'audit_finished', 'argument':b64encode(rv[1])})        
        if randomtest:
            randomize_settings()


    def send_link(self, args):
        rv = send_link(args)
        self.respond({'response':'send_link', 'status':rv})
        return              

    def selftest(self):
        auditor_py = join(install_dir, 'src', 'auditor', 'tlsnotary-auditor.py')
        output = check_output([sys.executable, auditor_py, 'daemon', 'genkey'])
        auditor_key = output.split()[-1]
        import_auditor_pubkey(auditor_key)
        print ('Imported auditor key')
        print (auditor_key)
        my_newkey = newkeys()
        proc = Popen([sys.executable, auditor_py, 'daemon', 'hiskey='+my_newkey])
        global selftest_pid
        selftest_pid = proc.pid
        self.respond({'response':'selftest', 'status':'success'})
        return        

    def get_advanced(self):
        self.respond({'irc_server':shared.config.get('IRC','irc_server'),
                      'channel_name':shared.config.get('IRC','channel_name'),'irc_port':shared.config.get('IRC','irc_port')})
        return        

    def set_advanced(self, args):
        args = args.split(',')
        #TODO can make this more generic when there are lots of arguments;
        if not (args[0].split('=')[0] == 'server_val' and args[1].split('=')[0] == 'channel_val' \
                and args[2].split('=')[0] == 'port_val' and args[0].split('=')[1] and \
                args[1].split('=')[1] and args[2].split('=')[1]):
            print ('Failed to reset the irc config. Server was:',args[0].split('=')[1], \
                   ' and channel was: ', args[1].split('=')[1])
            return
        shared.config.set('IRC','irc_server',args[0].split('=')[1])
        shared.config.set('IRC','channel_name',args[1].split('=')[1])
        shared.config.set('IRC','irc_port',args[2].split('=')[1])
        with open(shared.config_location,'wb') as f: shared.config.write(f)
        return        


    def get_recent_keys(self):
        #the very first command from addon 
        #on tlsnotary frst run, there will be no saved keys
        #otherwise we load up the keys saved from previous session
        my_prvkey_pem = my_pubkey_pem = auditor_pubkey_pem = ''
        if os.path.exists(join(data_dir, 'recentkeys')):
            if os.path.exists(join(data_dir, 'recentkeys', 'myprivkey')) and os.path.exists(join(data_dir, 'recentkeys', 'mypubkey')):
                with open(join(data_dir, 'recentkeys', 'myprivkey'), 'rb') as f: my_prvkey_pem = f.read()
                with open(join(data_dir, 'recentkeys', 'mypubkey'), 'rb') as f: my_pubkey_pem = f.read()
                with open(join(current_session_dir, 'myprivkey'), 'wb') as f: f.write(my_prvkey_pem)
                with open(join(current_session_dir, 'mypubkey'), 'wb') as f: f.write(my_pubkey_pem)
                global my_prv_key                    
                my_prv_key = rsa.PrivateKey.load_pkcs1(my_prvkey_pem)
            if os.path.exists(join(data_dir, 'recentkeys', 'auditorpubkey')):
                with open(join(data_dir, 'recentkeys', 'auditorpubkey'), 'rb') as f: auditor_pubkey_pem = f.read()
                with open(join(current_session_dir, 'auditorpubkey'), 'wb') as f: f.write(auditor_pubkey_pem)
                global auditor_pub_key                    
                auditor_pub_key = rsa.PublicKey.load_pkcs1(auditor_pubkey_pem)
            global my_pub_key
            my_pub_key = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
            my_pubkey_export = b64encode(shared.bi2ba(my_pub_key.n))
            if auditor_pubkey_pem == '': auditor_pubkey_export = ''
            else: auditor_pubkey_export = b64encode(shared.bi2ba(auditor_pub_key.n))
            self.respond({'response':'get_recent_keys', 'mypubkey':my_pubkey_export,
                          'auditorpubkey':auditor_pubkey_export})
        else:
            self.respond({'response':'get_recent_keys', 'mypubkey':'', 'auditorpubkey':''})                
        return                        

    def do_HEAD(self):
        request = self.path
        print ('browser sent ' + request[:80] + '... request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        if request.startswith('/get_recent_keys'):
            self.get_recent_keys()
        elif request.startswith('/new_keypair'):
            self.new_keypair()
        elif request.startswith('/import_auditor_pubkey'):
            self.import_auditor_pubkey(request.split('?', 1)[1])        
        elif request.startswith('/start_peer_connection'):
            self.start_peer_connection()
        elif request.startswith('/stop_recording'):
            self.stop_recording()
        elif request.startswith('/get_certificate'):
            global suspended_session
            suspended_session  = self.get_certificate(request.split('?', 1)[1])
        elif request.startswith('/start_audit'):
            self.start_audit(request.split('?', 1)[1])
        elif request.startswith('/send_link'):
            self.send_link(request.split('?', 1)[1])
        elif request.startswith('/selftest'):
            self.selftest()
        elif request.startswith('/get_advanced'):
            self.get_advanced()
        elif request.startswith('/set_advanced'):
            self.set_advanced(request.split('?', 1)[1]) 
        elif request.startswith('/cleartext'):
            self.process_cleartext(request.split('?', 1)[1])   
        else:
            self.respond({'response':'unknown command'})

    #overriding BaseHTTPRequestHandler's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          (fmt%args)[:80]))


def randomize_settings():
    global global_tlsver
    global global_use_gzip
    global global_use_slowaes
    global global_use_paillier
    #set random values before the next page begins to be audited
    global_use_gzip = (True, False)[random.randint(0,1)]
    global_use_slowaes = (True, False, False, False, False, False)[random.randint(0,5)]
    #we dont want to use paillier too often because it takes 2 minutes for 1 audit
    global_use_paillier = (True, False, False, False, False, False)[random.randint(0,5)]
    global_tlsver = (bytearray('\x03\x01'), bytearray('\x03\x02'))[random.randint(0,1)]
    if global_use_paillier:
        #in normal mode, paillier key is generated as soon as we start p2p connection
        #however, in randomtest it is cleaner to generate it on first use
        if not paillier_private_key:
            paillier_gen_privkey()
    print('Settings for next audit: use_gzip', global_use_gzip, 'use_slowaes', global_use_slowaes, 'tlsver', binascii.hexlify(global_tlsver), 'use_paillier',  global_use_paillier)    


def paillier_gen_privkey_thread():
    global paillier_private_key
    paillier_private_key = shared.Paillier(privkey_bits=4096+8)
    global b_paillier_privkey_being_generated
    b_paillier_privkey_being_generated = False

def paillier_gen_privkey():
    thread = threading.Thread(target=paillier_gen_privkey_thread)
    thread.daemon = True
    thread.start()    


#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
#TODO the probability seems to have increased too much w.r.t. random padding, investigate
def prepare_pms(tlsn_session):
    n = shared.bi2ba(tlsn_session.server_modulus)
    rs_choice = random.choice(shared.reliable_sites.keys())
    for i in range(10): #keep trying until reliable site check succeeds
        try:
            pms_session = shared.TLSNClientSession(rs_choice,shared.reliable_sites[rs_choice][0], ccs=53, tlsver=global_tlsver)
            if not pms_session: 
                raise Exception("Client session construction failed in prepare_pms")
            tls_sock = shared.create_sock(pms_session.server_name,pms_session.ssl_port)
            pms_session.start_handshake(tls_sock)
            reply = send_and_recv('rcr_rsr_rsname_n:'+\
                                  pms_session.client_random+pms_session.server_random+rs_choice[:5]+n)
            if reply[0] != 'success': 
                raise Exception ('Failed to receive a reply for rcr_rsr_rsname_n:')
            if not reply[1].startswith('rrsapms_rhmac_rsapms'):
                raise Exception ('bad reply. Expected rrsapms_rhmac_rsapms:')
            reply_data = reply[1][len('rrsapms_rhmac_rsapms:'):]
            rrsapms2 = reply_data[:256]
            pms_session.p_auditor = reply_data[256:304]
            rsapms2 = reply_data[304:]
            response = pms_session.complete_handshake(tls_sock,rrsapms2)
            tls_sock.close()
            if not response:
                print ("PMS trial failed")
                continue
            #judge success/fail based on whether a properly encoded 
            #Change Cipher Spec record is returned by the server (we could
            #also check the server finished, but it isn't necessary)
            if not response.count(shared.TLSRecord(shared.chcis,f='\x01', tlsver=global_tlsver).serialized):
                print ("PMS trial failed, retrying. (",binascii.hexlify(response),")")
                continue
            tlsn_session.auditee_secret = pms_session.auditee_secret
            tlsn_session.auditee_padding_secret = pms_session.auditee_padding_secret		
            tlsn_session.enc_second_half_pms = shared.ba2int(rsapms2)			
            tlsn_session.set_enc_first_half_pms()
            tlsn_session.set_encrypted_pms()
            return
        except shared.TLSNSSLError:
            shared.ssl_dump(pms_session,fn='preparepms_ssldump')
            shared.ssl_dump(tlsn_session)
            raise
        except Exception,e:
            print ('Exception caught in prepare_pms, retrying...', e)
            continue
    raise Exception ('Could not prepare PMS with ', rs_choice, ' after 10 tries. Please '+\
                     'double check that you are using a valid public key modulus for this site; '+\
                     'it may have expired.')


def paillier_prepare_encrypted_pms(tlsn_session):
    #cert_pubkey is lowercase hexdigest
    N_ba = shared.bi2ba(tlsn_session.server_modulus)
    if len(N_ba) > 256:
        raise Exception ('''Can not audit the website with a pubkey length more than 256 bytes.
        Please set use_paillier_scheme = 0 in tlsnotary.ini and rerun tlsnotary''')
    if b_paillier_privkey_being_generated:
        print ('Waiting for Paillier key to finish generating before continuing')
        while b_paillier_privkey_being_generated:
            time.sleep(0.1)
        print ('Paillier private key generated! Continuing.')  
    print ('Preparing enc_pms using Paillier. This usually takes 2 minutes')
    assert paillier_private_key
    for i in range(10):
        try:
            scheme = shared.Paillier_scheme_auditee(paillier_private_key)
            data_for_auditor = scheme.get_data_for_auditor(tlsn_session.auditee_padded_rsa_half, N_ba)
            data_file = join(current_session_dir, 'paillier_data')
            with open(data_file, 'wb') as f: f.write(data_for_auditor)
            try: 
                link = shared.sendspace_getlink(data_file, requests.get, requests.post)
            except:
                raise Exception('Could not use sendspace')  
            reply = send_and_recv('p_link:'+link, timeout=200)
            if reply[0] != 'success':
                raise Exception ('Failed to receive a reply for p_link:')

            for i in range(8):
                if not reply[1].startswith('p_round_or'+str(i)+':'):
                    raise Exception('bad reply. Expected p_round_or'+str(i)+' but got', reply[1][:20])
                E_ba = reply[1][len('p_round_or'+str(i)+':'):]
                F_ba = shared.bi2ba( scheme.do_round(i, shared.ba2int(E_ba)), fixed=513)
                reply = send_and_recv('p_round_ee'+str(i)+':'+F_ba, timeout=10)
                if reply[0] != 'success': 
                    raise Exception ('Failed to receive a reply for p_round_ee'+str(i)+':')

            if not reply[1].startswith('p_round_or8:'):
                raise Exception ('bad reply. Expected p_round_or8 but got', reply[1])
            PSum_ba = reply[1][len('p_round_or8:'):]
            enc_pms = scheme.do_ninth_round(shared.ba2int(PSum_ba))    
            tlsn_session.enc_pms = enc_pms
            break
        except Exception, exc:
            print ('Exception in paillier_prepare_encrypted_pms, retrying...', exc)
            continue


#peer messaging protocol
def send_and_recv (data,timeout=5):
    if not ('success' == shared.tlsn_send_msg(data,auditor_pub_key,ack_queue,auditor_nick,seq_init=None)):
        return ('failure','')
    #receive a response (these are collected into the recv_queue by the receiving thread)
    for i in range(3):
        try: onemsg = recv_queue.get(block=True, timeout=timeout)
        except:  continue 
        return ('success', onemsg)
    return ('failure', '')

#complete audit function
def stop_recording():
    trace_dir = join(current_session_dir, 'mytrace')
    os.makedirs(trace_dir)
    zipf = zipfile.ZipFile(join(trace_dir, 'mytrace.zip'), 'w')
    commit_dir = join(current_session_dir, 'commit')
    com_dir_files = os.listdir(commit_dir)
    for onefile in com_dir_files:
        if not onefile.startswith(('pms_ee','response', 'tlsver', 'origtlsver', 'domain','IV','cs','certificate.der')): continue
        zipf.write(join(commit_dir, onefile), onefile)
    zipf.close()
    path = join(trace_dir, 'mytrace.zip')
    ul_sites = [shared.sendspace_getlink, shared.qfs_getlink]
    #try a random upload site until we either succeed or deplete the list of sites
    was_loadto_used = False
    while True:
        if not len(ul_sites):
            #load.to seems to be blocking certain IPs so we use it as a last resort 
            #when all other sites fail
            if not was_loadto_used:
                ul_sites.append(shared.loadto_getlink)
                was_loadto_used = True
            else:
                raise Exception ('Could not use any of the available upload websites.')
        idx = random.randint(0, len(ul_sites)-1)
        try:
            print ('Uploading trace using ' +  str(ul_sites[idx]))
            link = ul_sites[idx](path, requests.get, requests.post)
            break #success
        except:
            print ('Error sending file using ' + str(ul_sites[idx]) + " Trying another site.")
            ul_sites.pop(idx)
    return send_link(link)

#reconstruct correct http headers
#for passing to TLSNotary custom ssl session
def parse_headers(headers):
    header_lines = headers.split('\r\n') #no new line issues; it was constructed like that
    server = header_lines[1].split(':')[1].strip()
    if not global_use_gzip:
        modified_headers = '\r\n'.join([x for x in header_lines if 'gzip' not in x])
    else:
        modified_headers = '\r\n'.join(header_lines)
    return (server,modified_headers)


def negotiate_crippled_secrets(tlsn_session, tls_sock):
    '''Negotiate with auditor in order to create valid session keys
    (except server mac is garbage as auditor withholds it)'''
    assert tlsn_session.handshake_hash_md5
    assert tlsn_session.handshake_hash_sha
    tlsn_session.set_auditee_secret()
    cs_cr_sr_hmacms_verifymd5sha = chr(tlsn_session.chosen_cipher_suite) + tlsn_session.client_random + \
        tlsn_session.server_random + tlsn_session.p_auditee[:24] +  tlsn_session.handshake_hash_md5 + \
        tlsn_session.handshake_hash_sha
    reply = send_and_recv('cs_cr_sr_hmacms_verifymd5sha:'+cs_cr_sr_hmacms_verifymd5sha)
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply for cs_cr_sr_hmacms_verifymd5sha:')
    if not reply[1].startswith('hmacms_hmacek_hmacverify:'):
        raise Exception ('bad reply. Expected hmacms_hmacek_hmacverify but got', reply[1])
    reply_data = reply[1][len('hmacms_hmacek_hmacverify:'):]
    expanded_key_len = shared.tlsn_cipher_suites[tlsn_session.chosen_cipher_suite][-1]
    if len(reply_data) != 24+expanded_key_len+12:
        raise Exception('unexpected reply length in negotiate_crippled_secrets')
    hmacms = reply_data[:24]    
    hmacek = reply_data[24:24 + expanded_key_len]
    hmacverify = reply_data[24 + expanded_key_len:24 + expanded_key_len+12] 
    tlsn_session.set_master_secret_half(half=2,provided_p_value = hmacms)
    tlsn_session.p_master_secret_auditor = hmacek
    tlsn_session.do_key_expansion()
    tlsn_session.send_client_finished(tls_sock,provided_p_value=hmacverify)
    sha_digest2,md5_digest2 = tlsn_session.set_handshake_hashes(server=True)
    reply = send_and_recv('verify_md5sha2:'+md5_digest2+sha_digest2)
    if reply[0] != 'success':
        raise Exception("Failed to receive a reply for verify_md5sha2")
    if not reply[1].startswith('verify_hmac2:'):
        raise Exception("bad reply. Expected verify_hmac2:")
    if not tlsn_session.check_server_ccs_finished(provided_p_value = reply[1][len('verify_hmac2:'):]):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    return 'success'    

def make_tlsn_request(headers,tlsn_session,tls_sock):
    '''Send TLS request including http headers and receive server response.'''
    try:
        tlsn_session.build_request(tls_sock,headers)
        response = shared.recv_socket(tls_sock) #not handshake flag means we wait on timeout
        if not response: 
            raise Exception ("Received no response to request, cannot continue audit.")
        tlsn_session.store_server_app_data_records(response)
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    
    tls_sock.close()
    #we return the full record set, not only the response to our request
    return tlsn_session.unexpected_server_app_data_raw + response

def commit_session(tlsn_session,response,sf):
    '''Commit the encrypted server response and other data to auditor'''
    commit_dir = join(current_session_dir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    #Serialization of RC4 'IV' requires concatenating the box,x,y elements of the RC4 state tuple
    IV = shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished) \
        if tlsn_session.chosen_cipher_suite in [4,5] else tlsn_session.IV_after_finished
    stuff_to_be_committed  = {'response':response,'IV':IV,
                              'cs':str(tlsn_session.chosen_cipher_suite),
                              'pms_ee':tlsn_session.pms1,'domain':tlsn_session.server_name,
                              'certificate.der':tlsn_session.server_certificate.asn1cert, 
                              'origtlsver':tlsn_session.initial_tlsver, 'tlsver':tlsn_session.tlsver}
    for k,v in stuff_to_be_committed.iteritems():
        with open(join(commit_dir,k+sf),'wb') as f: f.write(v)    
    commit_hash = sha256(response).digest()
    reply = send_and_recv('commit_hash:'+commit_hash)
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply') 
    if not reply[1].startswith('pms2:'):
        raise Exception ('bad reply. Expected pms2')    
    return reply[1][len('pms2:'):]


def decrypt_html(pms2, tlsn_session,sf):
    '''Receive correct server mac key and then decrypt server response (html),
    (includes authentication of response). Submit resulting html for browser
    for display (optionally render by stripping http headers).'''
    try:
        tlsn_session.auditor_secret = pms2[:tlsn_session.n_auditor_entropy]
        tlsn_session.set_auditor_secret()
        tlsn_session.set_master_secret_half() #without arguments sets the whole MS
        tlsn_session.do_key_expansion() #also resets encryption connection state
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    if global_use_slowaes or not tlsn_session.chosen_cipher_suite in [47,53]:
        #either using slowAES or a RC4 ciphersuite
        try:
            plaintext,bad_mac = tlsn_session.process_server_app_data_records()
        except shared.TLSNSSLError:
            shared.ssl_dump(tlsn_session)
            raise
        if bad_mac:
            raise Exception("ERROR! Audit not valid! Plaintext is not authenticated.")
        return decrypt_html_stage2(plaintext, tlsn_session, sf)
    else: #AES ciphersuite and not using slowaes
        try:
            ciphertexts = tlsn_session.get_ciphertexts()
        except:
            shared.ssl_dump(tlsn_session)
            raise
        return ('decrypt', ciphertexts)


def decrypt_html_stage2(plaintext, tlsn_session, sf):
    plaintext = shared.dechunk_http(plaintext)
    if global_use_gzip:    
        plaintext = shared.gunzip_http(plaintext)
    #write a session dump for checking even in case of success
    with open(join(current_session_dir,'session_dump'+sf),'wb') as f: f.write(tlsn_session.dump())
    commit_dir = join(current_session_dir, 'commit')
    html_path = join(commit_dir,'html-'+sf)
    with open(html_path,'wb') as f: f.write('\xef\xbb\xbf'+plaintext) #see "Byte order mark"
    if not int(shared.config.get("General","prevent_render")):
        html_path = join(commit_dir,'forbrowser-'+sf+'.html')
        with open(html_path,'wb') as f:
            f.write('\r\n\r\n'.join(plaintext.split('\r\n\r\n')[1:]))
    return ('success',html_path)

#peer messaging receive thread
def receiving_thread(my_nick, auditor_nick):
    shared.tlsn_msg_receiver(my_nick,auditor_nick,ack_queue,recv_queue,shared.message_types_from_auditor,my_prv_key)

#set up temporary user id and initialise peer messaging
def start_peer_messaging():
    global my_nick
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    shared.tlsn_initialise_messaging(my_nick)
    #if we got here, no exceptions were thrown, which counts as success.
    return 'success'

#perform handshake with auditor over peer messaging channel.
def peer_handshake():
    global my_nick
    global auditor_nick
    shared.import_reliable_sites(join(install_dir,'src','shared'))
    #hello contains the first 10 bytes of modulus of the auditor's pubkey
    #this is how the auditor knows that we are addressing him.
    modulus = shared.bi2ba(auditor_pub_key.n)[:10]
    #pad to 1024bit = 128 bytes
    signed_hello = rsa.sign('ae_hello'+my_nick, my_prv_key, 'SHA-1').rjust(128, '\x00')

    b_is_auditor_registered = False
    for attempt in range(6): #try for 6*5 secs to find the auditor
        if b_is_auditor_registered == True: break #previous iteration successfully regd the auditor
        time_attempt_began = int(time.time())
        shared.tlsn_send_single_msg(' :ae_hello:',modulus+signed_hello,auditor_pub_key)
        signed_hello_message_dict = {}
        full_signed_hello = ''
        while not b_is_auditor_registered:
            if int(time.time()) - time_attempt_began > 5: break
            #ignore decryption errors here, as above, the message may be
            #from someone else's handshake
            x = shared.tlsn_receive_single_msg('ao_hello:',my_prv_key,my_nick,ide=True)
            if not x: continue
            returned_msg,returned_auditor_nick = x
            hdr, seq, signed_hello, ending = returned_msg
            signed_hello_message_dict[seq] = signed_hello
            if 'EOL' in ending:
                sh_message_len = seq + 1
                if range(sh_message_len) == signed_hello_message_dict.keys():
                    for i in range(sh_message_len):
                        full_signed_hello += signed_hello_message_dict[i]
                    try:
                        rsa.verify('ao_hello'+returned_auditor_nick, full_signed_hello, auditor_pub_key)
                        auditor_nick = returned_auditor_nick
                        b_is_auditor_registered = True
                        print ('Auditor successfully verified')
                    except: 
                        raise
                            #return ('Failed to verify the auditor. Are you sure you have the correct auditor\'s pubkey?')

    if not b_is_auditor_registered:
        print ('Failed to register auditor within 60 seconds')
        return 'failure'

    thread = threading.Thread(target= receiving_thread, args=(my_nick, auditor_nick))
    thread.daemon = True
    thread.start()
    return 'success'

#Make a local copy of firefox, find the binary, install the new profile
#and start up firefox with that profile.
def start_firefox(FF_to_backend_port, firefox_install_path):
    #find the binary *before* copying; acts as sanity check
    ffbinloc = {'linux':['firefox'],'mswin':['firefox.exe'],'macos':['Contents','MacOS','firefox']}
    assert os.path.isfile(join(*([firefox_install_path]+ffbinloc[OS]))),\
           "Firefox executable not found - invalid Firefox application directory."

    local_ff_copy = join(data_dir,'Firefox.app') if OS=='macos' else join(data_dir,'firefoxcopy')  

    #check if FF-addon/tlsnotary@tlsnotary files were modified. If so, get a fresh 
    #firefoxcopy and FF-profile. This is useful for developers, otherwise
    #we forget to do it manually and end up chasing wild geese
    filehashes = []
    for root, dirs, files in os.walk(join(data_dir, 'FF-addon', 'tlsnotary@tlsnotary')):
        for onefile in files:
            with open(join(root, onefile), 'rb') as f: filehashes.append(md5(f.read()).hexdigest())
    #sort hashes and get the final hash
    filehashes.sort()
    final_hash = md5(''.join(filehashes)).hexdigest()
    hash_path = join(data_dir, 'ffaddon.md5')
    if not os.path.exists(hash_path):
        with open(hash_path, 'wb') as f: f.write(final_hash)
    else:
        with open(hash_path, 'rb') as f: saved_hash = f.read()
        if saved_hash != final_hash:
            print("FF-addon directory changed since last invocation. Creating a new Firefox profile directory...")
            try:
                shutil.rmtree(join(data_dir, 'FF-profile'))
            except:
                pass
            with open(hash_path, 'wb') as f: f.write(final_hash)            

    firefox_exepath = join(*([firefox_install_path]+ffbinloc[OS]))

    logs_dir = join(data_dir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(data_dir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    shutil.copyfile(join(data_dir,'prefs.js'),join(ffprof_dir,'prefs.js'))
    shutil.copyfile(join(data_dir,'localstore.rdf'),join(ffprof_dir,'localstore.rdf'))
    shutil.copyfile(join(data_dir,'extensions.json'),join(ffprof_dir,'extensions.json'))

    extension_path = join(ffprof_dir, 'extensions', 'tlsnotary@tlsnotary')
    if not os.path.exists(extension_path):
        shutil.copytree(join(data_dir, 'FF-addon', 'tlsnotary@tlsnotary'),extension_path)

    #Disable addon compatibility check on startup
    try:
        application_ini_data = None
        with open(join(firefox_install_path, 'application.ini'), 'r') as f: application_ini_data = f.read()
        version_pos = application_ini_data.find('Version=')+len('Version=')
        #version string can be 34.0 or 34.0.5
        version_raw = application_ini_data[version_pos:version_pos+8]
        version = ''.join(char for char in version_raw if char in '1234567890.')

        with open(join(ffprof_dir, 'prefs.js'), 'a') as f:
            f.write('user_pref("extensions.lastAppVersion", "' + version + '"); ')
    except:
        print ('Failed to disable add-on compatibility check')

    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows
    if not global_use_slowaes:
        os.putenv('TLSNOTARY_USING_BROWSER_AES_DECRYPTION', 'true')

    if testing:
        print ('****************************TESTING MODE********************************')
        os.putenv('TLSNOTARY_TEST', 'true')

    print ('Starting a new instance of Firefox with tlsnotary profile',end='\r\n')
    try: ff_proc = Popen([firefox_exepath,'-no-remote', '-profile', ffprof_dir],
                         stdout=open(join(logs_dir, 'firefox.stdout'),'w'), 
                         stderr=open(join(logs_dir, 'firefox.stderr'), 'w'))
    except Exception,e: return ('Error starting Firefox: %s' %e,)
    return ('success', ff_proc)

#HTTP server to talk with Firefox addon
def http_server(parentthread): 
    print ('Starting http server to communicate with Firefox addon')
    try:
        httpd = shared.StoppableHttpServer(('127.0.0.1', 0), HandleBrowserRequestsClass)
    except Exception, e:
        parentthread.retval = ('failure',)
        return
    #Caller checks thread.retval for httpd status
    parentthread.retval = ('success', httpd.server_port)
    print ('Serving HTTP on port ', str(httpd.server_port), end='\r\n')
    httpd.serve_forever()


#use miniHTTP server to receive commands from Firefox addon and respond to them
def aes_decryption_thread(parentthread):    
    print ('Starting AES decryption server')
    try:
        aes_httpd = shared.StoppableHttpServer(('127.0.0.1', 0), HandlerClass_aes)
    except Exception, e:
        parentthread.retval = ('failure',)
        return
    #Caller checks thread.retval for httpd status
    parentthread.retval = ('success',  aes_httpd.server_port)
    print ('Receiving decrypted AES on port ', str(aes_httpd.server_port), end='\r\n')
    aes_httpd.serve_forever()


#Sending links (urls) to files passed from auditee to
#auditor over peer messaging
def send_link(filelink):
    #we must be very generous with the timeout because
    #the auditor must do his decryption (which could be AES).
    #For single page audits this will very rarely be an issue,
    #but for multi-page or auto testing, it certainly could be.
    reply = send_and_recv('link:'+filelink,timeout=200) 
    if not reply[0] == 'success' : return 'failure'
    if not reply[1].startswith('response:') : return 'failure'
    response = reply[1][len('response:'):]
    return response

#cleanup
def quit_clean(sig=0, frame=0):
    if testing:
        try: os.kill(test_auditor_pid, signal.SIGTERM)
        except: pass #happens when test terminated itself
        try: os.kill(test_driver_pid, signal.SIGTERM)
        except: pass #happens when test terminated itself
    if firefox_pid != 0:
        try: os.kill(firefox_pid, signal.SIGTERM)
        except: pass #firefox not runnng
    if selftest_pid != 0:
        try: os.kill(selftest_pid, signal.SIGTERM)
        except: pass #selftest not runnng    
    exit(1)

#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = join(data_dir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(data_dir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(data_dir, 'python'))
        tar = tarfile.open(join(data_dir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()


#Used during testing only.
#It is best to start testing from this file rather than a standalone one.
#This will increase the likelihood of debugger stopping on breakpoints
def start_testing():
    import subprocess    
    #initiate an auditor window in daemon mode
    print ("TESTING: starting auditor")    
    auditor_py = os.path.join(install_dir, 'src', 'auditor', 'tlsnotary-auditor.py')
    auditor_proc = subprocess.Popen(['python', auditor_py,'daemon'])
    global test_auditor_pid 
    test_auditor_pid = auditor_proc.pid    
    print ("TESTING: starting testdriver")
    testdir = join(install_dir, 'src', 'test')
    test_py = join(testdir, 'tlsnotary-test.py')
    site_list = join (testdir, 'websitelist.txt')
    #testdriver kills ee/or when test ends, passing PIDs
    test_proc = subprocess.Popen(filter(None,['python', test_py, site_list, str(os.getpid()), str(test_auditor_pid)]))
    global test_driver_pid
    test_driver_pid = test_proc.pid



if __name__ == "__main__":
    if ('test' in sys.argv): testing = True
    if ('randomtest' in sys.argv): 
        testing = True
        randomtest = True
    if ('mode=addon' in sys.argv): 
        mode='addon'
    else:
        mode='normal'
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(join(data_dir, 'python', x))

    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation        
    import shared
    shared.load_program_config()
    #override default config values
    if int(shared.config.get("General","tls_11")) == 0: 		
        global_tlsver = bytearray('\x03\x01')
    if int(shared.config.get("General","decrypt_with_slowaes")) == 1:
        global_use_slowaes = True
    if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False
    if int(shared.config.get("General","use_paillier_scheme")) == 1:
        global_use_paillier = True    


    firefox_install_path = None
    if len(sys.argv) > 1: firefox_install_path = sys.argv[1]
    if firefox_install_path in ('test', 'randomtest'): firefox_install_path = None

    if mode == 'normal':
        if not firefox_install_path:
            if OS=='linux':
                if not os.path.exists('/usr/lib/firefox'):
                    raise Exception ("Could not set firefox install path")
                firefox_install_path = '/usr/lib/firefox'
            elif OS=='mswin':
                bFound = False
                prog64 = os.getenv('ProgramW6432')
                prog32 = os.getenv('ProgramFiles(x86)')
                progxp = os.getenv('ProgramFiles')			
                if prog64:
                    if os.path.exists(join(prog64,'Mozilla Firefox')):
                        firefox_install_path = join(prog64,'Mozilla Firefox')
                        bFound = True
                if not bFound and prog32:
                    if os.path.exists(join(prog32,'Mozilla Firefox')):
                        firefox_install_path = join(prog32,'Mozilla Firefox')
                        bFound = True
                if not bFound and progxp:
                    if os.path.exists(join(progxp,'Mozilla Firefox')):
                        firefox_install_path = join(progxp,'Mozilla Firefox')
                        bFound = True
                if not bFound:
                    raise Exception('Could not set firefox install path')
            elif OS=='macos':
                if not os.path.exists(join("/","Applications","Firefox.app")):
                    raise Exception('''Could not set firefox install path. 
                    Please make sure Firefox is in your Applications folder''')
                firefox_install_path = join("/","Applications","Firefox.app")
            else:
                raise Exception("Unrecognised operating system.")           
        print ("Firefox install path is: ",firefox_install_path)
        if not os.path.exists(firefox_install_path): 
            raise Exception ("Could not find Firefox installation")

    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status and FF_to_backend_port  
    b_was_started = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        #else
        if thread.retval[0] != 'success': 
            raise Exception (
                'Failed to start minihttpd server. Please investigate')
        #else
        b_was_started = True
        break
    if b_was_started == False:
        raise Exception ('minihttpd failed to start in 10 secs. Please investigate')
    FF_to_backend_port = thread.retval[1]

    if mode == 'addon':
        with open (join(data_dir, 'ports'), 'w') as f:
            f.write(str(FF_to_backend_port))
    elif mode == 'normal':
        ff_retval = start_firefox(FF_to_backend_port, firefox_install_path)
        if ff_retval[0] != 'success': 
            raise Exception (
                'Error while starting Firefox: '+ ff_retval[0])
        ff_proc = ff_retval[1]
        firefox_pid = ff_proc.pid 

    signal.signal(signal.SIGTERM, quit_clean)

    if testing: start_testing()

    try:
        while True:
            time.sleep(1)
            if mode == 'normal':
                if ff_proc.poll() != None: quit_clean() #FF was closed
    except KeyboardInterrupt: quit_clean()            