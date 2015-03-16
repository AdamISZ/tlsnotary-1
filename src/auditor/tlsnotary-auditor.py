#!/usr/bin/env python
from __future__ import print_function
import base64, binascii, hashlib, hmac, os
import platform, Queue, re, shutil, socket
import SimpleHTTPServer, struct, subprocess
import sys, tarfile, threading, time, random
import urllib2, zipfile
try: import wingdbstub
except: pass

#file system setup.
datadir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(datadir))
installdir = os.path.dirname(os.path.dirname(datadir))
sessionsdir = os.path.join(datadir, 'sessions')
time_str = time.strftime("%d-%b-%Y-%H-%M-%S", time.gmtime())
current_sessiondir = os.path.join(sessionsdir, time_str)
os.makedirs(current_sessiondir)

#OS detection
platform = platform.system()
if platform == 'Windows': OS = 'mswin'
elif platform == 'Linux': OS = 'linux'
elif platform == 'Darwin': OS = 'macos'

#Globals
my_nick = ''
auditee_nick = ''
my_private_key = my_pub_key = auditee_public_key = None
recv_queue = Queue.Queue() #all messages destined for me
ack_queue = Queue.Queue() #auditee ACKs
progress_queue = Queue.Queue() #messages intended to be displayed by the frontend
rs_choice = 0
b_terminate_all_threads = False

#peer messaging receive thread
def receiving_thread():
    shared.tlsn_msg_receiver(my_nick,auditee_nick,ack_queue,recv_queue,shared.message_types_from_auditee,my_private_key,seq_init=None)

#send a single message over peer messaging
def send_message(data):
    if ('success' == shared.tlsn_send_msg(data,auditee_public_key,ack_queue,auditee_nick)):
        return ('success',)
    else:
        return ('failure',)
 
#Main thread which receives messages from auditee over peer messaging,
#and performs crypto auditing functions.
def process_messages():
    while True:
        try: msg = recv_queue.get(block=True, timeout=1)
        except: continue
        
        #rcr_rsr - reliable site client random, server random.
        #Receiving this data, the auditor generates his half of the 
        #premaster secret, and returns the hashed version, along with
        #the half-pms encrypted to the server's pubkey
        if msg.startswith('rcr_rsr:'):                
            msg_data = msg[len('rcr_rsr:'):]
            tlsn_session = shared.TLSNClientSession()
            rsp_session = shared.TLSNClientSession()
            rsp_session.client_random = msg_data[:32]
            rsp_session.server_random = msg_data[32:64]
            #pubkey required to set encrypted pms
            rsp_session.server_modulus = int(shared.reliable_sites[rs_choice][1],16)
            rsp_session.server_exponent = 65537
            #TODO currently can only handle 2048 bit keys for 'reliable site'
            rsp_session.server_mod_length = shared.bi2ba(256)
            rsp_session.set_auditor_secret()
            rsp_session.set_enc_second_half_pms()           
            rrsapms = shared.bi2ba(rsp_session.enc_second_half_pms)
            send_message('rrsapms_rhmac:'+ rrsapms+rsp_session.p_auditor)
            #we keep resetting so that the final, successful choice of secrets are stored
            tlsn_session.auditor_secret = rsp_session.auditor_secret
            tlsn_session.auditor_padding_secret = rsp_session.auditor_padding_secret
            continue
        #---------------------------------------------------------------------#
        #cs_cr_sr_hmacms_verifymd5sha : sent by auditee at the start of the real audit.
        #client random, server random, md5 hmac of auditee's PMS half, client handshake hashes (md5 and sha)
        #Then construct master secret half, hmac for expanded keys. Note that the 
        #HMAC is 'garbageized', meaning some bytes are set as random garbage, so that 
        #the auditee's expanded keys will be invalid for that section (specifically -
        #the server mac key). Finally send back to auditee the hmac half for the
        #master secret half and the hmac for the expanded keys and auditor's half
        #of the HMAC needed to construct the PRF output for the verify data
        #which is needed to construct the Client Finished handshake final message.        
        #message (hmacms_hmacek_hmacverify).
        elif msg.startswith('cs_cr_sr_hmacms_verifymd5sha:'): 
            progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Processing data from the auditee.')
            request = msg[len('cs_cr_sr_hmacms_verifymd5sha:'):]
            assert len(request) == 125
            tlsn_session.chosen_cipher_suite = int(request[:1].encode('hex'),16)
            tlsn_session.client_random = request[1:33]
            tlsn_session.server_random = request[33:65]
            md5_hmac1_for_ms=request[65:89] #half of MS's 48 bytes
            verify_md5 = request[89:105]
            verify_sha = request[105:125]
            tlsn_session.set_auditor_secret()
            tlsn_session.set_master_secret_half(half=1,provided_p_value=md5_hmac1_for_ms)         
            garbageized_hmac = tlsn_session.get_p_value_ms('auditor',[2]) #withhold the server mac
            #TODO: I thought the convention was that the auditor always does the SHA part of PRF
            #however, here he does MD5.
            hmac_verify_md5 = tlsn_session.get_verify_hmac(verify_sha, verify_md5, half=1) 
            if not tlsn_session.auditor_secret: 
                raise Exception("Auditor PMS secret data should have already been set.")            
            hmacms_hmacek_hmacverify = tlsn_session.p_auditor[24:]+garbageized_hmac+hmac_verify_md5
            send_message('hmacms_hmacek_hmacverify:'+ hmacms_hmacek_hmacverify)
            continue
        #---------------------------------------------------------------------#
        #n_e: Server pubkey's modulus and exponent used to construct the
        #second half of encrypted PMS
        #This is done before the audit starts to cut down online time
        elif msg.startswith('n_e:'): 
            n_e = msg[len('n_e:'):]
            n_len_int = int(n_e[:2].encode('hex'),16)
            n = n_e[2:2+n_len_int]
            e = n_e[2+n_len_int:2+n_len_int+3]
            tlsn_session.server_modulus = int(n.encode('hex'),16)
            tlsn_session.server_exponent = int(e.encode('hex'),16)
            tlsn_session.server_mod_length = shared.bi2ba(n_len_int)
            if not tlsn_session.auditor_secret: 
                raise Exception("Auditor PMS secret data should have already been set.")
            tlsn_session.set_enc_second_half_pms() #will set the enc PMS second half
            rsapms =  shared.bi2ba(tlsn_session.enc_second_half_pms)
            send_message('rsapms:'+ rsapms)
            continue

        #---------------------------------------------------------------------#
        #Receive from the auditee the client handshake hashes (md5 and sha) and return
        #auditor's half of the HMAC needed to construct the PRF output for the verify data
        #which is needed to verify the Server Finished handshake final message.
        elif msg.startswith('verify_md5sha2:'):
            md5sha2 = msg[len('verify_md5sha2:'):]
            md5hmac2 = tlsn_session.get_verify_hmac(md5sha2[16:],md5sha2[:16],half=1,is_for_client=False)
            send_message('verify_hmac2:'+md5hmac2)
            continue
        #------------------------------------------------------------------------------------------------------#    
        #Receive from the auditee the sha256 hashes of the ciphertext response sent by the server,
        #as a commitment (note that the auditee does not yet possess the master secret and so cannot
        #yet fake this data). Once received and written to disk, the auditor can pass the secret
        #material (sha1hmac for MS) which the auditee needs to reconstruct the full master secret and
        #so decrypt the server response safely.
        elif msg.startswith('commit_hash:'):
            commit_hash = msg[len('commit_hash:'):]
            response_hash = commit_hash[:32]
            md5hmac_hash = commit_hash[32:64]
            commit_dir = os.path.join(current_sessiondir, 'commit')
            if not os.path.exists(commit_dir): os.makedirs(commit_dir)
            #file names are assigned sequentially hash1, hash2 etc.
            #The auditee must provide responsefiles response1, response2 corresponding
            #to these sequence numbers.
            commdir_list = os.listdir(commit_dir)
            #get last seqno
            seqnos = [int(one_response[len('responsehash'):]) for one_response
                      in commdir_list if one_response.startswith('responsehash')]
            last_seqno = max([0] + seqnos) #avoid throwing by feeding at least one value 0
            my_seqno = last_seqno+1
            response_hash_path = os.path.join(commit_dir, 'responsehash'+str(my_seqno))
            n_hexlified = binascii.hexlify(shared.bi2ba(tlsn_session.server_modulus))
            #pubkey in the format 09 56 23 ....
            n_write = " ".join(n_hexlified[i:i+2] for i in range(0, len(n_hexlified), 2)) 
            pubkey_path = os.path.join(commit_dir, 'pubkey'+str(my_seqno))
            response_hash_path = os.path.join(commit_dir, 'responsehash'+str(my_seqno))
            md5hmac_hash_path =  os.path.join(commit_dir, 'md5hmac_hash'+str(my_seqno))
            with open(pubkey_path, 'wb') as f: f.write(n_write)            
            with open(response_hash_path, 'wb') as f: f.write(response_hash)
            with open(md5hmac_hash_path, 'wb') as f: f.write(md5hmac_hash)
            sha1hmac_path = os.path.join(commit_dir, 'sha1hmac'+str(my_seqno))
            with open(sha1hmac_path, 'wb') as f: f.write(tlsn_session.p_auditor)
            cr_path = os.path.join(commit_dir, 'cr'+str(my_seqno))
            with open(cr_path, 'wb') as f: f.write(tlsn_session.client_random)
            sr_path = os.path.join(commit_dir,'sr'+str(my_seqno))
            with open(sr_path,'wb') as f: f.write(tlsn_session.server_random)
            send_message('sha1hmac_for_MS:'+tlsn_session.p_auditor)
            continue  
        #---------------------------------------------------------------------#
        #Phase 1: Receive a url from the auditee from which can be downloaded a zip file containing
        #all relevant data: the full encrypted server response, and the "reveals" from the
        #commits sent previously. Confirm the commitments are valid by comparing hashes.
        #Phase 2: Then reconstruct a ssl client session object with a correct full master
        #secret in order to decrypt the server response, and write to disk along with the
        #claimed server pubkey (which should be checked manually). Finally indicate success
        #or failure
        elif msg.startswith('link:'):
            #PHASE 1
            link = msg[len('link:'):]
            time.sleep(1) #just in case the upload server needs some time to prepare the file
            req = urllib2.Request(link)
            resp = urllib2.urlopen(req)
            linkdata = resp.read()
            with open(os.path.join(current_sessiondir, 'auditeetrace.zip'), 'wb') as f : f.write(linkdata)
            zipf = zipfile.ZipFile(os.path.join(current_sessiondir, 'auditeetrace.zip'), 'r')
            auditeetrace_dir = os.path.join(current_sessiondir, 'auditeetrace')
            zipf.extractall(auditeetrace_dir)
            link_response = 'success' #unless overridden by a failure in sanity check
            #sanity: all trace names must be unique and their hashes must correspond to the
            #hashes which the auditee committed to earlier
            adir_list = os.listdir(auditeetrace_dir)
            seqnos = []
            for one_response in adir_list:
                if not one_response.startswith('response'): continue
                try: this_seqno = int(one_response[len('response'):])
                except: 
                    raise Exception ('WARNING: Could not cast response\'s tail to int')
                if this_seqno in seqnos: 
                    raise Exception ('WARNING: multiple responsefiles names detected')
                saved_hash_path = os.path.join(commit_dir, 'responsehash'+str(this_seqno))
                if not os.path.exists(saved_hash_path): 
                    raise Exception ('WARNING: Auditee gave a response number which doesn\'t have a committed hash')
                with open(saved_hash_path, 'rb') as f: saved_hash = f.read()
                with open(os.path.join(auditeetrace_dir, one_response), 'rb') as f: responsedata = f.read()
                response_hash = hashlib.sha256(responsedata).digest()
                if not saved_hash == response_hash:
                    raise Exception ('WARNING: response\'s hash doesn\'t match the hash committed to')
                iv_path = os.path.join(auditeetrace_dir,'IV'+str(this_seqno))
                if not os.path.exists(iv_path):
                    raise Exception("WARNING: Could not find IV block in auditeetrace")
                md5hmac_path = os.path.join(auditeetrace_dir, 'md5hmac'+str(this_seqno))
                if not os.path.exists(md5hmac_path):
                    raise Exception ('WARNING: Could not find md5hmac in auditeetrace')
                with open(md5hmac_path, 'rb') as f: md5hmac_data = f.read()
                md5hmac_hash = hashlib.sha256(md5hmac_data).digest()
                with open(os.path.join(commit_dir, 'md5hmac_hash'+str(this_seqno)), 'rb') as f: commited_md5hmac_hash = f.read()
                if not md5hmac_hash == commited_md5hmac_hash:
                    raise Exception ('WARNING: mismatch in committed md5hmac hashes')
                domain_path = os.path.join(auditeetrace_dir, 'domain'+str(this_seqno))
                if not os.path.exists(domain_path):
                    raise Exception ('WARNING: Could not find domain in auditeetrace')                
                #elif no errors
                seqnos.append(this_seqno)
                continue
            #PHASE 2
            decr_dir = os.path.join(current_sessiondir, 'decrypted')
            os.makedirs(decr_dir)
            for one_response in adir_list:
                if not one_response.startswith('response'): continue
                seqno = one_response[len('response'):]
                decr_data = {}
                for fname in ['md5hmac','response','IV','cs']:
                    with open(os.path.join(auditeetrace_dir, fname+seqno), 'rb') as f: 
                        decr_data[fname] = f.read()
                for fname in ['sha1hmac','cr','sr']:
                    with open(os.path.join(commit_dir, fname+seqno), 'rb') as f: 
                        decr_data[fname] = f.read()
                tlsver = decr_data['response'][1:3]
                decr_session = shared.TLSNClientSession(ccs = int(decr_data['cs']), tlsver=tlsver)
                #update TLS protocol dynamically based on response content
                decr_session.client_random = decr_data['cr']
                decr_session.server_random = decr_data['sr']
                decr_session.p_auditee = decr_data['md5hmac']
                decr_session.p_auditor = decr_data['sha1hmac']
                decr_session.set_master_secret_half()
                decr_session.do_key_expansion()
                decr_session.store_server_app_data_records(decr_data['response'])
                #if RC4, we need to unpack the RC4 state from the IV data
                IV = (map(ord,decr_data['IV'][:256]),ord(decr_data['IV'][256]),ord(decr_data['IV'][257])) \
                    if decr_session.chosen_cipher_suite in [4,5] else decr_data['IV']
                decr_session.IV_after_finished = IV
                plaintext, bad_mac = decr_session.process_server_app_data_records(is_for_auditor=True)
                if bad_mac:
                    link_response = 'false'
                    raise Exception("AUDIT FAILURE - invalid mac")
                plaintext = shared.dechunk_http(plaintext)
                plaintext = shared.gunzip_http(plaintext)
                path = os.path.join(decr_dir, 'html-'+seqno)
                with open(path, 'wb') as f: f.write(plaintext) #TODO maybe strip headers?
                #also create a file where the auditor can see the domain and pubkey
                with open (os.path.join(auditeetrace_dir, 'domain'+seqno), 'rb') as f: domain_data = f.read()
                with open (os.path.join(commit_dir, 'pubkey'+seqno), 'rb') as f: pubkey_data = f.read()
                with open (os.path.join(auditeetrace_dir, 'certificate.der'+seqno), 'rb') as f: certDER = f.read()
                certPEM = base64.b64encode(certDER)
                write_data = domain_data + '\n\n'
                write_data += """
You must paste the code below into the Browser Console of Mozilla Firefox to finish the audit.
1. Enable the Browser Console by pressing Ctrl+Shift+I or from menu Tools-Web Developer-Toggle Tools
2. In the upper right corner of the appeared console click a cogwheel icon (Toolbox Options)
3. Scroll down a little and check "Enable chrome and add-on debugging" in the right hand side column
4. Bring up Browser Console by pressing Ctrl+Shift+J or from menu Tools-Web Developer-Browser Console
5. Paste the code below where the blinking cursor is at the bottom of the Browser Console and press Enter
----------------------COPY AND PASTE THE CODE BELOW THIS LINE INTO THE BROWSER CONSOLE---------------

function verifyCert(certBase64){
	const {classes: Cc, interfaces: Ci} = Components;
	const nsIX509CertDB = Ci.nsIX509CertDB;
	const nsX509CertDB = "@mozilla.org/security/x509certdb;1";
	const nsIX509Cert = Ci.nsIX509Cert;
	let certdb = Cc[nsX509CertDB].getService(nsIX509CertDB);
	let cert = certdb.constructX509FromBase64(certBase64);
	let a = {}, b = {};
	let retval = certdb.verifyCertNow(cert, nsIX509Cert.CERT_USAGE_SSLServer, nsIX509CertDB.FLAG_LOCAL_ONLY, a, b);
	if (retval == 0){alert(cert.commonName + ' was successfully verified')}
	else {alert('FAILED TO VERIFY')}
}
let cert =""" + '"' + certPEM + '"' + "\n" + "verifyCert(cert)"
                write_data += '\n\n'
                #format pubkey in nice rows of 16 hex numbers just like Firefox does
                #we may need this later
                #for i in range(1+len(pubkey_data)/48):
                 #   write_data += pubkey_data[i*48:(i+1)*48] + '\n' 
                with open(os.path.join(decr_dir, 'README'+seqno), 'wb') as f: f.write(write_data)
               
            send_message('response:'+link_response)            
            if link_response == 'success':
                progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': The auditee has successfully finished the audit session')
            else:
                progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': WARNING!!! The auditee FAILED the audit session')
            progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': Decrypting  auditee\'s data')
            progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': All decrypted HTML can be found in ' + decr_dir)
            progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + ': You may now close the browser.')
            continue
    #---------------------------------------------------------------------#
    #Paillier scheme
        elif msg.startswith('p_link:'):
            p_link = msg[len('p_link:'):]
            tlsn_session = shared.TLSNClientSession_Paillier()            
            time.sleep(1) #just in case the upload server needs some time to prepare the file
            req = urllib2.Request(p_link)
            resp = urllib2.urlopen(req)
            linkdata = resp.read()
            
            assert len(linkdata) == (256+513+1026*(3*8+2))
            tlsn_session.server_modulus = shared.ba2int(linkdata[:256])
            scheme = shared.Paillier_scheme_auditor(tlsn_session.auditor_padded_rsa_half, linkdata)
            E1 = scheme.do_round(0, None)
            send_message('p_round_or0:'+shared.bi2ba(E1, fixed=1026))
            continue
        
        elif msg.startswith('p_round_ee'):
            round_no  = int( msg[len('p_round_ee'):len('p_round_ee')+1] )
            assert round_no < 8
            F_ba = msg[len('p_round_ee'+str(round_no)+':'):]
            if round_no == 7:
                E = scheme.do_ninth_round(shared.ba2int(F_ba))
            else:
                E = scheme.do_round(round_no+1, shared.ba2int(F_ba))
            send_message('p_round_or'+str(round_no+1)+':'+shared.bi2ba(E, fixed=1026))
            continue      
    
      
#Receive HTTP HEAD requests from FF extension. This is how the extension communicates with python backend.
class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      
    
    def respond(self, headers):
        # we need to adhere to CORS and add extra headers in server replies        
        keys = [k for k in headers]
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Expose-Headers', ','.join(keys))
        for key in headers:
            self.send_header(key, headers[key])
        self.end_headers()                    

    def do_HEAD(self):                
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/page_marked?accno=12435678&sum=1234.56&time=1383389835"    
        if self.path.startswith('/get_recent_keys'):
            my_pubkey_export, auditee_pubkey_export = get_recent_keys()
            self.respond({'response':'get_recent_keys', 'mypubkey':my_pubkey_export,
                                             'auditeepubkey':auditee_pubkey_export})
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/new_keypair'):
            my_pubkey_export = new_keypair()
            self.respond({'response':'new_keypair', 'pubkey':my_pubkey_export})                        
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/import_auditee_pubkey'):
            arg_str = self.path.split('?', 1)[1]
            if not arg_str.startswith('pubkey='):
                self.respond({'response':'import_auditee_pubkey', 'status':'wrong HEAD parameter'})                        
                return
            auditee_pubkey_b64modulus = arg_str[len('pubkey='):]            
            import_auditee_pubkey(auditee_pubkey_b64modulus)
            self.respond({'response':'import_auditee_pubkey', 'status':'success'})                                    
            return
       #----------------------------------------------------------------------# 
        if self.path.startswith('/start_peer_connection'):
            #connect, send hello to the auditor and get a hello in return
            rv = start_peer_messaging()
            self.respond({'response':'start_peer_connection', 'status':rv})
            return
        #----------------------------------------------------------------------#
        if self.path.startswith('/progress_update'):
            #receive this command in a loop, blocking for 30 seconds until there is something to respond with
            update = 'no update'
            time_started = int(time.time())
            while int(time.time()) - time_started < 30:
                try: 
                    update = progress_queue.get(block=False)
                    break #something in the queue
                except:
                    if b_terminate_all_threads: break
                    time.sleep(1) #nothing in the queue
            self.respond({'response':'progress_update', 'update':update})
            return
        #----------------------------------------------------------------------#
        else:
            self.respond({'response':'unknown command'})
            return
        
#Peer connection key management    
def import_auditee_pubkey(auditee_pubkey_b64modulus): 
    auditee_pubkey_modulus = base64.b64decode(auditee_pubkey_b64modulus)
    auditee_pubkey_modulus_int = int(auditee_pubkey_modulus.encode('hex'),16)
    global auditee_public_key    
    auditee_public_key = rsa.PublicKey(auditee_pubkey_modulus_int, 65537)         
    auditee_pubkey_pem = auditee_public_key.save_pkcs1()                
    with open(os.path.join(current_sessiondir, 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
    #also save the key as recent, so that they could be reused in the next session
    if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
    with open(os.path.join(datadir, 'recentkeys' , 'auditeepubkey'), 'w') as f: f.write(auditee_pubkey_pem)
        
def get_recent_keys():
    global my_private_key
    global auditee_public_key
    global my_pub_key
    #this is the very first command that we expect in a new session.
    #If this is the very first time tlsnotary is run, there will be no saved keys
    #otherwise we load up the saved keys which the user can override with new keys if need be
    my_pubkey_export = auditee_pubkey_export = ''
    if os.path.exists(os.path.join(datadir, 'recentkeys')):
        if os.path.exists(os.path.join(datadir, 'recentkeys', 'myprivkey')) and os.path.exists(os.path.join(datadir, 'recentkeys', 'mypubkey')):
            with open(os.path.join(datadir, 'recentkeys', 'myprivkey'), 'r') as f: my_privkey_pem = f.read()
            with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'r') as f: my_pubkey_pem = f.read()
            with open(os.path.join(current_sessiondir, 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
            with open(os.path.join(current_sessiondir, 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
            my_private_key = rsa.PrivateKey.load_pkcs1(my_privkey_pem)
            my_pub_key = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
            my_pubkey_export = base64.b64encode(shared.bi2ba(my_pub_key.n))
        if os.path.exists(os.path.join(datadir, 'recentkeys', 'auditeepubkey')):
            with open(os.path.join(datadir, 'recentkeys', 'auditeepubkey'), 'r') as f: auditee_pubkey_pem = f.read()
            with open(os.path.join(current_sessiondir, 'auditorpubkey'), 'w') as f: f.write(auditee_pubkey_pem)
            auditee_public_key = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            auditee_pubkey = rsa.PublicKey.load_pkcs1(auditee_pubkey_pem)
            auditee_pubkey_export = base64.b64encode(shared.bi2ba(auditee_pubkey.n))
    return my_pubkey_export, auditee_pubkey_export
      
def new_keypair():
    global my_private_key
    global my_pub_key
    my_pub_key, my_private_key = rsa.newkeys(1024)
    my_pubkey_pem = my_pub_key.save_pkcs1()
    my_privkey_pem = my_private_key.save_pkcs1()
    #------------------------------------------
    with open(os.path.join(current_sessiondir, 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
    with open(os.path.join(current_sessiondir, 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
    #also save the keys as recent, so that they could be reused in the next session
    if not os.path.exists(os.path.join(datadir, 'recentkeys')): os.makedirs(os.path.join(datadir, 'recentkeys'))
    with open(os.path.join(datadir, 'recentkeys' , 'myprivkey'), 'w') as f: f.write(my_privkey_pem)
    with open(os.path.join(datadir, 'recentkeys', 'mypubkey'), 'w') as f: f.write(my_pubkey_pem)
    my_pubkey_export = base64.b64encode(shared.bi2ba(my_pub_key.n))
    with open(os.path.join(datadir, 'recentkeys', 'mypubkey_export'), 'w') as f: f.write(my_pubkey_export)
    return my_pubkey_export

#Thread to wait for arrival of auditee in peer messaging channel
#and perform peer handshake according to tlsnotary messaging protocol
def register_auditee_thread():
    global auditee_nick
    global rs_choice
    global my_pub_key
    shared.import_reliable_sites(os.path.join(installdir,'src','shared'))
    with open(os.path.join(current_sessiondir, 'mypubkey'), 'r') as f: my_pubkey_pem =f.read()
    my_pub_key = rsa.PublicKey.load_pkcs1(my_pubkey_pem)
    my_modulus = shared.bi2ba(my_pub_key.n)[:10]
    full_hello = ''
    while not b_terminate_all_threads:
        #NB we must allow decryption errors for this message, since another
        #handshake might be going on at the same time.
        try:
            x = shared.tlsn_receive_single_msg(':ae_hello:',my_private_key,ide=True)
            if not x: continue
            msg_array,nick = x
            header, seq, msg, ending = msg_array
            if not 'ae_hello' in header: continue
            full_hello += msg            
            if ending == 'CRLF':
                continue
            modulus = full_hello[:10] #this is the first 10 bytes of modulus of auditor's pubkey
            sig = str(full_hello[10:138]) #this is a sig for 'ae_hello||auditee nick'. The auditor is expected to have received auditee's pubkey via other channels
            rs_choice = full_hello[138:]
            if not (rs_choice in shared.reliable_sites):
                raise Exception('Unknown reliable site', rs_choice)
            if modulus != my_modulus:
                raise Exception ('Not my modulus', modulus)
            rsa.verify('ae_hello'+nick, sig, auditee_public_key)
            print ('Auditee successfully verified')
            auditee_nick = nick
            break
        except Exception,e:
            print ('Verification of a hello message failed', e)
            auditee_nick=''#erase the nick so that the auditee could try registering again
            full_hello = ''
            continue
    #we get here if auditee was successfully verified
    signed_hello = rsa.sign('ao_hello'+my_nick, my_private_key, 'SHA-1')
    #send twice because it was observed that the msg would not appear on the chan
    for x in range(2):
        shared.tlsn_send_single_msg(':ao_hello',signed_hello,auditee_public_key,ctrprty_nick = auditee_nick)
        time.sleep(2)

    progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) + \
                      ': Auditee has been authorized. Awaiting data...')
    thread = threading.Thread(target= receiving_thread)
    thread.daemon = True
    thread.start()
    thread = threading.Thread(target= process_messages)
    thread.daemon = True
    thread.start()
    
#Initialise peer messaging channel with the auditee
def start_peer_messaging():
    global my_nick
    #we should take any IRC settings from the config file
    #*immediately* before connecting, because in self-test mod
    #it can be reset by the auditee
    shared.config.read(shared.config_location)
    progress_queue.put(time.strftime('%H:%M:%S', time.localtime()) +\
    ': Connecting to '+shared.config.get('IRC','irc_server')+' and joining #'\
    +shared.config.get('IRC','channel_name'))
    my_nick= 'user' + ''.join(random.choice('0123456789') for x in range(10))
    shared.tlsn_initialise_messaging(my_nick)
    #if we got here, no exceptions were thrown, which counts as success.
    thread = threading.Thread(target= register_auditee_thread)
    thread.daemon = True
    thread.start()
    return 'success'

#use http server to talk to auditor.html
def http_server(parentthread): 
    print ('Starting http server to communicate with auditor panel')    
    #for the GET request, serve files only from within the datadir
    os.chdir(datadir)
    try: 
        httpd = shared.StoppableThreadedHttpServer(('127.0.0.1', 0), Handler)
    except Exception, e:
        print ('Error starting mini http server', e, end='\r\n')
        exit(1)
   #Caller checks thread.retval for httpd status
    parentthread.retval = ('success', httpd.server_port)
    print ("Serving HTTP on", str(httpd.server_port), end='\r\n') 
    httpd.serve_forever()


#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = os.path.join(datadir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(os.path.join(datadir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
        if hashlib.md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(os.path.join(datadir, 'python'))
        tar = tarfile.open(os.path.join(datadir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()
        
if __name__ == "__main__":
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                           'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                           'slowaes':''}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(os.path.join(datadir, 'python', x))    
    import rsa
    import pyasn1
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation
    import shared
    shared.load_program_config()   
    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status   
    b_was_started = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        elif thread.retval[0] == 'failure': 
            raise Exception('MINIHTTPD_FAILURE')
        elif thread.retval[0] == 'success':
            b_was_started = True
            break
        else: 
            raise Exception('MINIHTTPD_WRONG_RESPONSE')
    if b_was_started == False: 
        raise Exception('MINIHTTPD_START_TIMEOUT')
    FF_to_backend_port = thread.retval[1]
    
    daemon_mode = False
    if len(sys.argv) > 1:
        if sys.argv[1] == 'daemon':
            daemon_mode = True
            print('Running auditor in daemon mode')
        
    if OS=='mswin':
        prog64 = os.getenv('ProgramW6432')
        prog32 = os.getenv('ProgramFiles(x86)')
        progxp = os.getenv('ProgramFiles')                
        browser_exepath= ''
        if prog64:
            ff64 = os.path.join(prog64, "Mozilla Firefox",  "firefox.exe")
            if os.path.isfile(ff64): browser_exepath = ff64           
        if prog32:            
            ff32 = os.path.join(prog32, "Mozilla Firefox",  "firefox.exe" )
            if os.path.isfile(ff32): browser_exepath = ff32            
        if progxp:
            ff32 = os.path.join(progxp, "Mozilla Firefox",  "firefox.exe" )
            if os.path.isfile(ff32): browser_exepath = ff32
        if not daemon_mode and browser_exepath == '': 
            raise Exception(
            'Failed to find Firefox in your Program Files location')     
    elif OS=='linux':
        if not daemon_mode: browser_exepath = 'firefox'
    elif OS=='macos':
        if not daemon_mode: browser_exepath = "open" #will open up the default browser
                     
    if daemon_mode:
        my_pubkey_b64modulus, auditee_pubkey_b64modulus = get_recent_keys()
        if ('genkey' in sys.argv) or (my_pubkey_b64modulus == ''):
            my_pubkey_b64modulus = new_keypair()
            print ('Pass this key to the auditee and restart:')
            print (my_pubkey_b64modulus)
            exit(0)
        else:
            print ('Reusing your key from the previous session:')
            print (my_pubkey_b64modulus)
        #check if hiskey=OIAAHhdshdu89dah... was supplied
        key = [b[len('hiskey='):] for idx,b in enumerate(sys.argv) if b.startswith('hiskey=')]
        if len(key) == 1:
            auditee_pubkey_b64modulus = key[0]
            if len(auditee_pubkey_b64modulus) != 172:
                raise Exception ('His key must be 172 characters long')
            import_auditee_pubkey(auditee_pubkey_b64modulus)
            print('Imported hiskey from command line:')
            print(auditee_pubkey_b64modulus)
        elif auditee_pubkey_b64modulus != '':
            print ('Reusing his key from previous session:')
            print (auditee_pubkey_b64modulus)
        else: 
            raise Exception ('You need to provide his key using hiskey=')
        start_peer_messaging()
    else:#not a daemon mode
        try: ff_proc = subprocess.Popen([browser_exepath, os.path.join(
            'http://127.0.0.1:' + str(FF_to_backend_port) + '/auditor.html')])
        except: 
            raise Exception('BROWSER_START_ERROR')
    
    try:
        while True:
            time.sleep(1)
            if daemon_mode:
                try: print (progress_queue.get_nowait())
                except: pass      
    except KeyboardInterrupt:
        b_terminate_all_threads = True
