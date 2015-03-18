
#TLSNotary's own messaging protocol abstraction layer
#Protocol is documented in the documentation folder.

#Import the implementation module here and name it 'mi' = messaging implementation
import shared.irc_messaging as mi
from shared.tlsn_crypto import ee, dd
from shared.tlsn_common import config as config
import time

msg_chunk_size = None
initialized = False

#valid types of tlsnotary message to be passed on the private message channel
message_types_from_auditor = ('rrsapms_rhmac_rsapms', 'hmacms_hmacek_hmacverify', 'verify_hmac2','response', 'pms2',
'p_round_or0','p_round_or1', 'p_round_or2', 'p_round_or3', 'p_round_or4', 'p_round_or5', 'p_round_or6', 'p_round_or7', 'p_round_or8')
message_types_from_auditee =  ('cs_cr_sr_hmacms_verifymd5sha', 'rcr_rsr_rsname_n','verify_md5sha2', 'zipsig', 'link', 'commit_hash',
'p_link', 'p_round_ee0', 'p_round_ee1', 'p_round_ee2', 'p_round_ee3', 'p_round_ee4', 'p_round_ee5', 'p_round_ee6', 'p_round_ee7')


def tlsn_initialise_messaging(my_nick):
    '''Instantiate the connection for user my_nick and set up any parameters'''
    global msg_chunk_size
    msg_chunk_size = int(config.get('General','msg_chunk_size'))
    global initialized
    initialized = True
    mi.start_connection(my_nick)


#does not implement any of: seqnos, acks, recv/ack queues, chunking, encryption, encoding
def tlsn_send_raw(data):
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")
    return mi.send_raw(data)


def tlsn_send_single_msg(header,data,pk,ctrprty_nick=None):
    '''send a message without acks/seq nos, but including chunking,
    encoding and encryption; just for handshakes.
    message sent is data, then encrypted and encoded and chunked data.
    If ctrprty_nick is included, this nick is included in the header to direct the message.
    (Only one side of the handshake needs this).
    '''
    header = header if not ctrprty_nick else ':'+ctrprty_nick + ' ' + header
    chunks = len(data)/msg_chunk_size + 1
    if len(data)%msg_chunk_size == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of chunk_size

    for chunk_index in range(chunks) :
        chunk = data[msg_chunk_size*chunk_index:msg_chunk_size*(chunk_index+1)]
        encrypted_encoded_chunk = ee(str(chunk_index)+chunk,pk)
        ending = 'EOL' if chunk_index == chunks-1 else 'CRLF'
        tlsn_send_raw(header+' '+encrypted_encoded_chunk+' '+ending)
        time.sleep(0.5)

def tlsn_send_msg(data,pk,ack_q,recipient,seq_init=100000,raw=False):
    '''Send a message <data> on an already negotiated connection ;
    wait for an acknowledgement by polling for it on Queue ack_q
    Messages are sent with sequence numbers initialised at seq_init,
    or 0 if seq_init is undef.
    Messages larger than chunk_size are split into chunks with line endings.
    After chunking, messages are encrypted to public key pk then base64 encoded.
    CRLF and EOL are appended to the end of chunks according to tlsnotary's messaging protocol.
    Return 'success' only if message was sent and ack received correctly, otherwise 'failure'.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")

    if not hasattr(tlsn_send_msg, "my_seq"):
        if not seq_init: seq_init = 0
        tlsn_send_msg.my_seq = seq_init #static variable. Initialized only on first function's run

    #split up data longer than chunk_size bytes
    chunks = len(data)/msg_chunk_size + 1
    if len(data)%msg_chunk_size == 0: chunks -= 1 #avoid creating an empty chunk if data length is a multiple of chunk_size

    for chunk_index in range(chunks) :
        tlsn_send_msg.my_seq += 1
        chunk = data[msg_chunk_size*chunk_index:msg_chunk_size*(chunk_index+1)]
        #encrypt and base 64 encode the chunk; if we have used a sensible chunk size
        #this will neither cause a problem for RSA nor for IRC
        encrypted_encoded_chunk = ee(chunk,pk)

        ending = ' EOL ' if chunk_index+1==chunks else ' CRLF ' #EOL for the last chunk, otherwise CRLF
        msg_to_send = ' :' + recipient + ' seq:' + str(tlsn_send_msg.my_seq) + ' ' + encrypted_encoded_chunk + ending

        if not raw:
            for i in range (3):
                b_was_message_acked = False
                #empty the ack queue. Not using while True: because sometimes an endless loop would happen TODO: find out why
                for j in range(5):
                    try: ack_q.get_nowait()
                    except: pass
                tlsn_send_raw(msg_to_send)
                try:
                    ack_check = ack_q.get(block=True, timeout=3)
                except: continue #send again because ack was not received
                #print ('ack check is: ',ack_check)
                if not str(tlsn_send_msg.my_seq) == ack_check: continue
                #else: correct ack received
                #print ('message was acked')
                b_was_message_acked = True
                break

            if not b_was_message_acked:
                return 'failure'
        else:
            tlsn_send_raw(msg_to_send)

    return 'success'



def tlsn_receive_single_msg(header, pk, my_nick=None,ide=False):
    '''Non blocking receipt of a single message statelessly
    filtered on a message header, optionally prefixed by a username
    NB This is for handshake messages. All other messaging is handled
    by the tlsn_msg_receiver loop.
    'header' is not currently used but could be to filter.
    Messages received are filtered by header 'my_nick' if defined, otherwise
    all messages are received.
    Messages are decrypted using private key pk and base64 decoded
    Sequence number, plaintext message, ending and (if relevant) nick of sending party
    are returned.
    If ide (ignore decryption errors) is true, we return False on a decryption 
    error, treating the failure as receiving a handshake message from the wrong
    counterparty.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")

    retval = mi.receive_single_msg(my_nick)
    if not retval:
        return False
    if len(retval) != 2:
        raise Exception ("Invalid return from messaging implementation module")

    msg_array,ctrprty_nick = retval
    header = msg_array[1] if my_nick else msg_array[0]
    encrypted_encoded_msg = msg_array[2] if my_nick else msg_array[1]
    ending = msg_array[-1]
    try:
        msg = dd(encrypted_encoded_msg,pk)
        seq = msg[0]
        msg = ''.join(msg[1:])
    except:
        if ide:
            return False #means we got a message from the wrong counterparty
        raise Exception ("Failure in decryption or decoding of message: ", encrypted_encoded_msg)

    return ((header,int(seq),msg,ending),ctrprty_nick)


def tlsn_msg_receiver(my_nick,counterparty_nick,ack_queue,recv_queue,message_headers,pk,seq_init=100000):
    '''Intended to be run as a thread; puts msgs sent to my_nick from counterparty_nick
    onto the Queue recv_queue, and sends acknowledgements onto ack_queue, filtering out
    messages whose headers/topics are not in message_headers, and using sequence numbering
    starting from seq_init (or 0 if seq_init is undef).
    Messages are received in chunks and decrypted using private key pk and base64 decoded, then
    reassembled according to line endings CRLF and EOL, as per tlsnotary's
    messaging protocol.
    '''
    if not initialized:
        raise Exception("TLSN Messaging not yet instantiated")
    
    if not hasattr(tlsn_msg_receiver, 'last_seq_which_i_acked'):
        if not seq_init: seq_init=0
        tlsn_msg_receiver.last_seq_which_i_acked = seq_init #static variable. Initialized only on first function's run

    chunks = []
    while True:
        eemsg = mi.msg_receiver(my_nick,counterparty_nick)
        if not eemsg: continue #note that the timeout is in the implementation layer

        #acknowledgements are not our business here; put them on the queue
        if eemsg[0].startswith('ack'):
            #acks are not encrypted
            ack_queue.put(eemsg[0][len('ack:'):])
            continue

        if len(eemsg) !=3: continue
        if not eemsg[0].startswith('seq'): continue #wrong format; old server hellos will do this

        msg_decrypted = dd(eemsg[1],pk)
        #print ("decrypted message is: ",msg_decrypted)
        if len(chunks) == 0:
            msg = [msg_decrypted.split(':')[0]] + [':'.join(msg_decrypted.split(':')[1:])]+[eemsg[2]]
        else:
            msg = [None,msg_decrypted,eemsg[2]]

        his_seq = int(eemsg[0][len('seq:'):])
        if his_seq <=  tlsn_msg_receiver.last_seq_which_i_acked:
            #the other side is out of sync, send an ack again
            mi.send_raw(' :' + counterparty_nick + ' ack:' + str(his_seq))
            continue

        #we did not receive the next seq in order
        if not his_seq == tlsn_msg_receiver.last_seq_which_i_acked +1: continue

        #else we got a new seq
        if len(chunks)==0: #a new message is starting
            if not msg[0].startswith(message_headers) : continue
            hdr = msg[0]

        #'CRLF' is used at the end of the first chunk, 'EOL' is used to show that there are no more chunks
        chunks.append(msg[1])
        mi.send_raw(' :' + counterparty_nick + ' ack:' + str(his_seq))
        tlsn_msg_receiver.last_seq_which_i_acked = his_seq
        if msg[-1]=='EOL':
            assembled_message = ''.join(chunks)
            recv_queue.put(hdr+':'+assembled_message)
            chunks = []
