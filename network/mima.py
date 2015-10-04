# COMP90043 Cryptography and Security Client Implementation
# University of Melbourne
# For use in Project
#
# Commissioned by Prof. Assoc. Udaya P.
# Authored by Renlord Y.
#
# INSTRUCTIONS TO CANDIDATES:
# Do not alter any code in here. If you break it, it will not communicate properly with the server.
#
# 23 Jul 2015

import socket as s
import sys

from cryptoclient.network.protocol import *
import cryptoclient.crypto.dhex
import cryptoclient.crypto.stream
import cryptoclient.crypto.des
import cryptoclient.util.error

CLIENT_CORPUS_PATH = "cryptoclient/corpus.txt"

DEST_HOST = ''
DEST_PORT = 8001

NETWORK_DEBUG = True
PROTOCOL_DEBUG = False

STDOUT_COMM = True

class ClientServer:
    def __init__(self,listensocket, socket, student_id):
        self.sock = socket
        self.lsock = listensocket
        self.clientProtocol = ClientProtocol(student_id)
        self.sharedKey = None
        self.streamCipher = None
        self.streamKeys = None

    # A Better send function for sockets with error handling
    def send(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("Socket Connection Broken")
            totalsent = totalsent + sent

        if NETWORK_DEBUG is True:
            print("SENT: {0}".format(self.clientProtocol.parse(msg)))

    def send_to_client(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.lsock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("Socket Connection Broken")
            totalsent = totalsent + sent

        if NETWORK_DEBUG is True:
            print("SENT: {0}".format(self.clientProtocol.parse(msg)))

    # A Better Socket Receiver with Error Handling
    def strict_receive(self, reqlen, key=None):
        bytestr = b''
        bytes_recd = 0
        while bytes_recd < reqlen:
            chunk = self.sock.recv(min(reqlen - bytes_recd, 4096))
            if chunk == b'':
                raise RuntimeError("Socket connection broken")
            bytestr += chunk
            bytes_recd = bytes_recd + len(chunk)
        result = self.clientProtocol.parse(bytestr)
        if NETWORK_DEBUG is True:
            print "RECEIVED: " + str(result)
        return result

    # A Better Socket Receiver with Error Handling
    def strict_receive_client(self, reqlen, key=None):
        bytestr = b''
        bytes_recd = 0
        while bytes_recd < reqlen:
            chunk = self.lsock.recv(min(reqlen - bytes_recd, 4096))
            if chunk == b'':
                raise RuntimeError("Socket connection broken")
            bytestr += chunk
            bytes_recd = bytes_recd + len(chunk)
        result = self.clientProtocol.parse(bytestr)
        if NETWORK_DEBUG is True:
            print "RECEIVED: " + str(result)
        return result

    def receive(self):
        msg = self.sock.recv(4096)
        result = self.clientProtocol.parse(msg)
        if NETWORK_DEBUG is True:
            print("RECEIVED: " + str(result))
        return result

    def receive_from_client(self):
        msg = self.lsock.recv(4096)
        result =self.clientProtocol.parse(msg)
        if NETWORK_DEBUG is True:
            print("RECEIVED: " + str(result))
        return result

    # A Better Socket Receiver for receiving from the client.
    def receivesl(arg):
        pass


    # ENCIPHERING COMPONENT
    def encrypt(self, msg, field=None):
        if field is None:
            msg = self.streamCipher.encrypt(msg)
        else:
            msg[field] = self.streamCipher.encrypt(msg[field])
        return msg

    def encrypt_client(self, msg, field=None):
        if field is None:
            msg = self.streamCipher_client.encrypt(msg)
        else:
            msg[field] = self.streamCipher_client.encrypt(msg[field])
        return msg

    def decrypt(self, msg, field=None):
        if field is None:
            msg = self.streamCipher.decrypt(msg)
        else:
            msg[field] = self.streamCipher.decrypt(msg[field])
        return msg

    def decrypt_client(self, msg, field=None):
        if field is None:
            msg = self.streamCipher_client.decrypt(msg)
        else:
            msg[field] = self.streamCipher_client.decrypt(msg[field])
        return msg

    def picklines(self):
        fp = open(CLIENT_CORPUS_PATH)
        results = [(i, x) for i, x in enumerate(fp) if i in self.out_lines]
        fp.close()
        return results

    def send_line(self, line_number, text):
        # Send TEXT Message Length
        encrypted_text = self.encrypt(text)
        text_msg = self.clientProtocol.text(line_number, encrypted_text)
        len_msg = self.clientProtocol.next_message_length(line_number, text_msg)
        self.send(len_msg)
        clientmsg = self.receive_from_client()
        message_length = clientmsg["length"]
        # Length Acknowledgement
        while True:
            msg = self.receive()
            if msg["type"] == "SERVER_NEXT_LENGTH_RECV" and msg["id"] == line_number:
                break
            else:
                self.send(len_msg)
        self.send_to_client(self.clientProtocol.server_next_length_recv(line_number))

        # Send TEXT Message
        if STDOUT_COMM is True:
            print "CLIENT_TEXT >>>>>>>>> ID: " + str(line_number)
            print "Plain Text: \n" + text
            print "Cipher Text: \n" + encrypted_text
        self.send(text_msg)
        clientmsg = self.strict_receive_client(message_length)
        # Wait Acknowledgement of SERVER_TEXT_RECV
        while True:
            msg = self.receive()
            if msg["type"] == "SERVER_TEXT_RECV" and msg["id"] == line_number:
                self.send_to_client(self.clientProtocol.server_text_recv(line_number))
                break
            else:
                self.send(msg)
        return True

    def send_all_lines(self):
        for item in self.picklines():
            self.send_line(item[0], item[1])
        return True

    def send_all_lines_client(self):
        for item in self.picklines():
            self.send_line_client(item[0], item[1])
        return True

    def recv_line(self):
        info = "HAHA YOUR HAVE BEEN ATTACKED"
        # Get TEXT Message Length
        while True:
            # Receive the next length
            msg = self.receive()
            if msg["type"] == "SERVER_NEXT_LENGTH":
                message_length = msg["length"]
                line_number = msg["id"]
                # send to the correspooding server next length to the client
                break
            elif msg["type"] == "SERVER_TEXT_DONE":
                self.send_to_client(self.clientProtocol.server_text_done())
                return True
            else:
                self.send(self.clientProtocol.require_message_length())


        # Send Acknowledgement of Message Length
        self.send(self.clientProtocol.next_message_length_received(line_number))
        # Get complete TEXT Message.
        while True:
            msg = self.strict_receive(message_length)
            if msg["type"] == "SERVER_TEXT":
                break
            else:
                self.send(self.clientProtocol.next_message_length_received(line_number))
        # if the type is received, then come with the next steps.
        decrypted_body = self.decrypt(msg["body"], None)+info
        client_encrypt_body = self.encrypt_client(decrypted_body,None)
        if STDOUT_COMM is True:
            print "SERVER_TEXT <<<<<<<<<<<< ID: " + str(msg["id"])
            print "Cipher Text: \n" + msg["body"]
            print "Plain Text: \n" + decrypted_body
        # Inform Client TEXT Message Received
        self.send_to_client(self.clientProtocol.server_next_length(line_number, len(self.clientProtocol.server_text(line_number, client_encrypt_body))))
        clientmsg = self.receive_from_client()
        self.send_to_client(self.clientProtocol.server_text(line_number, client_encrypt_body))
        self.send(self.clientProtocol.text_recv(msg["id"]))
        # receive received message from client.
        clientmsg = self.receive_from_client()
        return False



    def recv_all_lines(self):
        haveWeReceivedAllLines = False
        while not haveWeReceivedAllLines:
            if self.recv_line():
                break
        return True
    # Say hello to the server and receive hello from the client.
    def contact_phase(self):
        # recieive from the client
        msg = self.receive_from_client()
        #send the hello to the server, pretend the student id
        self.send(self.clientProtocol.hello(msg["id"]))
        self.clientProtocol.counter += 1
        msg = self.receive()
        if msg["type"] == "SERVER_HELLO":
            self.send_to_client(self.clientProtocol.server_hello())
        if msg["type"] == "SERVER_BUSY":
            self.send_to_client(self.clientProtocol.server_busy())

    # exchange the diffie_hellman key with the server
    def exchange_phase_server(self):
        # send the dhex with the server
        self.send(self.clientProtocol.dhex_start())
        self.clientProtocol.counter += 1
        # receive from the sever
        msg = self.receive()
        if msg["type"] == "SERVER_DHEX":
            # store corresponding g, p, public key
            self.dh_generator = int(msg["dh_g"])
            self.dh_prime = int(msg["dh_p"])
            self.dh_Ys = int(msg["dh_Ys"])
            # judge if there is Xc
            if "dh_Xc" in msg.keys():
                self.dh_Xc = int(msg["dh_Xc"])
            else:
                # generate priavte key with server
                self.dh_Xc = cryptoclient.crypto.dhex.diffie_hellman_private(2048)
            # generate public key with server return private and public key
            self.dh_Xc, self.dh_Yc = cryptoclient.crypto.dhex.diffie_hellman_pair(self.dh_generator, self.dh_prime, self.dh_Xc)
        # send public key to server
        self.send(self.clientProtocol.dhex(self.dh_Yc))
        self.clientProtocol.counter += 1
        msg = self.receive()
        if msg["type"] == "SERVER_DHEX_DONE":
            # generate shared key with server
            self.sharedKey = cryptoclient.crypto.dhex.diffie_hellman_shared(self.dh_Xc, self.dh_Ys, self.dh_prime)
        self.send(self.clientProtocol.dhex_done(self.sharedKey))
        self.clientProtocol.counter += 1
        return True
    # exchange the diffie_hellman key with the client
    def exchange_phase_client(self):
        msg = self.receive_from_client()
        # generate new private key with client
        if msg["type"] == "CLIENT_DHEX_START":
            self.dh_Xm = cryptoclient.crypto.dhex.diffie_hellman_private(2048)
            self.dh_Xm, self.dh_Ym = cryptoclient.crypto.dhex.diffie_hellman_pair(self.dh_generator, self.dh_prime, self.dh_Xm)
        # Send to the Client the generator , the prime and public key.
        self.send_to_client(self.clientProtocol.dhex_server(self.dh_generator, self.dh_prime, self.dh_Ym))
        self.clientProtocol.counter += 1
        # Xm  private key of man in the middle with the client. dh_Yc will be the public key from client.
        msg = self.receive_from_client()
        # Receive the public key from the Client.
        if msg["type"] == "CLIENT_DHEX":
            # Store the public key of client.
            self.dh_Yc = int(msg["dh_Yc"])
            self.sharedKey_client = cryptoclient.crypto.dhex.diffie_hellman_shared(self.dh_Xm, self.dh_Yc, self.dh_prime)
        # send to notif client, the dhex has beeen completed by the server
        self.send_to_client(self.clientProtocol.server_dhex_done())
        self.clientProtocol.counter += 1

    def specification_phase_client(self):
        msg = self.receive_from_client()
        if msg["type"] == "CLIENT_DHEX_DONE":
            print self.sharedKey_client
            print msg["dh_key"]
            if msg["dh_key"] == str(self.sharedKey_client):
                self.send_to_client(self.clientProtocol.server_spec(self.out_lines, self.p1, self.p2))
            else:
                self.send_to_client(self.clientProtocol.server_dhex_error())

    def specification_phase(self):
        msg = self.receive()
        if msg["type"] == "SERVER_SPEC":
            self.out_lines = msg["out_lines"]
            self.p1 = int(msg["p1"])
            self.p2 = int(msg["p2"])
            self.streamKeys = (self.p1, self.p2)
        if msg["type"] == "SERVER_DHEX_ERROR":
            raise cryptoclient.util.error.InvalidDHComputation()



    def communication_phase(self):
        # Instantiation of Ciphers
        self.streamCipher = cryptoclient.crypto.stream.StreamCipher(self.sharedKey, self.dh_prime, self.streamKeys[0], self.streamKeys[1])
        self.streamCipher_client = cryptoclient.crypto.stream.StreamCipher(self.sharedKey_client, self.dh_prime, self.p1, self.p2)
        msg = self.receive_from_client()
        if msg["type"] == "CLIENT_SPEC_DONE":
            self.send(self.clientProtocol.spec_done())
            # RECEIVE ALL IN TEXT
            self.recv_all_lines()
            # Reset the Shift Register prior to sending out CLIENT_TEXT messages
            self.streamCipher.reset()
            # Send all text after cipher to client
            self.streamCipher_client.reset()
            # SEND ALL OUT TEXT
            self.send_all_lines()
            self.send(self.clientProtocol.text_done())
            clientmsg =  self.receive_from_client()

        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_COMM_END":
                    self.send_to_client(self.clientProtocol.server_comm_end())
                    break
            except KeyError:
                print("Message does not contain `type` field key")
                sys.exit()

        self.send(self.clientProtocol.comm_end())
        self.receive_from_client()

    def exit(self):
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_FINISH":
                    self.send_to_client(self.clientProtocol.server_finish())
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()
        print("Client Tasks completed successfully. Terminating cleanly...")
        self.sock.close()
        return True

def main(student_id, host=DEST_HOST, port=DEST_PORT):
    server_socket = s.socket()
    listensocket = s.socket()
    server_socket.connect((host, port))
    # socket for listening to msg from client.
    listensocket.bind(('127.0.0.1',8003))
    listensocket.listen(1)
    lsocket, addr = listensocket.accept()


    print("Connecting to HOST: {0} | Port: {1}".format(host, port))
    print(" ")
    print("Connected to Server...")
    print(" ")
    # create the instance of Client server
    c = ClientServer(lsocket, server_socket, student_id)
    print("==================== 1) Contact Phase Now ====================")
    # exchange hello info firstly between the middle man and the client
    c.contact_phase()
    print("==================== 1) Contact Phase END ====================")
    print("==================== 2) Exchange Phase Now ===================")
    # echange shared key with server
    c.exchange_phase_server()
    # echange shared key with client
    c.exchange_phase_client()
    print("==================== 2) Exchange Phase END ===================")
    print("==================== 3) Specification Phase Now ==============")
    # specify the shared key
    c.specification_phase()
    c.specification_phase_client()
    print("==================== 3) Specification Phase END ==============")
    print("==================== 4) Communication Phase Now ==============")
    '''
    communication starts exchanging including:
    1.
    2.
    3.

    '''
    c.communication_phase()
    print("==================== 4) Communication Phase END ==============")
    c.exit()

if __name__ == "__main__":
    try:
        if len(sys.argv) > 2:
            main(sys.argv[1], sys.argv[2], sys.argv[3])
        else:
            main(sys.argv[1])
    except IndexError:
        print("python client.py [STUDENT_ID] [HOST?] [PORT_NO?]")
