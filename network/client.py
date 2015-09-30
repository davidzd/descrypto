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
    def __init__(self, socket, student_id):
        self.sock = socket
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
    def receive(self):
        msg = self.sock.recv(4096)
        result = self.clientProtocol.parse(msg)
        if NETWORK_DEBUG is True:
            print("RECEIVED: " + str(result))
        return result


    # ENCIPHERING COMPONENT
    def encrypt(self, msg, field=None):
        if field is None:
            msg = self.streamCipher.encrypt(msg)
        else:
            msg[field] = self.streamCipher.encrypt(msg[field])
        return msg

    def decrypt(self, msg, field=None):
        if field is None:
            msg = self.streamCipher.decrypt(msg)
        else:
            msg[field] = self.streamCipher.decrypt(msg[field])
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

        # Length Acknowledgement
        while True:
            msg = self.receive()
            if msg["type"] == "SERVER_NEXT_LENGTH_RECV" and msg["id"] == line_number:
                break
            else:
                self.send(len_msg)

        # Send TEXT Message
        if STDOUT_COMM is True:
            print "CLIENT_TEXT >>>>>>>>> ID: " + str(line_number)
            print "Plain Text: \n" + text
            print "Cipher Text: \n" + encrypted_text
        self.send(text_msg)
        # Wait Acknowledgement of SERVER_TEXT_RECV
        while True:
            msg = self.receive()
            if msg["type"] == "SERVER_TEXT_RECV" and msg["id"] == line_number:
                break
            else:
                self.send(msg)
        return True

    def send_all_lines(self):
        for item in self.picklines():
            self.send_line(item[0], item[1])
        return True

    def recv_line(self):
        # Get TEXT Message Length
        while True:
            msg = self.receive()
            if msg["type"] == "SERVER_NEXT_LENGTH":
                message_length = msg["length"]
                line_number = msg["id"]
                break
            elif msg["type"] == "SERVER_TEXT_DONE":
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

        decrypted_body = self.decrypt(msg["body"], None)
        if STDOUT_COMM is True:
            print "SERVER_TEXT <<<<<<<<<<<< ID: " + str(msg["id"])
            print "Cipher Text: \n" + msg["body"]
            print "Plain Text: \n" + decrypted_body

        # Inform Client TEXT Message Received
        self.send(self.clientProtocol.text_recv(msg["id"]))
        return False

    def recv_all_lines(self):
        haveWeReceivedAllLines = False
        while not haveWeReceivedAllLines:
            if self.recv_line():
                break
        return True

    def contact_phase(self):
        self.send(self.clientProtocol.hello())
        self.clientProtocol.counter += 1
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_HELLO":
                    return True
                if msg["type"] == "SERVER_BUSY":
                    return False
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()

    def exchange_phase(self):
        self.send(self.clientProtocol.dhex_start())
        self.clientProtocol.counter += 1
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_DHEX":
                    self.dh_generator = int(msg["dh_g"])
                    self.dh_prime = int(msg["dh_p"])
                    self.dh_Ys = int(msg["dh_Ys"])
                    if "dh_Xc" in msg.keys():
                        self.dh_Xc = int(msg["dh_Xc"])
                    else:
                        self.dh_Xc = cryptoclient.crypto.dhex.diffie_hellman_private(2048)
                    self.dh_Xc, self.dh_Yc = cryptoclient.crypto.dhex.diffie_hellman_pair(self.dh_generator, self.dh_prime, self.dh_Xc)
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()

        self.send(self.clientProtocol.dhex(self.dh_Yc))
        self.clientProtocol.counter += 1

        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_DHEX_DONE":
                    self.sharedKey = cryptoclient.crypto.dhex.diffie_hellman_shared(self.dh_Xc, self.dh_Ys, self.dh_prime)
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()

        self.send(self.clientProtocol.dhex_done(self.sharedKey))
        self.clientProtocol.counter += 1

        return True

    def specification_phase(self):
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_SPEC":
                    self.out_lines = msg["out_lines"]
                    p1 = int(msg["p1"])
                    p2 = int(msg["p2"])
                    self.streamKeys = (p1, p2)
                    return None
                if msg["type"] == "SERVER_BUSY":
                    return False
                if msg["type"] == "SERVER_DHEX_ERROR":
                    raise cryptoclient.util.error.InvalidDHComputation()
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()
            except cryptoclient.util.error.InvalidDHComputation as e:
                print(e.errorMessage())
                sys.exit()

    def communication_phase(self):
        # Instantiation of Ciphers
        self.streamCipher = cryptoclient.crypto.stream.StreamCipher(self.sharedKey, self.dh_prime, self.streamKeys[0], self.streamKeys[1])
        self.send(self.clientProtocol.spec_done())
        # RECEIVE ALL IN TEXT
        self.recv_all_lines()
        # Reset the Shift Register prior to sending out CLIENT_TEXT messages
        self.streamCipher.reset()
        # SEND ALL OUT TEXT
        self.send_all_lines()
        self.send(self.clientProtocol.text_done())

        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_COMM_END":
                    break
            except KeyError:
                print("Message does not contain `type` field key")
                sys.exit()

        self.send(self.clientProtocol.comm_end())

    def exit(self):
        while True:
            msg = self.receive()
            try:
                if msg["type"] == "SERVER_FINISH":
                    break
            except KeyError:
                print("KeyError: Message does not contain all required fields")
                sys.exit()
        print("Client Tasks completed successfully. Terminating cleanly...")
        self.sock.close()
        return True

def main(student_id, host=DEST_HOST, port=DEST_PORT):
    socket = s.socket()
    socket.connect((host, port))
    print("Connecting to HOST: {0} | Port: {1}".format(host, port))
    print(" ")
    print("Connected to Server...")
    print(" ")
    c = ClientServer(socket, student_id)
    print("==================== 1) Contact Phase Now ====================")
    c.contact_phase()
    print("==================== 1) Contact Phase END ====================")
    print("==================== 2) Exchange Phase Now ===================")
    c.exchange_phase()
    print("==================== 2) Exchange Phase END ===================")
    print("==================== 3) Specification Phase Now ==============")
    c.specification_phase()
    print("==================== 3) Specification Phase END ==============")
    print("==================== 4) Communication Phase Now ==============")
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
