import json

class ClientProtocol:
    def __init__(self, student_id):
        self.student_id = student_id
        self.counter = 1

    # Messages a client can send to a server
    def hello(self):
        msg = { "type": "CLIENT_HELLO", "id": self.student_id, "n": self.counter}
        return json.dumps(msg)

    def dhex_start(self):
        msg = {"type": "CLIENT_DHEX_START", "n": self.counter }
        return json.dumps(msg)

    def dhex(self, Yc):
        msg = { "type": "CLIENT_DHEX", "dh_Yc": Yc, "n": self.counter }
        return json.dumps(msg)

    def dhex_done(self, shared_key):
        msg = { "type": "CLIENT_DHEX_DONE", "n": self.counter, "dh_key": str(shared_key)}
        return json.dumps(msg)

    # ALL MESSAGES AFTER THIS LINE SHOULD BE ENCRYPTED
    def spec_done(self):
        msg = { "type": "CLIENT_SPEC_DONE", "n": self.counter}
        return json.dumps(msg)

    def text(self, line_number, body):
        msg = { "type": "CLIENT_TEXT", "id": line_number, "body": body, "n": self.counter}
        return json.dumps(msg, ensure_ascii=False).decode('latin1')

    def text_recv(self, line_number):
        msg = { "type": "CLIENT_TEXT_RECV", "id": line_number }
        return json.dumps(msg)

    def text_done(self):
        msg = { "type": "CLIENT_TEXT_DONE" }
        return json.dumps(msg)

    def comm_end(self):
        msg = { "type": "CLIENT_COMM_END" }
        return json.dumps(msg)

    # m_n = message number
    def require_message_length(self, m_n):
        msg = { "type": "CLIENT_NEXT_LENGTH_REQUEST", "req_n": m_n, "n": self.counter}
        return json.dumps(msg)

    def next_message_length(self, line_number, m):
        msg = { "type": "CLIENT_NEXT_LENGTH", "id": line_number, "length": len(m), "n": self.counter}
        return json.dumps(msg)

    def next_message_length_received(self, line_number):
        msg = { "type": "CLIENT_NEXT_LENGTH_RECV", "n": self.counter, "id": line_number}
        return json.dumps(msg)

    def parse(self, msg):
        try:
            return json.loads(msg)
        except UnicodeDecodeError:
            return json.loads(msg.encode('latin1'))
