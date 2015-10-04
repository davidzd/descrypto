import sys
import os.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from cryptoclient.network.client import main

if __name__ == "__main__":
    try:
        if len(sys.argv) > 2:
            sys.argv[3] = int(sys.argv[3])
            main(sys.argv[1], sys.argv[2], sys.argv[3])
        else:
            main(sys.argv[1])
    except IndexError:
        print("python client.py [STUDENT_ID] [HOST?] [PORT_NO?]")
