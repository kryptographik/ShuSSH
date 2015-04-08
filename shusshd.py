'''
shusshd.py - The ShuSSH Server Daemon

Usage:
    shusshd.py [options]
    shusshd.py -h | --help
    shusshd.py -v | --version

Options:
    -p --port <port>    Start the server on <port>
    -l --log <logfile>  Enable logging to <logfile>
    -k --key <keyfile>  Use <keyfile> as the host's key
    -e --ephemeral      Do not persist data across server restarts
    -h --help           Display this documentation
    -v --version        Display the server version

'''

VERSION = 0.1

# Copyright (c) 2015 Noah Tippett
#
# Any person obtaining a copy of this source code may use it or learn from it as
# they see fit. Distribution or use with the intent to profit or distribution of
# a modified copy of this source code is prohbited. All other rights reserved.
#
# THIS SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THIS SOURCE CODE OR THE USE OR OTHER DEALINGS IN
# THIS SOURCE CODE.

import datetime
import os
import pickle
import socket
import string
import sys
import threading
import _thread as thread
import time

from queue import Queue
from binascii import hexlify

imported = False
try:
    from docopt import docopt
except ImportError:
    print("This program requires docopt (http://docopt.org/)")
    print("")
    print("     Try 'pip install docopt'...")
    print("")
    imported = True

try:
    import paramiko
except ImportError:
    print("This program requires paramiko (http://www.paramiko.org/)")
    print("")
    print("     Try 'pip install paramiko'...")
    print("")
    imported = True

try:
    from passlib.hash import bcrypt_sha256 as bcrypt
    from passlib.exc import MissingBackendError
except ImportError:
    print("This program requires passlib (https://pythonhosted.org/passlib/)")
    print("")
    print("     Try 'pip install passlib'...")
    print("")
    imported = True
finally:
    try:
        bcrypt.get_backend()
    except MissingBackendError:
        print("Your system does not have bcrypt installed. Try one of these implementations:")
        print("")
        print("     bcrypt      (http://bcrypt.sourceforge.net/)")
        print("     py-bcrypt   (http://www.mindrot.org/projects/py-bcrypt/")
        print("     bcryptor    (https://pypi.python.org/pypi/Bcryptor)")
        print("")
        imported = True

if imported is True:
    sys.exit(1)

from paramiko.py3compat import u

# Defaults:
host_port = 22
key_bits = 2048
key_file = "shusshd-rsa.key"
state_file = "shussh.db"
savestate = False

userdb = dict()
channels = dict()
chatQ = Queue()
linebuffer = dict()


if os.path.isfile(state_file):
    userdb = pickle.load(open(state_file, "rb"))

class Commands ():

    def help(chan):
        chan.send("\r\nShuSSH Chat Help:\r\n\n")
        chan.send("/help /?         Displays this documentation\r\n")
        chan.send("/exit            Exits the chat\r\n")
    
    def exit(chan):
        username = chan.get_name()
        addr = chan.getpeername()
        chan.send("\rGoodbye\r\n")
        putQ("{:s} has left.".format(username))
        chan.close()
        del channels[username]
        print("Connection closed: {:s}:{:d} ({:s})".format(addr[0], addr[1], username))
        exit()

class Connection (paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
           # print("Opened channel: {:d}".format(chanid))
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username in userdb:
            user = userdb[username]
            if user['lastlogin'] is None:
                if user['secret'] == password:
                    print("-> {:s} (New user)".format(username))
                    updateuser(user, 'lastlogin', user['firstlogin'])
                    updateuser(user, 'secret', bcrypt.encrypt(password, rounds=12))
                    return paramiko.AUTH_SUCCESSFUL
            elif bcrypt.verify(password, user['secret']) is True:
                print("-> {:s}".format(username))
                return paramiko.AUTH_SUCCESSFUL
        else:
            user = dict(handle=username, secret=password, firstlogin=int(time.time()), lastlogin=None)
            userdb[username] = user
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def updateuser(user, field, newvalue):
    username = user['handle']
    user[field] = newvalue
    userdb[username] = user
    if savestate is not False:
        pickle.dump(userdb, open(state_file, "wb"))

def putQ(message, name=None, time=time.time()):
    chatQ.put((time, name, message))


def run (command, chan):
    if command == "?":
        command = "help"
    if command == "quit":
        command = "exit"
    try:
        rc = getattr(Commands, command)
        rc(chan)
        return True
    except AttributeError:
        return False
    return False

def decode (char):
    try:
        chard = char.decode("utf-8")
    except UnicodeDecodeError:
        chard = char.decode("cp437")
    return chard

def timeish (timedelta):
    seconds = minutes = hours = days = weeks = months = years = decades = 0
    seconds = int(timedelta.total_seconds())
    time = "{:d} seconds".format(seconds)
    if seconds > 90:
        minutes = int(seconds / 60)
        time = "{:d} minutes".format(minutes)
    if minutes >= 60:
        hours = int(minutes / 60)
        time = "{:d} hours".format(hours)
    if hours >= 24:
        days = int(hours / 24)
        time = "{:d} days".format(days)
    if days >= 7:
        weeks = int(days / 7)
        time = "{:d} weeks".format(weeks)
    if weeks >= 4:
        months = int(weeks / 4)
        time = "{:d} months".format(months)
    if months >= 12:
        years = int(months / 12)
        time = "{:d} years".format(years)
    if years >= 10:
        decades = int(years / 10)
        time = "{:d} decades".format(decades)
                    
    return time

def getansi(chan):
    csiseq = False
    ecbuffer = list()
    chan.send("^")
    while True:
        char = chan.recv(1)
        ecbuffer.append(decode(char))
        if csiseq is True:
            chan.send(char)
        if char == b'[':
            csiseq = True
            chan.send(char)
        elif char == b'\r':
            return "?"
        elif ord(char) >= 64:
            if csiseq is False:
                chan.send("\b \b")
                if len(ecbuffer) is 2:
                    return "".join(ecbuffer)
                elif len(ecbuffer) > 2:
                    return "?"
            if csiseq is True and ord(char) <= 126:
                chan.send("\b" * (len(ecbuffer) + 1))
                chan.send(" " * (len(ecbuffer) + 1))
                chan.send("\b" * (len(ecbuffer) + 1))
                return "".join(ecbuffer)

def parse(chan, linebuff):
    while True:
        chan.send("\r> {:s}".format("".join(linebuff)))
        char = chan.recv(1)
        if char == b'\r':
            return "".join(linebuff)
        elif char == b'\x7f':
            if len(linebuff) > 0:
                chan.send("\b \b")
                linebuff.pop()
        elif char == b'\x1b':
            print("Escape!")
            code = getansi(chan)
            print(code)
        else:
            chard = decode(char)
            if chard in string.printable:
                chan.send(chard)
                linebuff.append(chard)

def chat(chan, Q, linebuffer):
    while True:
        line = parse(chan, linebuffer)
        del linebuffer[:]
        chan.send("\r  ")
        chan.send(" " * len(line))
        if line.startswith("/"):
            if run(line[1:], chan) is False:
                putQ(line, chan.get_name())
            else:
                print("{:s} ran command {:s}".format(chan.get_name(), line))
        else:
            if line != "":
                putQ(line, chan.get_name())

def chatstream(channels, Q):
    while True:
        o = Q.get()
        if o is None:
            return
        c = channels.copy()
        for name in c:
            chan = c[name]
            try:
                chan.send("\r")
                chan.send(" " * (len(linebuffer[chan.get_name()]) + 2))
                if o[1] is None:
                    fr = " *"
                else:
                    fr = "[{:s}]:".format(o[1])
                chan.send("\r{:s} {:s}\n\r".format(fr, o[2]))
                chan.send("\r> {:s}".format("".join(linebuffer[chan.get_name()])))
            except OSError:
                pass
            except Exception as e:
                print("Unhandled exception in chatstream: {:s}".format(e))


def sendbanner (channel):
    channel.send("ShuSSH Server v{:s}\r\n".format(str(VERSION)))

def connect (remote):

    t = paramiko.Transport(remote)
    t.add_server_key(host_key)
    conn = Connection()
    try:
        t.start_server(server=conn)
    except paramiko.SSHException as e:
        print("SSH negotiation failure: {:s}".format(str(e)))
        return False

    chan = t.accept(10)

    conn.event.wait(3)
    if not conn.event.is_set():
        print("Client is not interactive, closing remote connection")
        t.close()
        return False

    sendbanner(chan)

    user = userdb[t.get_username()]
    username = user['handle']
    now = int(time.time())
    if username in channels:
        chan.send("Hijacking session from {:s}...\r\n".format(channels[username].getpeername()[0]))
        channels[username].send("\rYour session was hijacked by {:s}.\r\n".format(chan.getpeername()[0]))
        channels[username].close()
        del channels[username]
    else:
        putQ("{:s} has joined.".format(username))
        if user['lastlogin'] == user['firstlogin']:
            chan.send("Welcome {:s}!\r\n".format(user['handle']))
            chan.send("Type /help for a list of commands.\r\n")
        else:
            lastdt = datetime.datetime.fromtimestamp(user['lastlogin'])
            nowdt = datetime.datetime.fromtimestamp(now)
            ltdelta = nowdt - lastdt
            chan.send("Your last login was {:s} ago.\r\n".format(timeish(ltdelta)))
    updateuser(user, 'lastlogin', now)
    chan.set_name(username)
    channels[username] = chan
    linebuffer[username] = list()
    chat(chan, chatQ, linebuffer[username])


if __name__ == '__main__':
    args = docopt(__doc__)

    if args['--help']:
        print(__doc__)          #   display help
        sys.exit(0)

    if args['--version']:
        print("ShuSSH Server Version {:s}".format(str(VERSION))) #Display version
        sys.exit(0)

    print("Starting ShuSSH Daemon...")

    if args['--ephemeral'] is False:
        savestate = True

    if args['--key']:
        key_file = args['--key']
        if os.path.isfile(key_file) is False:
            print("Key file does not exist: {:s}".format(key_file))
            sys.exit(1)
        print("Using {:s}".format(key_file))

    if os.path.isfile(key_file):
        host_key = paramiko.RSAKey(filename=key_file, password=socket.gethostname())
    else:
        print("Generating host key...")
        host_key = paramiko.RSAKey.generate(bits=key_bits)
        if savestate is not False:
            print("Saving generated key as {:s}".format(key_file))
            host_key.write_private_key_file(key_file, password=socket.gethostname())
    keyhash = u(hexlify(host_key.get_fingerprint()))
    print("Host fingerprint: {:s}".format((":".join([keyhash[i:2+i] for i in range(0, len(keyhash), 2)]))))

    if args['--log'] is not None:
        logfile = str(args['--log'])
        print("Logging is on: {:s}".format(logfile))
        paramiko.util.log_to_file(logfile) #Enable logging

    if args['--port'] is not None:
        host_port = int(args['--port'])

    print("Listening for connections on port {:d}...".format(host_port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', host_port))
    except Exception as e:
        print("Could not bind port: {:s}".format(str(e)))
        sys.exit(1)

    thread.start_new_thread(chatstream, (channels,chatQ))

    while True:
        try:
            sock.listen(100)
            remote, addr = sock.accept()
        except Exception as e:
            print("Could not complete connection: {:s}".format(str(e)))
        ip, port = str(addr[0]), int(addr[1])
        print("Connection from {:s}:{:d}".format(ip, port), end="")
        thread.start_new_thread(connect, (remote,))


