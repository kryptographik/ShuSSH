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
from __future__ import print_function

VERSION = 0.1

# Copyright (c) 2015 Noah Tippett
#
# Any person obtaining a copy of this source code may use it or learn from it as
# they see fit. Distribution or use with the intent to profit or distribution of
# a modified copy of this source code is prohibited. All other rights reserved.
#
# THIS SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THIS SOURCE CODE OR THE USE OR OTHER DEALINGS IN
# THIS SOURCE CODE.

import sys
if sys.hexversion <  0x020700F0:
    print ("Please use python 2.7 or higher.")
    sys.exit()
elif sys.hexversion < 0x030000a1:
    pyV=2
    print ("Please use python 3.0 or higher.")
    sys.exit()
else:
    pyV=3

import datetime
import os
import pickle
import socket
import string
import threading
import time

from binascii import hexlify

if pyV is 2:
    from Queue import Queue
    import thread
elif pyV is 3:
    from queue import Queue
    import _thread as thread
else:
    print("Unsupported python version.")
    sys.exit()

imported = True
try:
    from docopt import docopt
except ImportError:
    print("This program requires docopt (http://docopt.org/)")
    print("")
    print("     Try 'pip install docopt'...")
    print("")
    imported = False

try:
    import paramiko
    if pyV is 3:
        from paramiko.py3compat import u
except ImportError:
    print("This program requires paramiko (http://www.paramiko.org/)")
    print("")
    print("     Try 'pip install paramiko'...")
    print("")
    imported = False

try:
    from passlib.hash import bcrypt_sha256 as bcrypt
    from passlib.exc import MissingBackendError
except ImportError:
    print("This program requires passlib (https://pythonhosted.org/passlib/)")
    print("")
    print("     Try 'pip install passlib'...")
    print("")
    imported = False
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
        imported = False

if imported is False:
    sys.exit(1)


# Defaults:
host_port = 22
key_bits = 2048
key_file = "shusshd-rsa.key"
state_file = "shussh.db"
savestate = False

# Global variables
userdb = dict()
channels = dict()
chatQ = Queue()
linebuffer = dict()

alias = dict()
# Command aliases
alias["?"] = "help"
alias["w"] = "who"
alias["pass"] = "passwd"
alias["q"] = "quit"
alias["exit"] = "quit"
command_aliases = alias

if os.path.isfile(state_file):
    userdb = pickle.load(open(state_file, "rb"))

class Commands ():

    _default_acl = ["help", "quit", "who", "passwd"]

    # Documentation is retrieved from the command's docstring,
    # commands without docstrings will not be listed
    def help(chan):
        """ Displays this documentation """
        user = userdb[chan.get_name()]
        chan.send("\r\n  ShuSSH Chat Help:\r\n\n")
        commands = ([ c for c in Commands.__dict__.keys() if not c.startswith("_")])
        commands = sorted(filter(lambda c: c in user['cacl'], commands))
        for command in commands:
            spaces = " " * (14 - len(command))
            helpdoc = getattr(Commands, command).__doc__
            if helpdoc is not None:
                chan.send("    /{:s}{:s}{:s}\r\n".format(command, spaces, helpdoc))
        chan.send("\n")
        return True
    
    def quit(chan):
        """ Exits the chat """
        chan.send("\rGoodbye\r\n")
        terminate(chan, "Quit")
        exit()
        return True

    def who(chan):
        """ Displays the list of logged in users """
        chan.send("\r\n  Users logged in:\r\n")
        for name in channels.keys():
            chan.send("    {:s}\r\n".format(name))
        chan.send("\n")
        return True

    def passwd(chan):
        """ Changes your password """
        cpasswd = str()
        tries = 0
        while checkpasswd(chan.get_name(), cpasswd) is False:
            if tries >= 3:
                chan.send("\r\nGood luck with that.\r\n")
                terminate(chan, "Forgot password")
            tries += 1
            chan.send("\r\nPlease enter your current password: ")
            f = chan.makefile('rU')
            cpasswd = f.readline().strip('\r\n')
        chan.send("\r\nPlease enter a new password: ")
        f = chan.makefile('rU')
        npasswd = f.readline().strip('\r\n')
        chan.send("\r\nPlease re-enter your new password: ")
        f = chan.makefile('rU')
        ncpasswd = f.readline().strip('\r\n')
        if npasswd != ncpasswd:
            chan.send("\r\nPasswords do not match.")
            chan.send("\r\nYour password has NOT been changed.\r\n")
        else:
            setpasswd(chan.get_name(), npasswd) 
            chan.send("\r\nYour password has been changed.\r\n")
            print("Password changed for {:s}.".format(chan.get_name()))
        return True

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
                    setpasswd(username, password)
                    return paramiko.AUTH_SUCCESSFUL
            elif checkpasswd(username, password) is True:
                print("-> {:s}".format(username))
                return paramiko.AUTH_SUCCESSFUL
        else:
            user = dict(handle=username,
                        secret=password,
                        firstlogin=int(time.time()),
                        lastlogin=None,
                        cacl=Commands._default_acl)
            userdb[username] = user
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def checkpasswd (username, password):
    user = userdb[username]
    return bcrypt.verify(password, user['secret'])

def setpasswd (username, password):
    updateuser(userdb[username], 'secret', bcrypt.encrypt(password, rounds=12))

def terminate (channel, reason):
        username = channel.get_name()
        putQ("{:s} has left. ({:s})".format(username, reason))
        channel.close()
        del channels[username]
        print("Connection closed: {:s}:{:d} ({:s})".format(addr[0], addr[1],username))

def updateuser(user, field, newvalue):
    username = user['handle']
    user[field] = newvalue
    userdb[username] = user
    if savestate is not False:
        pickle.dump(userdb, open(state_file, "wb"))

def putQ(message, name=None, time=time.time()):
    chatQ.put((time, name, message))

def run (command, chan):
    user = userdb[chan.get_name()]
    if command in command_aliases.keys():
        command = command_aliases[command]
    if command.startswith("_"):
        return False
    if command not in user['cacl']:
        return False
    try:
        rc = getattr(Commands, command)
        return rc(chan)
    except AttributeError:
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
        print("-> SSH negotiation failure: {:s}".format(str(e)))
        return False
    except EOFError as e:
        print("-> SSH negotiation failure: Host fingerprint mismatch?".format(str(e)))
        

    chan = t.accept(10)

    conn.event.wait(5)
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
    keyhash = hexlify(host_key.get_fingerprint())
    if pyV is 3:
        keyhash = u(keyhash)
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
        except KeyboardInterrupt:
            print("\n\nAborting...")
            putQ("My mind is going, I can feel it...")
            time.sleep(.5)
            os._exit(1)
        ip, port = str(addr[0]), int(addr[1])
        print("Connection from {:s}:{:d} ".format(ip, port), end="")
        thread.start_new_thread(connect, (remote,))
