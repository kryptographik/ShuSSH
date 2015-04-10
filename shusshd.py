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
import random
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
except ImportError:
    print("This program requires passlib (https://pythonhosted.org/passlib/)")
    print("")
    print("     Try 'pip install passlib'...")
    print("")
    imported = False

try:
    import psutil
except ImportError:
    print("This program requires psutil (https://pypi.python.org/pypi/psutil)")
    print("")
    print("     Try 'pip install psutil'...")
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
userdb = dict()         # A dictionary of user dicts, each filled with fields
channels = dict()       # A dictionary of channels username->channel object
chatQ = Queue()         # A queue of things to be chatted, use putQ() to add to it
linebuffer = dict()     # A dictionary of user's linebuffers username->working line
command_list = list()   # The list of chat commands

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
# These are chat commands that are available to clients

    # The commands in _default_acl are  granted to new users*
    _default_acl = ["help", "quit", "who", "passwd"]

    # *Except any user that is created from localhost gets all the commands:
    def god(chan):
        putQ("{:s} is a golden god!".format(chan.get_name()))
        updateuser(userdb[chan.get_name()], 'cacl', command_list)
        return True

    # Documentation is retrieved from the command's docstring,
    # commands without docstrings will not be listed in /help
    # If you pass help an argument it will attempt to get more
    # information from the command definition's _syntax_ attribute
    def help(chan, args=None):
        """ Displays this documentation """
        def helpline(chan, command):
            spaces = " " * (14 - len(command))
            helpdoc = getattr(Commands, command).__doc__
            if helpdoc is not None:
                return("/{:s}{:s}{:s}".format(command, spaces, helpdoc))
            else:
                return None

        def nohelp(chan, command):
            chan.send("\rNo help entry for {:s}\r\n".format(command))

        def formatter(syntax, usage):
            help = "\r?\r\n? {:s}\r\n".format(syntax)
            if usage is None:
                return help
            usage = usage.lstrip()
            linelen = 0
            line = list()
            for word in usage.split(" "):
                linelen += len(word)
                if linelen > 40:
                    linelen = 0
                    help += "?   {:s}\r\n".format(" ".join(line))
                    line = [word]
                else:
                    line.append(word)
            help += "?\r\n"
            return help

        user = userdb[chan.get_name()]
        if args is not None:
            command = args[0]
            if command.startswith("/"):
                command = command.lstrip("/")
            if command in command_aliases.keys():
                command = command_aliases[command]
            if command not in user['cacl']:
                nohelp(chan, command)
                return True
            halp = helpline(chan, command)
            try:
                syntax = getattr(Commands, command)._syntax_
            except Exception:
                if halp is None:
                    nohelp(chan, command)
                else:
                    chan.send("\r? {:s}\r\n".format(halp))
                return True
            try:
                usage = getattr(Commands, command)._usage_
            except:
                usage = None
            chan.send(formatter(syntax, usage))
            return True
        chan.send("\r\n  ShuSSH Chat Help:\r\n\n")
        commands = filter(lambda c: c in user['cacl'], command_list)
        for command in commands:
            halp = helpline(chan, command)
            if halp is not None:
                chan.send("\r    {:s}\r\n".format(halp))
        chan.send("\n")
        return True
    help._syntax_ = "/help [command]"
    help._usage_  = " The help command gives you information about the"
    help._usage_ += " commands you can run inside your chat session. When"
    help._usage_ += " run by itself /help returns a list of available commands"
    help._usage_ += " or you can specifiy a command for more detailed information."
    
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

    def _printpermissions(chan, username):
        user = userdb[username]
        chan.send("\r{:s}'s powers: {:s}\r\n".format(username, ", ".join(user['cacl'])))

    def grant(chan, args):
        """ Allows you to bestow special powers upon your bretheren """
        user = userdb[chan.get_name()]
        target = args[0]
        try:
            targetuser = userdb[target]
        except KeyError:
            targetuser = userdb[chan.get_name()]
        if target == chan.get_name():
            run('help', chan)
            return True
        if target in channels.keys():
            if len(args) is 1:
                Commands._printpermissions(chan, target)
                if "gold" not in user['cacl'] and "silver" not in user['cacl']:
                    channels[target].send("\r * {:s} looks at you funny and takes notes on a clipboard.\r\n".format(chan.get_name()))
                return True
            for permission in args[1:]:
                if permission not in user['cacl']:
                    chan.send("\rYou have no knowledge of alchemy!\r\n")
                    return True
                if permission in metals:
                    chan.send("\rYou can't give away prestigie!\r\n")
                if permission == "god":
                    if "gold" in user['cacl']:
                        updateuser(targetuser, 'cacl', union(["silver"], targetuser['cacl']))
                    elif "silver" in user['cacl']:
                        updateuser(targetuser, 'cacl', union(["bronze"], targetuser['cacl']))
                    else:
                        chan.send("\rGods are born, not made.\r\n")
                        return True
                    channels[target].send("\r * Wake up Neo ...\r\n")
            updateuser(targetuser, 'cacl', union(args[1:], targetuser['cacl']))
            Commands._printpermissions(chan, target)
            return True
        else:
            chan.send("\r{:s} isn't here!\r\n".format(target))
        return True

    def revoke(chan, args):
        """ Allows you to cruelly rescind powers from a hapless victim """
        user = userdb[chan.get_name()]
        target = args[0]
        try:
            targetuser = userdb[target]
        except KeyError:
            targetuser = userdb[chan.get_name()]
        haystack = channels.keys()
        if "gold" in user['cacl'] or "silver" in user['cacl']:
            haystack = userdb.keys()
        if target in haystack:
            if len(args) is 1:
                chan.send("\rRevoke what?\r\n")
                return True
            for permission in args[1:]:
                if permission not in user['cacl']:
                    chan.send("\rImpressive! But you are not a Jedi yet!\r\n")
                    return True
            if target == chan.get_name():
                if "gold" in user['cacl']:
                    chan.send("\rWhatever you say, boss.\r\n")
                else:
                    chan.send("\rSo be it, Jedi...\r\n")
            else:
                if "gold" not in user['cacl']:
                    channels[target].send("\r * {:s} looks at you disapprovingly.\r\n".format(chan.get_name()))
            updateuser(targetuser, 'cacl', negunion(args[1:], targetuser['cacl']))
            Commands._printpermissions(chan, target)
            return True
        else:
            chan.send("\rCouldn't find user: {:s}.\r\n".format(target))
        return True

    def users(chan):
        """ Displays the list of all existing users """
        chan.send("\r\n  Users:\r\n")
        for name in userdb.keys():
            chan.send("    {:s}\r\n".format(name))
        chan.send("\n")
        return True

    def kick(chan, args):
        """ Allows you to kick offensive users """
        if args[0] in channels.keys():
            channel = channels[args[0]]
            msg = "You're fired!"
            if len(args[1:]) > 0:
                msg = " ".join(args[1:])
            channel.send("\r *** {:s} ***\r\n".format(msg))
            terminate(channel, "Kicked by {:s}".format(chan.get_name()))
        else:
            chan.send("\r{:s} is not online.\r\n".format(args[0]))
        return True
    kick._syntax_ = "/kick <username> [message]"
    kick._usage_  = " Kick allows you to remove disruptive members from the"
    kick._usage_ += " chat. You can include an optional message that will"
    kick._usage_ += " be displayed to the user before the connection is"
    kick._usage_ += " closed."

    def server(chan, args=None):
        """ Displays information about the chat server """
        if args is None:
            chan.send("\rSorry, this doesn't do anything yet.\r\n")
        elif "god" not in userdb[chan.get_name()]['cacl']:
            raise TypeError("Ah ah ah, you didn't say the magic word...")
        elif args[0] == "reset":
            Commands._server_reset()
        elif args[0] == "shutdown":
            print("Server is shutting down at {:s}'s request.".format(chan.get_name()))
            putQ("{:s} has left the building.".format(socket.gethostname()))
            time.sleep(.5)
            os._exit(0)
        return True

    def _server_reset():
        # I stole this method from CherryPy
        putQ("The server is respawning. It will be back up momentarily.")
        time.sleep(.5)
        args = sys.argv[:]
        print("\nRestarting: {:s}".format(" ".join(args)))
        args.insert(0, sys.executable)
        if sys.platform == "win32":
            args = ["\"{:s}\"".format(arg) for arg in args]
        os.execv(sys.executable, args)
                

command_list = sorted([ c for c in Commands.__dict__.keys() if not c.startswith("_")])
metals = ["gold", "silver", "bronze", "copper", "tin"] # These are tokens for various acl configurations

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
            createuser(username, password)
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

def createuser(username, password):
    cacl = Commands._default_acl
    user = dict(handle=username,
            secret=password,
            firstlogin=int(time.time()),
            lastlogin=None,
            cacl=cacl)
    userdb[username] = user

def powerup(user, ip, port):
    # This complicated looking code checks to see if the localhost has an outbound net
    # connection with the ip and port of the connecting user. If it does it grants
    # the user all chat commands.
    if ip == "127.0.0.1":
        ipmatch = [filter((lambda c: ip in c[0]), [ s[3] for s in psutil.net_connections() ])]
        portmatch = [filter(lambda p: port in p[1], ipmatch)]
        if len(portmatch) is 1:
            updateuser(user, 'cacl', command_list + ["gold"])
            return True
    return False

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
    args = None
    tc = command.split(" ")
    if len(tc) > 1:
        command = tc[0]
        args = tc[1:]
    if command in command_aliases.keys():
        command = command_aliases[command]
    if command.startswith("_"):
        return False
    if command not in user['cacl']:
        return False
    try:
        rc = getattr(Commands, command)
    except AttributeError:
        return False
    try:
        return (rc(chan) if args is None else rc(chan, args))
    except TypeError as e:
        print(e)    # Debugging
        if args:
            if command == "god":
                return False
            chan.send("\r> /{:s} {:s} <- Syntax error\r\n".format(command, " ".join(args)))
            time.sleep(.4)
            chan.send("? Try typing just \"/{:s}\"\r\n".format(command))
        else:
            chan.send("\r> /{:s} <- Syntax error\r\n".format(command))
            time.sleep(.4)
            Commands.help(chan, command)
        return True

def decode (char):
    try:
        chard = char.decode("utf-8")
    except UnicodeDecodeError:
        chard = char.decode("cp437")
    return chard

def union(l1, l2):
    lu = l1 + l2
    k = {}
    for i in lu:
        k[i] = 1
    return list(k.keys())

def negunion(l1, l2):
    return list(filter(lambda x: x not in l1, l2))
        

def timeish (timedelta):
    seconds = minutes = hours = days = weeks = months = years = decades = 0
    seconds = int(timedelta.total_seconds())
    time = "{:d} seconds".format(seconds)
    if seconds > 120:
        minutes = int(seconds / 60)
        time = "{:d} minutes".format(minutes)
    if minutes >= 120:
        hours = int(minutes / 60)
        time = "{:d} hours".format(hours)
    if hours >= 48:
        days = int(hours / 24)
        time = "{:d} days".format(days)
    if days >= 14:
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

origin_quotes = ["All of our knowledge originates in our perceptions.",
                "Don't judge a book by its cover.",
                "Wake up, Neo...",
                "There is an eerie stillness in the air.",
                "You suddenly feel a powerful presence."]

def connect (remote,addr):

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
            if (powerup(user, addr[0], addr[1])) is True:
                putQ(random.choice(origin_quotes))
                print("Godmode enabled for {:s}.".format(username))
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
        thread.start_new_thread(connect, (remote,addr))
