ShuSSH
======
ShuSHH is a simple chat server that runs over SSH.

## ShuSSH Server requirements:
 - Python 3

 - docopt (http://docopt.org/)

 - Paramiko (http://www.paramiko.org/)

 - Passlib (https://pythonhosted.org/passlib/)

  If your system does not already have a bcrypt backend (e.g. most non BSDs)
  you will also need to install one of these:
  - bcrypt (http://bcrypt.sourceforge.net/)
  - py-bcrypt (http://www.mindrot.org/projects/py-bcrypt/)
  - Bcryptor (https://pypi.python.org/pypi/Bcryptor)

## Running the ShuSSH server
Once all the dependencies are installed, simply run shusshd.py:

> #> python3 shusshd.py
> Starting ShuSSH Daemon...
> Generating host key...
> Saving generated key as shusshd-rsa.key
> `Host fingerprint: `**`35:d8:00:c0:73:fc:8f:32:db:05:b7:0c:7e:a2:b2:31`**
> Listening for connections on port 22...

If you want the server to always be running, I recommend trying [the djb
way] (http://cr.yp.to/daemontools.html).

If you are not running in ephemeral mode (-e) the server will generate an
RSA key file in the current directory. Keep this file safe! It is what
verifies the authenticity of your host.

If you don't want to run the server as root you can run it on a port over 1024:

    $> python3 shusshd.py -p 1024
    Starting ShuSSH Daemon...

## Connecting to the server
Once your server is running you can log into it with any ssh client:

    $> ssh localhost
    The authenticity of host 'localhost (127.0.0.1)' can't be established.
    RSA key fingerprint is 35:d8:00:c0:73:fc:8f:32:db:05:b7:0c:7e:a2:b2:31.
    Are you sure you want to continue connecting (yes/no)?

Verify that the fingerprint matches that of the host:

    Are you sure you want to continue connecting (yes/no)? yes
    Warning: Permanently added 'localhost' (RSA) to the list of known hosts.

Then enter the same password twice:

    foo@localhost's password: test
    Permission denied, please try again.
    foo@localhost's password: test
    ShuSSH Server v0.1
    Welcome foo!
    Type /help for a list of commands.
    > 

The username foo is now yours, next time you log in you will only have to
enter your password once.


