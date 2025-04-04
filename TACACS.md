## Integration with `tac_plus` TACACS+ server

Various versions of `tac_plus` exist with several options of customising the
authentication function, including PAM integration. To protect your routers
using TACACS with Yubikey-based authentication, you can complete the following steps
(after installing the PAM module as described elsewhere):

- Download tac_plus from Shrubbery Networks. This code is refinement on the original
  Cisco reference implementation. https://shrubbery.net/pub/tac_plus/. At the time of writing,
  the latest version is F4.0.4.28.
- Ensure you have all necessary build dependencies installed:
    - bison
    - flex
    - tcp_wrappers (`libwrap0-dev` on Ubuntu/Debian)
    - PAM (but presumably already installed with PAM module above)
- Use the configuration tool `./confiugre` to localise the build process
- Compile and install with `make && sudo make install`
- Create an appropriate `/etc/tac_plus.conf` file. Read the man page
  for detailed documentation, but a bare minimal example here:

```
secret = foobar // an encryption key for securing client/server comms
user USER1 { login = PAM }
user USER2 { login = PAM }
user USER3 { login = PAM }
...
```

- Ensure that your server has an unrestricted TCP port 49 available
- Start the server `/usr/local/sbin/tac_plus -C /etc/tac_plus.conf`
- Test the TACACS+ server. A useful tool for doing this is the Python tacacs_plus
  package https://pypi.org/project/tacacs_plus/
    - You can also use the `-g` switch on `tac_plus` to run it single-threaded
      in the foreground with event reporting


- When confident, configure a Cisco IOS client:

```
# Create an authentication profile that uses TACACS for
# authentication (and disables per-command authorisation, 
# unless you want tac_plus to approve those). 
#
# Remove the local username when confident
#
aaa new-model
username LOCAL_USER password 0 BACKUP_PASSWORD
aaa group server tacacs+ TAC_YK
 server X.X.X.X key 0 foobar <-- match this with the secret above
aaa authentication login TACACAS group TAC_YK local
aaa authorization exec default none

# Configure network shell access via SSH, authenticated
# using the profile above
line vty 0 15
 transport input ssh
 login authentication TACACS
 privilege 15
```
It's best to make use of multiple windows to configure the IOS client
so that you can test as you are configuring.

Another helpful strategy is to start with a `reload in 1:00` (one hour) and not to commit configuration to startup until absolutely certain of
safe operation. Do remember to cancel the reload once it's working though!
