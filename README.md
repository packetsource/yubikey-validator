## PAM module for Offline Yubikey Validation

Enable PAM client applications and systems to authenticate
offline via Yubikey OTP passwords. Yubikey OTP passwords are generated
using an AES secret held securely on the Yubikey. The secret
is shared with the authenticating party (and stored in /etc/shadow.yk
in this implementation), and an OTP is validated by
decrypting it and deconstructing it into:

- Public identity,
- Private identity,
- Counter,
- Session-specific counter

If all of these components match, the OTP is acceptable and authentication
is successful. If the counters suggest a replay attempt, the OTP is discarded and
authentication is not successful. See (https://developers.yubico.com/OTP/) for
more details.

### Installation steps

- Install any build dependencies:
  - PAM development library (`libpam0g-dev` on Ubuntu/Debian)
- Compile using ```cargo build --release```
- Install the shared library into an appropriate folder that the PAM clients can load:

```
sudo cp target/release/libpam_yubikey.so /usr/lib/$(cc -dumpmachine)/security/pam_yubikey.so
```
- Reference the PAM module in the context that you would like to use it. You can do this in several ways, 
and it may be advisible to consult the PAM man pages to do it, but if you only want to bind the authentication
to a single function, say TACACS+ which uses a service name of `tac_plus`, simply add the following
to a new line within ```/etc/pam.d/tac_plus```:

```
auth required pam_yubikey.so
```

- Generate an identity pair and AES secret on a Yubikey using the `yk-man` utility:

```
# Generate a serial-number based public identity, random
# private identity, and random secret, and program to slot 1
# (short press):
$ ykman otp yubiotp -S -g -G 1;
Using YubiKey serial as public ID: vvccccbcjkhj
Using a randomly generated private ID: b3670f6e29e4
Using a randomly generated secret key: 41539f79378b1ce36fd71057ce6c1d79
```
- Store this, colon-separated, in `/etc/shadow.yk` thus (no space indent):
```
- username:vvccccbcjkhj:b3670f6e29e4:41539f79378b1ce36fd71057ce6c1d79
```

## Testing
The `yubikey-validator` tool will prompt for an OTP and perform the validation
step from the command line, operating on a local `shadow.yk` file.

```
$ yubikey-validator
Please enter OTP: vvccccbcjkhjgirvuernvibvfettjuhbjnkkcvglfebi
Parsed OTP: YubikeyOtp { public_id: "vvccccbcjkhj", private_id: YubikeyPrivateIdentity([179, 103, 15, 110, 41, 228]), counter: 7, timestamp: [248, 86, 134], session_counter: 0, random: 47932, crc: 48388 }
```


## Security Considerations

- One of the benefits of the Yubikey OTP is that a generated token should
only be valid for one use. This is implemented on the authenticating element
(with the PAM module), by maintaining a counter (actually two) and storing them
within `/etc/shadow.yk`. If for some reason, your root filesystem is read-only,
it will not be possible to update this counter, and while the authentication
will succeed, it can be also be replayed which is not healthy. You can change
this behaviour with the `STRICT_ANTI_REPLAY` knob in `yubikey.rs`

- Regardless of above configuration, take care with generated tokens. They
are valid for login until the authenticating agent sees a later one.

- If your `/etc/shadow.yk` is compromised, you should regenerate all
identities and secrets therein, because an attacker can theoretically
use this information to generate tokens without the Yubikey.

- Because the reliance on the shadow file, avoid using the same
Yubikey and identity/key pair for more than a single authenticating system.

No warranties. 
