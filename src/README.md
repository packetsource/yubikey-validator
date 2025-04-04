## PAM module for Offline Yubikey Validation

Enable PAM client applications and systems to authenticate
via Yubikey OTP passwords. Yubikey OTP passwords are generated
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

Installation steps

- Compile using ```cargo build```
- Install 





