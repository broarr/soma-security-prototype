# SOMA Security Prototype

This repository contains a proof of concept two-factor authentication
scheme using hashed phone numbers instead of them. Inspiration comes
from "[Hashing Phone Numbers For 2-Factor Authentication][1]" by
Abhishek Chaudhary.

User names are preprovisioned in some process. The user registers their
preprovisioned account by adding a (hashed) phone number. Verification
is initiated by the user texting the server's phone number.

To reset the password the user must text the server and the server
responds with a text link containing a reset token.

**NOTE:** This code is insecure and should not be used in production.

[1]: https://theabbie.github.io/blog/2FA-phone-number-hashing
