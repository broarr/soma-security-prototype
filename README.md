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
Here is a short list of the bad things I did that you shouldn't.

* No CSRF tokens
* Passwords stored in the clear
* Respond to bad SMS messages
* No confirm password fields
* Password inputs are set to `text` instead of `password`
* Token generation uses a bad source of random
* Tokens are way too short

I'm sure there's other sins I committed.

## Prerequisites 

You'll need a Twilio account with a phone number and an app. Save the phone number,
account sid, and auth token. We'll be using those below.

## Running

First install dependencies via `npm install`.

Create a `.env` file containing the following fields:

```
ACCOUNT_SID=<YOUR ACCOUNT ID HERE>
AUTH_TOKEN=<YOUR AUTH TOKEN HERE>
PHONE_NO=<YOUR TWILIO PHONE NUMBER HERE>
HOST=localhost
PORT=1337
SMS_WEBHOOK=http://${HOST}:${PORT}/sms
```

Install the Twilio cli via `npm install -g twilio-cli`. Then start the Twilio tunnel
so it can access your localhost webhook.

```
$ twilio phone-numbers:update "<TWILIO PHONE NUMBER HERE>" --sms-url="http://localhost:1337/sms"
```

On first boot it'll ask you for your account sid and your authentication token. Enter
those at the prompt. On subsequent boots it will not ask for the sid or token.

Finally, start the express server via `npm start`.


[1]: https://theabbie.github.io/blog/2FA-phone-number-hashing
