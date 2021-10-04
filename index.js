const path = require('path')
const crypto = require('crypto')

const LocalStrategy = require('passport-local').Strategy
const MessagingResponse = require('twilio').twiml.MessagingResponse
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn
const express = require('express')
const flash = require('connect-flash')
const passport = require('passport')
const session = require('express-session')

const HOST = process.env.HOST || '127.0.0.1'
const PORT = process.env.PORT || 1337
const PHONE_NO = process.env.PHONE_NO || ''

const app = express()

const sha256sum = (str) => crypto.createHash('sha256').update(str).digest('base64')
const generateToken = () => Math.random().toString(36).slice(-4)
const generateVerificationToken = () => `v-${generateToken()}`
const generatePasswordResetToken = () => `p-${generateToken()}`

/**
 * NOTE (BNR): This is our in-memory "database". It stores rows of pre-provisioned
 *             participant accounts. We manipulate the objects in the database by
 *             getting a reference to the object and mutating its fields.
 *
 *             The participant id is already filled out because that's how clinical
 *             studies work. The accounts are pre-provisioned by clinicians.
 *
 *             Password is the password of the user. I store it in the clear because
 *             this is a demo. NEVER SAVE PASSWORDS IN THE CLEAR. Use a cryptographic
 *             hash like argon2 or bcrypt.
 *
 *             Phone number is the hashed phone number of the user. I used a base64
 *             encoded sha256 hash of the phone number. If I were doing this for real
 *             I would allow users to have multiple phone numbers associated with them.
 *
 *             Verified is set to false until the user texts a verification token from
 *             their device. Unverified users cannot access the secure landing page.
 *
 *             Reset token is the currently active reset token. If the tokens don't match
 *             the password reset request is invalid. The reset token is stuck in a hidden
 *             input on the `/reset` page.
 *
 *             Verification token is the currently active verification token. This token
 *             must be texted from the registered phone number in order to verifiy the user.
 */
const database = [
  {
    username: 'p1337',
    password: undefined,
    phoneNo: undefined,
    verified: false,
    resetToken: undefined,
    verificationToken: undefined
  }
]

app.set('view engine', 'hbs')
app.set('views', path.join(__dirname, 'views'))

/**
 * NOTE (BNR): I am not using CSRF tokens because this is demo code. If you're accepting
 *             form input from a website you should use a CSRF token!
 */
app.use(express.urlencoded({ extended: true }))
app.use(session({
  secret: 'i love demo code',
  resave: false,
  saveUninitialized: true
}))
app.use(flash())

app.use(passport.initialize())
app.use(passport.session())

/**
 * NOTE (BNR): The `serializeUser` and `deserializeUser` functions are used to query
 *             our in-memory "database". Our "select" is calling `database.find()`.
 *             These methods are used by passport/express to automatically fetch the
 *             user object when a request comes in with a session cookie that holds the
 *             username.
 */
passport.serializeUser(({ username }, done) => done(null, username))

passport.deserializeUser((username, done) => {
  const user = database.find(user => user.username === username)
  const error = (user === undefined) ? new Error(`user "${username}" not found`) : null
  done(error, user)
})

/**
 * NOTE (BNR): This passport local strategy is used to register the pre-provisioned
 *             participant accounts. Registering means setting a password and saving a
 *             phone number hash.
 *
 *             The passwords are stored in the clear because I didn't want to complicate
 *             this demo more than I had to. You should always hash passwords with a
 *             strong hash like argon2 or bcrypt!
 */
passport.use('local-register', new LocalStrategy(
  { passReqToCallback: true },
  (req, username, password, done) => {
    const user = database.find(user => user.username === username)
    const phoneNo = req.body.phoneNo

    if (user === undefined) {
      return done(null, false, { message: `Unknown participant id ${username}` })
    }

    if (user?.password !== undefined) {
      return done(null, false, { message: 'That participant has already been registered' })
    }

    if (phoneNo === undefined) {
      return done(null, false, { message: 'Phone number required' })
    }

    user.username = username
    user.password = password
    user.phoneNo = sha256sum(phoneNo)
    user.verificationToken = generateVerificationToken()

    console.log(user)

    return done(null, user)
  })
)

/**
 * NOTE (BNR): This passport local strategy is used to reset the password of an already
 *             registered participant account. We set the `usernameField` to "token"
 *             because we look up the user by the token for password resets. When the
 *             password is reset we revoke the reset token so a participant can't use
 *             the same reset token twice.
 */
passport.use('local-reset', new LocalStrategy(
  {
    usernameField: 'token'
  },
  (token, password, done) => {
    const user = database.find(user => user.resetToken === token)

    if (user === undefined) {
      return done(null, false, { meassage: 'User not found' })
    }

    user.password = password
    user.resetToken = undefined
    return done(null, user, { message: 'Password reset successful' })
  })
)

/**
 * NOTE (BNR): This is the standard login passport strategy. It checks username and
 *             password. If the username and password are good, the user is authenticated.
 */
passport.use('local-login', new LocalStrategy((username, password, done) => {
  const user = database.find(user => user.username === username)

  if (user === undefined) {
    return done(null, false, { message: 'No user found' })
  }

  if (user.password === undefined) {
    return done(null, false, { message: 'Participant has not registered' })
  }

  if (user.password !== password) {
    return done(null, false, { message: 'Wrong password' })
  }

  if (user.verified === false) {
    return done(null, false, { message: 'Please verify account before logging in' })
  }

  return done(null, user)
}))

/**
 * NOTE (BNR): The root page of the app is a simple login form. On successful login
 *             the user is redirected to `/secure` a landing page that requires
 *             authentication.
 */
app.get('/', (req, res) => {
  res.render('login', { message: req.flash('error')[0] || req.flash('success')[0] })
})

app.post('/', passport.authenticate('local-login', {
  successRedirect: '/secure',
  failureRedirect: '/',
  failureFlash: true
}))

/**
 * NOTE (BNR): The register page of the app is also a simple form that asks for
 *             password, phone number and username. I didn't bother to confirm
 *             the password because this is a demo.
 */
app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error')[0] })
})

app.post('/register', passport.authenticate('local-register', {
  successRedirect: '/verify',
  failureRedirect: '/register',
  failureFlash: true
}))

/**
 * NOTE (BNR): The verify screen tells the user how to verify the account with their
 *             cell phone. It provides a link to the home page as well.
 */
app.get('/verify', (req, res) => {
  const user = req.user
  const token = user?.verificationToken
  res.render('verify', { token, phoneNo: PHONE_NO })
})

/**
 * NOTE (BNR): The reset endpoint allows a user to reset their password. It requires
 *             a valid reset token. The form saves the token in a hidden input and
 *             only asks the user for their new password.
 */
app.get('/reset', (req, res) => {
  const { token } = req.query
  res.render('reset', { token })
})

app.post('/reset', passport.authenticate('local-reset', {
  successRedirect: '/',
  successFlash: true,
  failureRedirect: '/',
  failureFlash: true
}))

/**
 * NOTE (BNR): This is our secure landing page. It will automatically redirect to `/`
 *             when the user is not authenticated.
 */
app.get('/secure', ensureLoggedIn('/'), (req, res) => {
  const { username } = req.user
  res.render('secure', { username })
})

/**
 * NOTE (BNR): The logout link destroys the session and redirects to `/`.
 */
app.get('/logout', (req, res) => {
  req.session.destroy()
  req.logout()
  return res.redirect('/')
})

/**
 * NOTE (BNR): This endpoint is a webhook registered with Twilio via the Twilio cli.
 *             It can handle two different types of messages, verification tokens and
 *             reset password requests.
 *
 *             Verification token SMS messages recieve a token in the form `v-xxxx`,
 *             looks up the user based on the phone number hash. Then it verifies the
 *             user and clears the verification token so it cannot be used again.
 *
 *             The reset password SMS message generates a reset password token and
 *             associates it with the user. Then it sends a response containing a link
 *             to the reset password page with the token as a parameter.
 *
 *             All other messages respond with an "Unknown request" response.
 */
app.post('/sms', (req, res) => {
  const incomingText = req.body.Body
  const phoneNo = req.body.From
  const twiml = new MessagingResponse()

  if (incomingText.startsWith('v-')) {
    const user = database.find(user => user.phoneNo === sha256sum(phoneNo))

    if (!user) {
      twiml.message('Unknown user')
      return res.writeHead(200, { 'Content-Type': 'text/xml' }).end(twiml.toString())
    }

    user.verified = true
    user.verificationToken = undefined
    twiml.message("Congrats you're verified! 🎉")
    return res.writeHead(200, { 'Content-Type': 'text/xml' }).end(twiml.toString())
  }

  if (incomingText === 'reset password') {
    const user = database.find(user => user.phoneNo === sha256sum(phoneNo))

    if (!user) {
      twiml.message('Unknown user')
      return res.writeHead(200, { 'Content-Type': 'text/xml' }).end(twiml.toString())
    }

    user.resetToken = generatePasswordResetToken()
    const url = `http://${HOST}:${PORT}/reset?token=${user.resetToken}`

    twiml.message(`Reset password at ${url}`)
    return res.writeHead(200, { 'Content-Type': 'text/xml' }).end(twiml.toString())
  }

  twiml.message(`Unknown request: ${incomingText}`)
  return res.writeHead(200, { 'Content-Type': 'text/xml' }).end(twiml.toString())
})

app.listen(PORT, () => {
  console.log(`http://${HOST}:${PORT}`)
})
