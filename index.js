const path = require('path')
const crypto = require('crypto')

const LocalStrategy = require('passport-local').Strategy
const express = require('express')
const flash = require('connect-flash')
const passport = require('passport')
const session = require('express-session')
const MessagingResponse = require('twilio').twiml.MessagingResponse;

const HOST = process.env.HOST || '127.0.0.1'
const PORT = process.env.PORT || 1337
const PHONE_NO = process.env.PHONE_NO || ''

const app = express()

const sha256sum = (str) => crypto.createHash('sha256').update(str).digest('base64')
const generateToken = () => Math.random().toString(36).slice(-4)
const generateVerificationToken = () => `v-${generateToken()}` 
const generatePasswordResetToken = () => `p-${generateToken()}`

const database = [
  {
    username: 'p1337',
    password: undefined,
    verified: false,
    resetToken: undefined,
    verificationToken: undefined,
  }
]

app.set('view engine', 'hbs')
app.set('views', path.join(__dirname, 'views'))

app.use(express.urlencoded({ extended: true }))
app.use(session({
  secret: 'i love demo code',
  resave: false,
  saveUninitialized: true,
}))
app.use(flash())

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser(({ username }, done) => done(null, username))

passport.deserializeUser((username, done) => {
  const user = database.find(user => user.username === username)
  const error = (user === undefined) ? new Error(`user "${username}" not found`) : null
  done(error, user)
})

passport.use('local-register', new LocalStrategy(
  {passReqToCallback: true},
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

passport.use('local-reset', new LocalStrategy(
  { passReqToCallback: true },
  (req, username, password, done) => {
    const { token } = req.body
    const user = database.find(user => user.username === username && user.resetToken === token)

    if (user === undefined) {
      return done(null, false, { meassage: 'User not found' })
    }

    user.password = password
    user.resetToken = undefined
    return done(null, user, { message: 'Password reset successful' })
  })
)

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

app.get('/', (req, res) => {
  res.render('login', { message: req.flash('error')[0] || req.flash('success')[0] })
})

app.post('/', passport.authenticate('local-login', {
  successRedirect: '/secure',
  failureRedirect: '/',
  failureFlash: true
}))

app.get('/register', (req, res) => {
  res.render('register', { message: req.flash('error')[0] })
})

app.post('/register', passport.authenticate('local-register', {
  successRedirect : '/verify',
  failureRedirect : '/register',
  failureFlash : true
}))

app.get('/verify', (req, res) => {
  const user = req.user
  const token = user?.verificationToken
  res.render('verify', { token, phoneNo: PHONE_NO })
})

app.get('/reset', (req, res) => {
  const { username, token } = req.query
  res.render('reset', { username, token })
})

app.post('/reset', passport.authenticate('local-reset', {
  successRedirect: '/',
  successFlash: true,
  failureRedirect: '/',
  failureFlash: true
}))

app.get('/secure', (req, res) => {
  const { username } = req.user
  res.render('secure', { username })
})

app.get('/logout', (req, res) => {
  req.session.destroy()
  req.logout()
  return res.redirect('/')
})

app.post('/sms', (req, res) => {
  const incomingText = req.body.Body
  const phoneNo = req.body.From
  const twiml = new MessagingResponse()

  if (incomingText.startsWith('v-')) {
    const user = database.find(user => user.phoneNo === sha256sum(phoneNo))

    if (!user) {
      twiml.message('Unknown user')
      return res.writeHead(200, {'Content-Type': 'text/xml'}).end(twiml.toString())
    } 

    user.verified = true
    user.verificationToken = undefined
    twiml.message("Congrats you're verified! 🎉")
    return res.writeHead(200, {'Content-Type': 'text/xml'}).end(twiml.toString())
  } 

  if (incomingText === 'reset password') {
    const user = database.find(user => user.phoneNo === sha256sum(phoneNo))

    if (!user) {
      twiml.message('Unknown user')
      return res.writeHead(200, {'Content-Type': 'text/xml'}).end(twiml.toString())
    } 

    user.resetToken = generatePasswordResetToken()
    const url = `http://${HOST}:${PORT}/reset?token=${user.resetToken}&username=${user.username}`

    twiml.message(`Reset password at ${url}`)
    return res.writeHead(200, {'Content-Type': 'text/xml'}).end(twiml.toString())
  }

  twiml.message(`Unknown request: ${incomingText}`)
  return res.writeHead(200, {'Content-Type': 'text/xml'}).end(twiml.toString())
})

app.listen(PORT, () => {
  console.log(`http://${HOST}:${PORT}`)
})
