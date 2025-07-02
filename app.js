require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'session_secret',
  resave: false,
  saveUninitialized: true,
}));

app.use((req, res, next) => {
  res.locals.message = req.session.message || null;
  delete req.session.message;
  next();
});

function authenticateToken(req, res, next) {
  const token = req.session.token;
  if (!token) return res.redirect('/login');

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.redirect('/login');
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => res.redirect('/register'));

app.get('/register', (req, res) =>
  res.render('auth', { form: 'register', pageTitle: 'Register', heading: 'Register' })
);

app.get('/login', (req, res) =>
  res.render('auth', { form: 'login', pageTitle: 'Login', heading: 'Login' })
);

app.get('/dashboard', authenticateToken, (req, res) =>
  res.send('<h1>Welcome to your dashboard, ' + req.user.email + '!</h1><a href="/logout">Logout</a>')
);

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/forgot', (req, res) =>
  res.render('auth', { form: 'forgot', pageTitle: 'Forgot Password', heading: 'Forgot Password' })
);

app.get('/reset/:token', (req, res) =>
  res.render('auth', {
    form: 'reset',
    pageTitle: 'Reset Password',
    heading: 'Reset Password',
    token: req.params.token,
  })
);

app.get('/message', (req, res) =>
  res.render('auth', {
    form: 'message',
    pageTitle: 'Message',
    heading: 'Message',
    message: req.query.msg || '',
  })
);

function isValidEmail(email) {
  const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
  return re.test(email);
}

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.redirect('/message?msg=' + encodeURIComponent('Email and password are required'));

  if (!isValidEmail(email))
    return res.redirect('/message?msg=' + encodeURIComponent('Invalid email address'));

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hash]);
    res.redirect('/message?msg=' + encodeURIComponent('Registration successful. You can login.'));
  } catch (err) {
    console.error(err);
    res.redirect('/message?msg=' + encodeURIComponent('Registration failed. Email may exist.'));
  }
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.redirect('/message?msg=' + encodeURIComponent('Invalid credentials.'));

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.redirect('/message?msg=' + encodeURIComponent('Invalid credentials.'));

    const token = jwt.sign({ email: user.email, id: user.id }, JWT_SECRET, { expiresIn: '1h' });
    console.log('JWT Token:', token);
    req.session.token = token;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.redirect('/message?msg=' + encodeURIComponent('Login failed.'));
  }
});

app.post('/api/auth/forgot', async (req, res) => {
  const { email } = req.body;
  try {
    const token = crypto.randomBytes(32).toString('hex');
    const result = await pool.query(
      'UPDATE users SET reset_token = $1 WHERE email = $2 RETURNING *',
      [token, email]
    );

    if (result.rowCount === 0)
      return res.redirect('/message?msg=' + encodeURIComponent('Email not found.'));

    const link = `http://localhost:${PORT}/reset/${token}`;
    res.redirect('/message?msg=' + encodeURIComponent('Use this link to reset your password: ' + link));
  } catch (err) {
    console.error(err);
    res.redirect('/message?msg=' + encodeURIComponent('Reset failed.'));
  }
});

app.post('/api/auth/reset/:token', async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'UPDATE users SET password = $1, reset_token = null WHERE reset_token = $2 RETURNING *',
      [hash, token]
    );

    if (result.rowCount === 0)
      return res.redirect('/message?msg=' + encodeURIComponent('Invalid or expired reset token.'));

    res.redirect('/message?msg=' + encodeURIComponent('Password reset successful.'));
  } catch (err) {
    console.error(err);
    res.redirect('/message?msg=' + encodeURIComponent('Reset failed.'));
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
