const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

require('dotenv').config();

const { ACCESS_KEY, COOKIE_SECRET, PORT = 3007 } = process.env;
const sessionEpoch = crypto.randomBytes(32).toString('hex');

if (!ACCESS_KEY || !COOKIE_SECRET) {
  console.error('Fatal: ACCESS_KEY and COOKIE_SECRET environment variables are required.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(express.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' }
});

function getKeyHash(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

const currentKeyHash = getKeyHash(ACCESS_KEY);

function createSessionToken() {
  const payload = JSON.stringify({
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    keyHash: currentKeyHash,
    sessionEpoch
  });
  const data = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', COOKIE_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [data, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', COOKIE_SECRET).update(data).digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return false;
  }

  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.sessionEpoch !== sessionEpoch || !payload.exp || Date.now() > payload.exp) return false;

    const payloadHashBuf = Buffer.from(payload.keyHash || '');
    const expectedHashBuf = Buffer.from(currentKeyHash);
    if (payloadHashBuf.length !== expectedHashBuf.length || !crypto.timingSafeEqual(payloadHashBuf, expectedHashBuf)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// 1. GET / : public login page
app.get('/', (req, res) => {
  if (verifySession(req.cookies.rfm_session)) {
    return res.redirect('/app');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// 2. POST /api/login : verify key and issue signed cookie
app.post('/api/login', loginLimiter, (req, res) => {
  const submittedHash = crypto.createHash('sha256').update(String(req.body?.key || '')).digest();
  const realHash = crypto.createHash('sha256').update(ACCESS_KEY).digest();

  if (!crypto.timingSafeEqual(submittedHash, realHash)) {
    return res.status(401).json({ error: 'Invalid access key' });
  }

  const token = createSessionToken();
  res.cookie('rfm_session', token, {
    httpOnly: true,
    secure: req.secure,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({ ok: true });
});

// 3. GET /app : protected app
app.get('/app', (req, res) => {
  if (!verifySession(req.cookies.rfm_session)) {
    return res.redirect('/');
  }
  res.set({
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex'
  });
  res.sendFile(path.join(__dirname, 'protected', 'app.html'));
});

// 4. POST /api/logout : clear session cookie
app.post('/api/logout', (req, res) => {
  res.clearCookie('rfm_session', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  res.json({ ok: true });
});

// Logout convenience endpoint for browser navigation
app.get('/logout', (req, res) => {
  res.clearCookie('rfm_session', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  res.redirect('/');
});

// 5. GET /healthz : Render health check
app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});

// Static assets (login page dependencies, not protected)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
