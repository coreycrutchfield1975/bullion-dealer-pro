'use strict';
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const APP_URL = [process.env.APP](https://process.env.APP)_URL || `http://localhost:${PORT}`;

let stripe = null;
if (process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.startsWith('sk_')) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

const users = new Map();
const sessions = new Map();

async function seedAdmin() {
  const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  const adminPassword = (process.env.ADMIN_PASSWORD || '').trim();
  if (!adminEmail || !adminPassword) {
    console.log('Admin env vars not set, skipping seed');
    return;
  }
  if (!users.has(adminEmail)) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    users.set(adminEmail, {
      email: adminEmail,
      passwordHash,
      plan: 'admin',
      createdAt: new Date().toISOString(),
    });
    console.log('Admin seeded: ' + adminEmail);
  }
}
seedAdmin();

app.use(cors({ origin: APP_URL, credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.static(path.join(__dirname, 'public')));

function signToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const token = req.cookies.bdp_token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const { email } = jwt.verify(token, JWT_SECRET);
    const user = users.get(email);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.plan !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

function hasPaidAccess(user) {
  return user.plan === 'admin' || user.plan === 'monthly' || user.plan === 'annual';
}

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (users.has(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  const passwordHash = await bcrypt.hash(password, 10);
  users.set(email.toLowerCase(), {
    email: email.toLowerCase(),
    passwordHash,
    plan: 'trial',
    createdAt: new Date().toISOString(),
    trialEnd: new Date(Date.now() + 14 * 86400000).toISOString(),
  });
  const token = signToken(email.toLowerCase());
  res.cookie('bdp_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 86400000 });
  res.json({ ok: true, plan: 'trial' });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = users.get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const ok = await [bcrypt.com](https://bcrypt.com)pare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  const token = signToken(user.email);
  res.cookie('bdp_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 86400000 });
  res.json({ ok: true, plan: user.plan });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('bdp_token');
  res.json({ ok: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { passwordHash, ...safe } = req.user;
  res.json(safe);
});

app.post('/api/stripe/checkout', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
  const { plan } = req.body || {};
  const priceId = plan === 'annual' ? process.env.STRIPE_PRICE_ANNUAL : process.env.STRIPE_PRICE_MONTHLY;
  if (!priceId) return res.status(400).json({ error: 'Invalid plan' });
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    customer_email: req.user.email,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: APP_URL + '/app?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: APP_URL + '/pricing',
    metadata: { email: req.user.email },
  });
  res.json({ url: session.url });
});

app.post('/api/stripe/portal', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
  const user = req.user;
  if (!user.stripeCustomerId) return res.status(400).json({ error: 'No subscription found' });
  const session = await stripe.billingPortal.sessions.create({
    customer: user.stripeCustomerId,
    return_url: APP_URL + '/app',
  });
  res.json({ url: session.url });
});

app.post('/api/stripe/webhook', (req, res) => {
  if (!stripe) return res.sendStatus(200);
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send('Webhook Error: ' + [err.me](https://err.me)ssage);
  }
  if (event.type === '[checkout.session.com](https://checkout.session.com)pleted') {
    const sess = event.data.object;
    const email = (sess.customer_email || ([sess.me](https://sess.me)tadata && [sess.me](https://sess.me)tadata.email) || '').toLowerCase();
    const user = users.get(email);
    if (user) {
      user.stripeCustomerId = sess.customer;
      user.stripeSubId = sess.subscription;
      user.plan = 'monthly';
      users.set(email, user);
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    for (const u of users.values()) {
      if (u.stripeCustomerId === sub.customer) {
        u.plan = 'trial';
        users.set(u.email, u);
        break;
      }
    }
  }
  res.sendStatus(200);
});

app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const all = [...users.values()];
  res.json({
    total: all.length,
    trial: all.filter(u => u.plan === 'trial').length,
    monthly: all.filter(u => u.plan === 'monthly').length,
    annual: all.filter(u => u.plan === 'annual').length,
    admin: all.filter(u => u.plan === 'admin').length,
    users: all.map(({ passwordHash, ...u }) => u),
  });
});

app.post('/api/admin/set-plan', adminMiddleware, (req, res) => {
  const { email, plan } = req.body || {};
  const user = users.get((email || '').toLowerCase());
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.plan = plan;
  users.set(user.email, user);
  res.json({ ok: true });
});

app.delete('/api/admin/user', adminMiddleware, (req, res) => {
  const { email } = req.body || {};
  const key = (email || '').toLowerCase();
  if (!users.has(key)) return res.status(404).json({ error: 'User not found' });
  users.delete(key);
  res.json({ ok: true });
});

app.get('/api/access', authMiddleware, (req, res) => {
  const user = req.user;
  const trialExpired = user.plan === 'trial' && user.trialEnd && new Date() > new Date(user.trialEnd);
  res.json({
    plan: user.plan,
    access: hasPaidAccess(user) || (user.plan === 'trial' && !trialExpired),
    trialEnd: user.trialEnd || null,
    trialExpired,
  });
});

const send = (file) => (req, res) => res.sendFile(path.join(__dirname, 'public', file));
app.get('/', send('index.html'));
app.get('/login', send('login.html'));
app.get('/register', send('register.html'));
app.get('/pricing', send('pricing.html'));
app.get('/app', send('app.html'));
app.get('/admin', send('admin.html'));

app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log('Bullion Dealer Pro running on port ' + PORT));
