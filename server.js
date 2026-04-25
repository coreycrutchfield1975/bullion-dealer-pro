'use strict';
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

/* ── MongoDB ── */
mongoose.connect(process.env.MONGODB_URI, { dbName: 'bulliondealerpro' })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  email:            { type: String, required: true, unique: true, lowercase: true },
  passwordHash:     { type: String, required: true },
  plan:             { type: String, default: 'trial' },
  trialEnd:         { type: Date },
  stripeCustomerId: { type: String },
  stripeSubId:      { type: String },
  resetToken:       { type: String },
  resetTokenExpiry: { type: Date },
  createdAt:        { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

/* ── Nodemailer ── */
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'coreycrutchfield1975@gmail.com',
    pass: (process.env.GMAIL_APP_PASSWORD || '').replace(/\s/g, ''),
  },
});

/* ── Stripe ── */
let stripe = null;
if (process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.startsWith('sk_')) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

/* Seed admin */
async function seedAdmin() {
  const adminEmail = 'coreycrutchfield1975@gmail.com';
  const adminPassword = (process.env.ADMIN_PASSWORD || '').trim();
  if (!adminPassword) { console.log('ADMIN_PASSWORD not set, skipping seed'); return; }
  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await User.create({ email: adminEmail, passwordHash, plan: 'admin' });
    console.log('Admin seeded:', adminEmail);
  } else if (existing.plan !== 'admin') {
    existing.plan = 'admin';
    await existing.save();
    console.log('Admin plan updated:', adminEmail);
  } else {
    console.log('Admin already exists:', adminEmail);
  }
}

mongoose.connection.once('open', seedAdmin);

/* ── Middleware ── */
// Security
app.use(helmet({ contentSecurityPolicy: false }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Too many attempts, try again in 15 minutes" } });

app.use(cors({ origin: APP_URL, credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ── Auth helpers ── */
function signToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies.bdp_token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const { email } = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function adminMiddleware(req, res, next) {
  await authMiddleware(req, res, () => {
    if (req.user.plan !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

function hasPaidAccess(user) {
  return user.plan === 'admin' || user.plan === 'monthly' || user.plan === 'annual';
}

/* ── AUTH ROUTES ── */

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 10);
  await User.create({
    email: email.toLowerCase(),
    passwordHash,
    plan: 'trial',
    trialEnd: new Date(Date.now() + 14 * 86400000),
  });

  const token = signToken(email.toLowerCase());
  res.cookie('bdp_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 86400000 });
  res.json({ ok: true, plan: 'trial' });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.passwordHash);
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
  const { passwordHash, resetToken, resetTokenExpiry, ...safe } = req.user.toObject();
  res.json(safe);
});

/* ── PASSWORD RESET ── */

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = await User.findOne({ email: email.toLowerCase() });
  // Always return success to avoid email enumeration
  if (!user) return res.json({ ok: true });

  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour
  await user.save();

  const resetUrl = `${APP_URL}/reset-password?token=${token}`;

  await mailer.sendMail({
    from: '"Bullion Dealer Pro" <coreycrutchfield1975@gmail.com>',
    to: user.email,
    subject: 'Reset your Bullion Dealer Pro password',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;">
        <h2 style="color:#d4af37;">Bullion Dealer Pro</h2>
        <p>You requested a password reset. Click the button below to set a new password:</p>
        <a href="${resetUrl}" style="display:inline-block;background:#d4af37;color:#000;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;margin:16px 0;">Reset Password</a>
        <p style="color:#666;font-size:13px;">This link expires in 1 hour. If you did not request this, ignore this email.</p>
      </div>
    `,
  });

  res.json({ ok: true });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: new Date() } });
  if (!user) return res.status(400).json({ error: 'Invalid or expired reset link' });

  user.passwordHash = await bcrypt.hash(password, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();

  res.json({ ok: true });
});

/* ── STRIPE ROUTES ── */

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
    success_url: `${APP_URL}/app?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${APP_URL}/pricing`,
    metadata: { email: req.user.email },
  });

  res.json({ url: session.url });
});

app.post('/api/stripe/portal', authMiddleware, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
  if (!req.user.stripeCustomerId) return res.status(400).json({ error: 'No subscription found' });

  const session = await stripe.billingPortal.sessions.create({
    customer: req.user.stripeCustomerId,
    return_url: `${APP_URL}/app`,
  });
  res.json({ url: session.url });
});

app.post('/api/stripe/webhook', async (req, res) => {
  if (!stripe) return res.sendStatus(200);
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook sig failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const sess = event.data.object;
    const email = (sess.customer_email || sess.metadata?.email || '').toLowerCase();
    await User.findOneAndUpdate({ email }, {
      stripeCustomerId: sess.customer,
      stripeSubId: sess.subscription,
      plan: 'monthly',
    });
  }

  if (event.type === 'invoice.paid') {
    const inv = event.data.object;
    await User.findOneAndUpdate({ stripeCustomerId: inv.customer }, { plan: 'monthly' });
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    await User.findOneAndUpdate({ stripeCustomerId: sub.customer }, { plan: 'trial' });
  }

  res.sendStatus(200);
});

/* ── ADMIN API ── */

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  const all = await User.find({}, { passwordHash: 0, resetToken: 0, resetTokenExpiry: 0 });
  res.json({
    total: all.length,
    trial: all.filter(u => u.plan === 'trial').length,
    monthly: all.filter(u => u.plan === 'monthly').length,
    annual: all.filter(u => u.plan === 'annual').length,
    admin: all.filter(u => u.plan === 'admin').length,
    users: all,
  });
});

app.post('/api/admin/set-plan', adminMiddleware, async (req, res) => {
  const { email, plan } = req.body || {};
  const user = await User.findOneAndUpdate({ email: (email || '').toLowerCase() }, { plan }, { new: true });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.delete('/api/admin/user', adminMiddleware, async (req, res) => {
  const { email } = req.body || {};
  const result = await User.findOneAndDelete({ email: (email || '').toLowerCase() });
  if (!result) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

/* ── ACCESS CHECK ── */
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

/* ── METALS PROXY ── */
app.get('/api/metals/:sym', authMiddleware, async (req, res) => {
  const allowed = ['XAU','XAG','HG','XPT','XPD'];
  const sym = (req.params.sym || '').toUpperCase();
  if (!allowed.includes(sym)) return res.status(400).json({ error: 'Unknown symbol' });
  try {
    const headers = { 'Accept': 'application/json' };
    if (process.env.GOLD_API_KEY) headers['x-access-token'] = process.env.GOLD_API_KEY;
    const r = await fetch(`https://api.gold-api.com/price/${sym}`, { headers });
    if (!r.ok) throw new Error('upstream ' + r.status);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    console.error('Metals proxy error:', e.message);
    res.status(502).json({ error: 'Metals data unavailable' });
  }
});

/* ── SITEMAP & ROBOTS ── */
app.get('/sitemap.xml', (req, res) => {
  const base = process.env.APP_URL || 'https://bulliondealerpro.com';
  const pages = ['', '/pricing', '/login', '/register'];
  const urls = pages.map(p => `
  <url>
    <loc>${base}${p}</loc>
    <changefreq>weekly</changefreq>
    <priority>${p === '' ? '1.0' : '0.8'}</priority>
  </url>`).join('');
  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}
</urlset>`);
});

app.get('/robots.txt', (req, res) => {
  const base = process.env.APP_URL || 'https://bulliondealerpro.com';
  res.set('Content-Type', 'text/plain');
  res.send(`User-agent: *\nAllow: /\nDisallow: /app\nDisallow: /admin\nSitemap: ${base}/sitemap.xml`);
});

/* ── PAGE ROUTES ── */
const send = (file) => (req, res) => res.sendFile(path.join(__dirname, 'public', file));

app.get('/', send('index.html'));
app.get('/login', send('login.html'));
app.get('/register', send('register.html'));
app.get('/pricing', send('pricing.html'));
app.get('/reset-password', send('reset-password.html'));
app.get('/app', send('app.html'));
app.get('/admin', send('admin.html'));

/* 404 */
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));

/* Error handler */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
