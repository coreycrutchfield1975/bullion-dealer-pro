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
      <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.10);">
        <!-- Header -->
        <div style="background:#0a0808;padding:28px 32px;text-align:center;border-bottom:3px solid #d4af37;">
          <img src="https://media.base44.com/images/public/69eae2a3c39807325aed8509/8479309ad_generated_image.png" alt="Bullion Dealer Pro" style="height:64px;width:auto;display:inline-block;">
        </div>
        <!-- Body -->
        <div style="padding:36px 32px;background:#fff;">
          <h2 style="margin:0 0 12px;font-size:22px;color:#1a1a1a;font-weight:700;">Password Reset Request</h2>
          <p style="color:#444;font-size:15px;line-height:1.6;margin:0 0 24px;">
            We received a request to reset the password for your Bullion Dealer Pro account.<br>
            Click the button below to set a new password. This link is valid for <strong>1 hour</strong>.
          </p>
          <div style="text-align:center;margin:28px 0;">
            <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(135deg,#d4af37,#f0c040);color:#000;padding:14px 36px;text-decoration:none;border-radius:8px;font-weight:800;font-size:15px;letter-spacing:0.04em;box-shadow:0 4px 14px rgba(212,175,55,0.35);">
              &#128273;&nbsp; RESET MY PASSWORD
            </a>
          </div>
          <p style="color:#888;font-size:12px;line-height:1.6;margin:24px 0 0;border-top:1px solid #eee;padding-top:18px;">
            If you did not request this reset, you can safely ignore this email — your password will remain unchanged.<br>
            For security, this link expires in 1 hour.
          </p>
        </div>
        <!-- Footer -->
        <div style="background:#f7f5f0;padding:18px 32px;text-align:center;border-top:1px solid #e8e0cc;">
          <p style="margin:0;font-size:11px;color:#aaa;letter-spacing:0.05em;">
            &copy; 2026 BULLION DEALER PRO &middot; <a href="https://bulliondealerpro.com" style="color:#d4af37;text-decoration:none;">bulliondealerpro.com</a>
          </p>
        </div>
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


/* ── NEWS RSS PROXY ── */
app.get('/api/news', authMiddleware, async (req, res) => {
  const feeds = [
    { url: 'https://feeds.finance.yahoo.com/rss/2.0/headline?s=%5EIXIC,%5EGSPC,GC%3DF,SI%3DF,ES%3DF&region=US&lang=en-US', cat: 'market' },
    { url: 'https://www.kitco.com/rss/kitco-news-gold.xml', cat: 'bullion' },
    { url: 'https://feeds.finance.yahoo.com/rss/2.0/headline?s=BTC-USD,ETH-USD,SOL-USD&region=US&lang=en-US', cat: 'crypto' },
    { url: 'https://www.coindesk.com/arc/outboundfeeds/rss/', cat: 'crypto' },
    { url: 'https://feeds.reuters.com/reuters/businessNews', cat: 'macro' },
  ];

  const https = require('https');
  const http = require('http');

  function fetchFeed(url) {
    return new Promise((resolve) => {
      const client = url.startsWith('https') ? https : http;
      const req = client.get(url, { headers: { 'User-Agent': 'BullionDealerPro/1.0' }, timeout: 5000 }, (r) => {
        let data = '';
        r.on('data', chunk => data += chunk);
        r.on('end', () => resolve(data));
      });
      req.on('error', () => resolve(''));
      req.on('timeout', () => { req.destroy(); resolve(''); });
    });
  }

  function parseRSS(xml, cat) {
    const items = [];
    const itemRx = /<item>([\s\S]*?)<\/item>/g;
    const titleRx = /<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/;
    const linkRx  = /<link>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/;
    const descRx  = /<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/;
    let m;
    while ((m = itemRx.exec(xml)) !== null && items.length < 6) {
      const t = titleRx.exec(m[1]);
      const l = linkRx.exec(m[1]);
      const d = descRx.exec(m[1]);
      if (t && t[1].trim()) {
        const clean = (s) => s ? s.replace(/<[^>]+>/g,'').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&#39;/g,"'").replace(/&quot;/g,'"').replace(/\s+/g,' ').trim() : '';
        const summary = d ? clean(d[1]).slice(0, 160) : '';
        items.push({
          text: clean(t[1]),
          link: l ? l[1].trim() : '#',
          summary,
          cat
        });
      }
    }
    return items;
  }

  try {
    const results = await Promise.allSettled(feeds.map(f => fetchFeed(f.url)));
    let allItems = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled' && r.value) {
        allItems = allItems.concat(parseRSS(r.value, feeds[i].cat));
      }
    });
    if (allItems.length === 0) return res.json({ ok: false, items: [] });
    res.json({ ok: true, items: allItems });
  } catch (e) {
    res.json({ ok: false, items: [] });
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

/* ═══════════════════════════════════════════════════
   PROMO / GIFT CODE SYSTEM
   ═══════════════════════════════════════════════════ */

const promoSchema = new mongoose.Schema({
  code:       { type: String, required: true, unique: true, uppercase: true },
  plan:       { type: String, default: 'annual' },   // 'monthly' or 'annual'
  usedBy:     { type: String, default: null },         // email of redeemer
  usedAt:     { type: Date, default: null },
  createdBy:  { type: String, default: 'admin' },
  createdAt:  { type: Date, default: Date.now },
  note:       { type: String, default: '' },           // e.g. "Winner - May contest"
});
const PromoCode = mongoose.model('PromoCode', promoSchema);

// Admin: create a promo code
app.post('/api/admin/promo/create', adminMiddleware, async (req, res) => {
  try {
    const { code, plan = 'annual', note = '' } = req.body || {};
    if (!code) return res.status(400).json({ error: 'code is required' });
    const clean = code.toUpperCase().replace(/\s+/g, '');
    const existing = await PromoCode.findOne({ code: clean });
    if (existing) return res.status(409).json({ error: 'Code already exists' });
    const promo = await PromoCode.create({ code: clean, plan, note });
    res.json({ ok: true, code: promo.code, plan: promo.plan });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: list all promo codes
app.get('/api/admin/promo/list', adminMiddleware, async (req, res) => {
  try {
    const promos = await PromoCode.find({}).sort({ createdAt: -1 });
    res.json({ promos });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Admin: delete a promo code
app.delete('/api/admin/promo', adminMiddleware, async (req, res) => {
  try {
    const { code } = req.body || {};
    await PromoCode.findOneAndDelete({ code: (code || '').toUpperCase() });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// User: redeem a promo code (must be logged in)
app.post('/api/promo/redeem', authMiddleware, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: 'No code provided' });
    const clean = code.toUpperCase().replace(/\s+/g, '');
    const promo = await PromoCode.findOne({ code: clean });
    if (!promo) return res.status(404).json({ error: 'Invalid code' });
    if (promo.usedBy) return res.status(409).json({ error: 'Code already used' });
    // Apply plan to user
    await User.findOneAndUpdate(
      { email: req.user.email },
      { plan: promo.plan, trialEnd: null }
    );
    // Mark code as used
    await PromoCode.findOneAndUpdate(
      { code: clean },
      { usedBy: req.user.email, usedAt: new Date() }
    );
    res.json({ ok: true, plan: promo.plan, message: `🎉 Congratulations! Your ${promo.plan} subscription is now active.` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
# Sat Apr 25 14:02:48 UTC 2026
