'use strict';
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const Stripe = require('stripe');
const Parser = require('rss-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── ENV ──────────────────────────────────────────────────────────────────────
const {
  MONGO_URI, JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
  STRIPE_MONTHLY_PRICE_ID, STRIPE_ANNUAL_PRICE_ID,
  GOLD_API_KEY, GMAIL_USER, GMAIL_PASS, APP_URL = 'https://bulliondealerpro.com'
} = process.env;

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const rssParser = new Parser();

// ── MONGOOSE MODELS ──────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:           { type: String, unique: true, lowercase: true, trim: true },
  passwordHash:    String,
  plan:            { type: String, enum: ['trial','monthly','annual','admin'], default: 'trial' },
  trialEnd:        Date,
  stripeCustomerId:String,
  stripeSubId:     String,
  resetToken:      String,
  resetExpires:    Date,
  createdAt:       { type: Date, default: Date.now }
});

const promoSchema = new mongoose.Schema({
  code:      { type: String, unique: true, uppercase: true },
  plan:      { type: String, enum: ['monthly','annual'], default: 'monthly' },
  months:    { type: Number, default: 1 },
  usedBy:    [String],
  maxUses:   { type: Number, default: 1 },
  createdAt: { type: Date, default: Date.now }
});

const User  = mongoose.model('User',  userSchema);
const Promo = mongoose.model('Promo', promoSchema);

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false });

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET || 'dev_secret');
    next();
  } catch { res.status(401).json({ error: 'Session expired' }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.plan !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

function activeAuth(req, res, next) {
  auth(req, res, () => {
    const { plan, trialEnd } = req.user;
    if (plan === 'admin' || plan === 'monthly' || plan === 'annual') return next();
    if (plan === 'trial' && new Date(trialEnd) > new Date()) return next();
    res.status(403).json({ error: 'Subscription required' });
  });
}

// ── DB CONNECT + ADMIN SEED ───────────────────────────────────────────────────
async function connectDB() {
  if (!MONGO_URI) { console.error('FATAL: MONGO_URI environment variable is not set!'); process.exit(1); }
  console.log('Connecting to MongoDB...');
  await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 30000,
    connectTimeoutMS: 30000,
    socketTimeoutMS: 45000,
  });
  console.log('MongoDB connected');
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await User.findOneAndUpdate(
      { email: ADMIN_EMAIL.toLowerCase() },
      { email: ADMIN_EMAIL.toLowerCase(), passwordHash: hash, plan: 'admin' },
      { upsert: true }
    );
    console.log('Admin user seeded');
  }
}

// ── EMAIL ─────────────────────────────────────────────────────────────────────
function mailer() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_PASS }
  });
}

async function sendResetEmail(to, token) {
  const link = `${APP_URL}/reset-password?token=${token}`;
  await mailer().sendMail({
    from: `"Bullion Dealer Pro" <${GMAIL_USER}>`,
    to,
    subject: 'Reset your password',
    html: `<p>Click to reset your password (expires in 1 hour):</p>
           <p><a href="${link}">${link}</a></p>`
  });
}

// ════════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════════
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 12);
    const trialEnd = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
    const user = await User.create({ email: email.toLowerCase(), passwordHash, plan: 'trial', trialEnd });
    const token = jwt.sign({ id: user._id, email: user.email, plan: user.plan, trialEnd }, JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7*24*60*60*1000 });
    res.json({ ok: true, plan: user.plan, trialEnd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user._id, email: user.email, plan: user.plan, trialEnd: user.trialEnd },
      JWT_SECRET || 'dev_secret', { expiresIn: '7d' }
    );
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7*24*60*60*1000 });
    res.json({ ok: true, plan: user.plan, trialEnd: user.trialEnd });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash -resetToken');
  res.json(user);
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email?.toLowerCase() });
    if (!user) return res.json({ ok: true }); // silent
    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    await sendResetEmail(user.email, token);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const user = await User.findOne({ resetToken: token, resetExpires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
    user.passwordHash = await bcrypt.hash(password, 12);
    user.resetToken = undefined;
    user.resetExpires = undefined;
    await user.save();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// METALS PROXY
// ════════════════════════════════════════════════════════════════════════════════
app.get('/api/metals/:sym', auth, async (req, res) => {
  try {
    const sym = req.params.sym.toUpperCase();
    const r = await fetch(`https://data-asg.goldapi.io/dbPeak/${sym}/USD`, {
      headers: { 'x-access-token': GOLD_API_KEY, 'Content-Type': 'application/json' }
    });
    if (!r.ok) return res.status(r.status).json({ error: 'Upstream error' });
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// NEWS PROXY
// ════════════════════════════════════════════════════════════════════════════════
const newsCache = { items: [], ts: 0 };
app.get('/api/news', async (req, res) => {
  try {
    if (Date.now() - newsCache.ts < 10 * 60 * 1000) return res.json(newsCache.items);
    const feeds = [
      'https://www.kitco.com/rss/kitconews.rss',
      'https://finance.yahoo.com/rss/topic/gold',
      'https://coindesk.com/arc/outboundfeeds/rss/'
    ];
    const results = await Promise.allSettled(feeds.map(f => rssParser.parseURL(f)));
    const items = [];
    for (const r of results) {
      if (r.status === 'fulfilled') {
        for (const item of r.value.items.slice(0, 5)) {
          items.push({ title: item.title, link: item.link, date: item.pubDate });
        }
      }
    }
    newsCache.items = items.slice(0, 20);
    newsCache.ts = Date.now();
    res.json(newsCache.items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// STRIPE
// ════════════════════════════════════════════════════════════════════════════════
app.post('/api/create-checkout', auth, async (req, res) => {
  try {
    const { plan } = req.body;
    const priceId = plan === 'annual' ? STRIPE_ANNUAL_PRICE_ID : STRIPE_MONTHLY_PRICE_ID;
    const user = await User.findById(req.user.id);
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const c = await stripe.customers.create({ email: user.email });
      customerId = c.id;
      user.stripeCustomerId = customerId;
      await user.save();
    }
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${APP_URL}/app?success=1`,
      cancel_url:  `${APP_URL}/pricing`
    });
    res.json({ url: session.url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) { return res.status(400).send('Webhook error'); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customer = await stripe.customers.retrieve(session.customer);
    const user = await User.findOne({ email: customer.email.toLowerCase() });
    if (user) {
      const sub = await stripe.subscriptions.retrieve(session.subscription);
      const plan = sub.items.data[0].price.id === STRIPE_ANNUAL_PRICE_ID ? 'annual' : 'monthly';
      user.plan = plan;
      user.stripeSubId = session.subscription;
      await user.save();
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const user = await User.findOne({ stripeSubId: sub.id });
    if (user) { user.plan = 'trial'; user.trialEnd = new Date(); await user.save(); }
  }
  res.json({ received: true });
});

// ════════════════════════════════════════════════════════════════════════════════
// PROMO CODES
// ════════════════════════════════════════════════════════════════════════════════
app.post('/api/admin/promo/create', adminAuth, async (req, res) => {
  try {
    const { code, plan, months, maxUses } = req.body;
    const promo = await Promo.create({
      code: (code || crypto.randomBytes(4).toString('hex')).toUpperCase(),
      plan: plan || 'monthly',
      months: months || 1,
      maxUses: maxUses || 1
    });
    res.json(promo);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/promo/redeem', auth, async (req, res) => {
  try {
    const { code } = req.body;
    const promo = await Promo.findOne({ code: code.toUpperCase() });
    if (!promo) return res.status(404).json({ error: 'Invalid code' });
    if (promo.usedBy.length >= promo.maxUses) return res.status(400).json({ error: 'Code already used' });
    if (promo.usedBy.includes(req.user.email)) return res.status(400).json({ error: 'Already redeemed' });
    const user = await User.findById(req.user.id);
    user.plan = promo.plan;
    promo.usedBy.push(user.email);
    await Promise.all([user.save(), promo.save()]);
    res.json({ ok: true, plan: user.plan });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await User.find().select('-passwordHash -resetToken').sort({ createdAt: -1 });
  res.json(users);
});

app.patch('/api/admin/users/:id', adminAuth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-passwordHash');
  res.json(user);
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/promos', adminAuth, async (req, res) => {
  res.json(await Promo.find().sort({ createdAt: -1 }));
});

// ════════════════════════════════════════════════════════════════════════════════
// STATIC FILES
// ════════════════════════════════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));

// Page routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin-panel', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ════════════════════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════════════════════
connectDB().then(() => {
  app.listen(PORT, () => console.log(`Bullion Dealer Pro running on port ${PORT}`));
}).catch(e => { console.error('DB error:', e); process.exit(1); });
