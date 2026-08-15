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
  STRIPE_PRICE_MONTHLY: STRIPE_MONTHLY_PRICE_ID, STRIPE_PRICE_ANNUAL: STRIPE_ANNUAL_PRICE_ID,
  GOLD_API_KEY, GMAIL_USER, GMAIL_PASS, APP_URL = 'https://bulliondealerpro.com'
} = process.env;

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const TEST_MODE = process.env.TEST_MODE === 'true';
const STRIPE_TEST_MONTHLY = process.env.STRIPE_TEST_MONTHLY_PRICE_ID;
const STRIPE_TEST_ANNUAL  = process.env.STRIPE_TEST_ANNUAL_PRICE_ID;
const BILLING_PLANS = Object.freeze({
  monthly: { unitAmount: 499, interval: 'month' },
  annual: { unitAmount: 4900, interval: 'year' }
});
// BDP_SERVER_HARDENING_V325
if (!JWT_SECRET && !TEST_MODE) {
  console.error('FATAL: JWT_SECRET environment variable is required outside TEST_MODE.');
  process.exit(1);
}
const JWT_KEY = JWT_SECRET || 'bdp_test_mode_only_secret';
const TOKEN_COOKIE = {
  httpOnly: true,
  secure: !TEST_MODE,
  sameSite: 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000
};
const TOKEN_CLEAR_COOKIE = { httpOnly: true, secure: !TEST_MODE, sameSite: 'lax' };

const CORS_ORIGINS = String(process.env.CORS_ORIGINS || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);
const CSP_REPORT_ONLY = process.env.CSP_REPORT_ONLY === 'true';
const CSP_REPORT_ONLY_VALUE = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://utt.impactcdn.com https://www.googletagmanager.com https://pagead2.googlesyndication.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https:",
  "connect-src 'self' https://www.google-analytics.com https://*.google-analytics.com https://www.googletagmanager.com https://pagead2.googlesyndication.com",
  "frame-src 'self' https://checkout.stripe.com https://*.googlesyndication.com https://*.doubleclick.net",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self' https://checkout.stripe.com"
].join('; ');
const rssParser = new Parser();

// ── MONGOOSE MODELS ──────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:           { type: String, unique: true, lowercase: true, trim: true },
  passwordHash:    String,
  plan:            { type: String, enum: ['free','trial','monthly','annual','admin'], default: 'trial' },
  trialEnd:        Date,
  stripeCustomerId:String,
  stripeSubId:     String,
  resetToken:      String,
  resetExpires:    Date,
  createdAt:       { type: Date, default: Date.now },
  syncInventory:   { type: Array,  default: [] },
  syncSlabs:       { type: Array,  default: [] },
  syncTypesets:    { type: Object, default: {} },
  syncPresets:     { type: Object, default: {} },
  syncAlerts:      { type: Array,  default: [] }
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
if (CORS_ORIGINS.length) {
  app.use(cors({
    origin(origin, callback) {
      if (!origin || CORS_ORIGINS.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true
  }));
} else {
  app.use(cors());
  console.warn('[security] CORS_ORIGINS is not configured; permissive CORS remains active.');
}
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (CSP_REPORT_ONLY) {
    res.setHeader('Content-Security-Policy-Report-Only', CSP_REPORT_ONLY_VALUE);
  }
  next();
});

async function stripeWebhookHandler(req, res) {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.error('[stripe-webhook] Stripe webhook configuration is incomplete.');
    return res.status(503).send('Webhook unavailable');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      STRIPE_WEBHOOK_SECRET
    );
  } catch (e) {
    console.warn('[stripe-webhook] signature verification failed:', e.message);
    return res.status(400).send('Webhook error');
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const customer = await stripe.customers.retrieve(session.customer);
      const customerEmail = String(customer?.email || '').trim().toLowerCase();
      if (!customerEmail) throw new Error('Stripe customer email missing');

      const user = await User.findOne({ email: customerEmail });
      if (user) {
        const sub = await stripe.subscriptions.retrieve(session.subscription);
        const annualPriceId = TEST_MODE ? STRIPE_TEST_ANNUAL : STRIPE_ANNUAL_PRICE_ID;
        const actualPriceId = sub?.items?.data?.[0]?.price?.id;
        if (!actualPriceId) throw new Error('Stripe subscription price missing');
        user.plan = actualPriceId === annualPriceId ? 'annual' : 'monthly';
        user.stripeSubId = session.subscription;
        await user.save();
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const user = await User.findOne({ stripeSubId: sub.id });
      if (user) {
        user.plan = 'trial';
        user.trialEnd = new Date();
        await user.save();
      }
    }

    return res.json({ received: true });
  } catch (e) {
    console.error('[stripe-webhook] processing failed:', e.message);
    return res.status(500).send('Webhook processing failed');
  }
}

app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), stripeWebhookHandler);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false });
const accountLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders: false });

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}
function validNewPassword(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}
function safeServerError(res, status, publicMessage, err, scope) {
  console.error(`[${scope}]`, err?.message || err);
  return res.status(status).json({ error: publicMessage });
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_KEY);
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
    if (plan === 'free') return next(); // free tier gets basic access
    if (plan === 'trial' && new Date(trialEnd) > new Date()) return next();
    if (plan === 'trial' && new Date(trialEnd) <= new Date()) {
      // expired trial downgrades to free
      return next();
    }
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
app.post('/api/register', accountLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!validEmail(email)) return res.status(400).json({ error: 'A valid email is required' });
    if (!validNewPassword(password)) return res.status(400).json({ error: 'Password must be 8-128 characters' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 12);
    const trialEnd = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
    const user = await User.create({ email, passwordHash, plan: 'trial', trialEnd });
    const token = jwt.sign({ id: user._id, email: user.email, plan: user.plan, trialEnd }, JWT_KEY, { expiresIn: '7d' });
    res.cookie('token', token, TOKEN_COOKIE);
    res.json({ ok: true, plan: user.plan, trialEnd });
  } catch (e) {
    return safeServerError(res, 500, 'Registration failed', e, 'register');
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!validEmail(email) || typeof password !== 'string') {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user._id, email: user.email, plan: user.plan, trialEnd: user.trialEnd }, JWT_KEY, { expiresIn: '7d' }
    );
    res.cookie('token', token, TOKEN_COOKIE);
    res.json({ ok: true, plan: user.plan, trialEnd: user.trialEnd });
  } catch (e) {
    return safeServerError(res, 500, 'Login failed', e, 'login');
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', TOKEN_CLEAR_COOKIE);
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash -resetToken');
  if (!user) return res.status(401).json({ error: 'Account not found' });
  const userData = user.toObject();
  userData.testMode = TEST_MODE;
  // isPro: true if on paid plan, admin, or active trial
  const now = new Date();
  userData.isPro = (
    userData.plan === 'monthly' ||
    userData.plan === 'annual' ||
    userData.plan === 'admin' ||
    (userData.plan === 'trial' && new Date(userData.trialEnd) > now)
  );
  res.json(userData);
});

app.post('/api/forgot-password', accountLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!validEmail(email)) return res.json({ ok: true });
    const user = await User.findOne({ email });
    if (!user) return res.json({ ok: true });
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    user.resetToken = tokenHash;
    user.resetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    await sendResetEmail(user.email, token);
    res.json({ ok: true });
  } catch (e) {
    console.error('[forgot-password]', e.message);
    return res.json({ ok: true });
  }
});

app.post('/api/reset-password', accountLimiter, async (req, res) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const password = req.body?.password;
    if (!token || !validNewPassword(password)) {
      return res.status(400).json({ error: 'Invalid reset request' });
    }
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      resetToken: { $in: [tokenHash, token] },
      resetExpires: { $gt: new Date() }
    });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
    user.passwordHash = await bcrypt.hash(password, 12);
    user.resetToken = undefined;
    user.resetExpires = undefined;
    await user.save();
    res.json({ ok: true });
  } catch (e) {
    return safeServerError(res, 500, 'Password reset failed', e, 'reset-password');
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// METALS PROXY
// ════════════════════════════════════════════════════════════════════════════════
// Metals cache — 5 min TTL to avoid hammering Yahoo
const metalsCache = {};
const METALS_TTL = 5 * 60 * 1000;

// Symbol map: our codes -> Yahoo Finance futures tickers
const YAHOO_MAP = { XAU:'GC=F', XAG:'SI=F', XCU:'HG=F', XPT:'PL=F', XPD:'PA=F', ZN:'ZN=F' };

app.get('/api/metals/:sym', async (req, res) => {
  const sym = req.params.sym.toUpperCase();
  const cached = metalsCache[sym];
  if (cached && Date.now() - cached.ts < METALS_TTL) return res.json(cached.data);

  const yticker = YAHOO_MAP[sym];
  if (!yticker) return res.status(404).json({ error: 'Unknown symbol' });

  const YAHOO_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache'
  };
  const tryFetch = async (host) => {
    const r = await fetch(
      `https://${host}/v8/finance/chart/${yticker}?interval=1m&range=1d`,
      { headers: YAHOO_HEADERS }
    );
    if (!r.ok) throw new Error(`Yahoo ${host} ${r.status}`);
    return r.json();
  };
  try {
    let yd;
    try { yd = await tryFetch('query1.finance.yahoo.com'); }
    catch(e1) {
      console.log(`[metals] query1 failed (${e1.message}), trying query2...`);
      yd = await tryFetch('query2.finance.yahoo.com');
    }
    const meta = yd?.chart?.result?.[0]?.meta;
    if (!meta) throw new Error('No meta in response');
    const price = meta.regularMarketPrice || 0;
    const prev  = meta.chartPreviousClose || meta.previousClose || price;
    const ch    = +(price - prev).toFixed(4);
    const data  = { price, prev_close_price: prev, ch, symbol: sym };
    metalsCache[sym] = { data, ts: Date.now() };
    console.log(`[metals] ${sym} = $${price}`);
    return res.json(data);
  } catch(e) {
    console.log(`[metals] ERROR ${sym}:`, e.message);
    return res.status(500).json({ error: 'Price data unavailable' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// NEWS PROXY
// ════════════════════════════════════════════════════════════════════════════════
const newsCache = { items: [], ts: 0 };
app.get('/api/news', async (req, res) => {
  try {
    if (Date.now() - newsCache.ts < 10 * 60 * 1000) return res.json(newsCache.items);
    const feeds = [
      'https://feeds.bloomberg.com/markets/news.rss',
      'https://feeds.marketwatch.com/marketwatch/topstories/',
      'https://www.coindesk.com/arc/outboundfeeds/rss/'
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
// CURRENCY EXCHANGE RATES PROXY
// ════════════════════════════════════════════════════════════════════════════════
let fxCache = { data: null, ts: 0 };
app.get('/api/fx', auth, async (req, res) => {
  try {
    if (fxCache.data && Date.now() - fxCache.ts < 30 * 60 * 1000) {
      return res.json(fxCache.data);
    }
    // Use exchangerate-api.com open endpoint (free, no key needed)
    const r = await fetch('https://open.er-api.com/v6/latest/USD');
    const d = await r.json();
    if (!d || d.result === 'error') throw new Error('Exchange rate fetch failed');
    fxCache.data = { rates: d.rates, timestamp: Math.floor(Date.now() / 1000) };
    fxCache.ts = Date.now();
    res.json(fxCache.data);
  } catch (e) {
    // Fallback: try frankfurter.app
    try {
      const r2 = await fetch('https://api.frankfurter.app/latest?from=USD');
      const d2 = await r2.json();
      fxCache.data = { rates: d2.rates, timestamp: Math.floor(Date.now() / 1000) };
      fxCache.ts = Date.now();
      res.json(fxCache.data);
    } catch (e2) {
      res.status(500).json({ error: 'Could not load exchange rates' });
    }
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// STRIPE
// ════════════════════════════════════════════════════════════════════════════════
app.post('/api/create-checkout', auth, async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: 'Billing is temporarily unavailable' });
    const { plan } = req.body || {};
    if (!['monthly','annual'].includes(plan)) {
      return res.status(400).json({ error: 'Invalid billing plan' });
    }
    const priceId = TEST_MODE
      ? (plan === 'annual' ? STRIPE_TEST_ANNUAL : STRIPE_TEST_MONTHLY)
      : (plan === 'annual' ? STRIPE_ANNUAL_PRICE_ID : STRIPE_MONTHLY_PRICE_ID);
    if (!priceId) return res.status(503).json({ error: 'Billing plan is not configured' });
    let configuredPrice;
    try {
      configuredPrice = await stripe.prices.retrieve(priceId);
    } catch (e) {
      if (e?.code === 'resource_missing') {
        console.error(`[billing] ${plan} Stripe Price ID is unavailable to the configured Stripe key.`);
        return res.status(503).json({
          error: `${plan === 'annual' ? 'Annual' : 'Monthly'} billing is connected to a Stripe Price ID that is not available in the active Stripe mode`
        });
      }
      throw e;
    }
    const expectedPlan = BILLING_PLANS[plan];
    if (!configuredPrice.active || configuredPrice.currency !== 'usd' ||
        configuredPrice.unit_amount !== expectedPlan.unitAmount ||
        configuredPrice.recurring?.interval !== expectedPlan.interval) {
      console.error(`[billing] ${plan} Stripe Price ID does not match the approved BDP price.`);
      return res.status(503).json({ error: 'Billing plan configuration does not match current pricing' });
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: 'Account not found' });
    let customerId = user.stripeCustomerId;
    if (customerId) {
      try {
        const existingCustomer = await stripe.customers.retrieve(customerId);
        if (existingCustomer.deleted) customerId = null;
      } catch (e) {
        // A customer ID created in Stripe test mode (or another Stripe account)
        // cannot be reused in live mode. Recover without exposing Stripe details.
        if (e?.code === 'resource_missing') {
          console.warn('[create-checkout] Replacing a stale Stripe customer ID.');
          customerId = null;
        } else {
          throw e;
        }
      }
    }
    if (!customerId) {
      const c = await stripe.customers.create({
        email: user.email,
        metadata: { bdpUserId: String(user._id) }
      });
      customerId = c.id;
      user.stripeCustomerId = customerId;
      await user.save();
    }
    // Only apply trial if user is still in their free trial period
    const trialDaysLeft = user.trialEnd ? Math.ceil((new Date(user.trialEnd) - new Date()) / (1000 * 60 * 60 * 24)) : 0;
    const sessionParams = {
      customer: customerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${APP_URL}/?success=1`,
      cancel_url:  `${APP_URL}/pricing`
    };
    if (trialDaysLeft > 0) {
      sessionParams.subscription_data = { trial_period_days: trialDaysLeft };
    }
    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ url: session.url });
  } catch (e) {
    return safeServerError(res, 500, 'Checkout could not be created', e, 'create-checkout');
  }
});


// Goldback exchange rate proxy
const goldbackCache = { data: null, ts: 0 };
app.get('/api/goldback-rate', async (req, res) => {
  try {
    if (goldbackCache.data && Date.now() - goldbackCache.ts < 5 * 60 * 1000)
      return res.json(goldbackCache.data);

    // goldback.com and all Goldback retailer sites are JS-rendered and block server scraping.
    // Instead: calculate directly from live gold spot price.
    // 1 Goldback = 1/1000 troy oz of 24k gold (by design).
    // BDP shows intrinsic spot value separately from a modeled transaction estimate.
    // The model is not the official Goldback exchange rate; published rates must be verified separately.

    // Get live gold spot from our own Yahoo proxy
    const goldReq = await fetch('https://bulliondealerpro.com/api/metals/XAU');
    const goldData = await goldReq.json();
    const spotPerOz = goldData.price;

    if (!spotPerOz || spotPerOz < 100) throw new Error('Invalid gold spot price');

    const MODEL_MULTIPLIER = 1.94; // BDP model only; not an official Goldback exchange rate
    const denoms = [
      { label: '¼ Goldback',   mult: 0.25,  oz: 0.00025 },
      { label: '½ Goldback',   mult: 0.5,   oz: 0.0005  },
      { label: '1 Goldback',   mult: 1,     oz: 0.001   },
      { label: '2 Goldback',   mult: 2,     oz: 0.002   },
      { label: '5 Goldback',   mult: 5,     oz: 0.005   },
      { label: '10 Goldback',  mult: 10,    oz: 0.010   },
      { label: '25 Goldback',  mult: 25,    oz: 0.025   },
      { label: '50 Goldback',  mult: 50,    oz: 0.050   },
      { label: '100 Goldback', mult: 100,   oz: 0.100   },
    ];

    const base = +(spotPerOz / 1000).toFixed(4); // spot value of 1 Goldback
    const rates = denoms.map(d => ({
      label: d.label,
      oz: d.oz,
      spotValue: +(spotPerOz * d.oz).toFixed(4),
      marketValue: +(spotPerOz * d.oz * MODEL_MULTIPLIER).toFixed(4),
      rate: +(spotPerOz * d.oz * MODEL_MULTIPLIER).toFixed(4), // backward compat
    }));

    const result = {
      base,
      goldSpot: spotPerOz,
      premium: MODEL_MULTIPLIER,
      modelMultiplier: MODEL_MULTIPLIER,
      rates,
      source: 'calculated',
      note: 'BDP modeled estimate based on live gold spot × 1.94. This is not the official Goldback exchange rate; verify published rates separately.',
      updated: new Date().toISOString()
    };

    goldbackCache.data = result;
    goldbackCache.ts = Date.now();
    return res.json(result);
  } catch(e) {
    console.log('[goldback-rate] error:', e.message);
    return res.json({ base: null, rates: null, error: e.message });
  }
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
// ── Cloud Sync ──
app.get('/api/sync', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('plan trialEnd syncInventory syncSlabs syncTypesets syncPresets syncAlerts');
    if (!user) return res.status(401).json({ error: 'Account not found' });
    const inventoryAllowed = user.plan === 'monthly' || user.plan === 'annual' || user.plan === 'admin' ||
      (user.plan === 'trial' && new Date(user.trialEnd) > new Date());
    res.json({ inventory: inventoryAllowed ? (user.syncInventory||[]) : [], inventoryAllowed, slabs: inventoryAllowed ? (user.syncSlabs||[]) : [], typesets: inventoryAllowed ? (user.syncTypesets||{}) : {}, presets: user.syncPresets||{}, alerts: user.syncAlerts||[] });
  } catch(e) { res.status(500).json({ error: 'Sync read failed' }); }
});

app.post('/api/sync', auth, async (req, res) => {
  try {
    const { inventory, slabs, typesets, presets, alerts } = req.body;
    const user = await User.findById(req.user.id).select('plan trialEnd');
    if (!user) return res.status(401).json({ error: 'Account not found' });
    const inventoryAllowed = user.plan === 'monthly' || user.plan === 'annual' || user.plan === 'admin' ||
      (user.plan === 'trial' && new Date(user.trialEnd) > new Date());
    const updates = {
      syncPresets:   presets   || {},
      syncAlerts:    alerts    || []
    };
    if (inventoryAllowed) {
      updates.syncInventory = Array.isArray(inventory) ? inventory : [];
      updates.syncTypesets = typesets && typeof typesets === 'object' && !Array.isArray(typesets) ? typesets : {};
      updates.syncSlabs = (Array.isArray(slabs) ? slabs : []).slice(0, 5000).map(record => ({
        id: String(record?.id || '').slice(0, 80),
        setId: String(record?.setId || '').slice(0, 80),
        coinId: String(record?.coinId || '').slice(0, 120),
        service: String(record?.service || 'Raw').slice(0, 16),
        grade: String(record?.grade || '').slice(0, 24),
        cert: String(record?.cert || '').slice(0, 48),
        purchaseDate: String(record?.purchaseDate || '').slice(0, 10),
        cost: Math.max(0, Number(record?.cost || 0)),
        marketValue: Math.max(0, Number(record?.marketValue || 0)),
        notes: String(record?.notes || '').slice(0, 500),
        createdAt: String(record?.createdAt || '').slice(0, 32)
      }));
    }
    await User.findByIdAndUpdate(req.user.id, updates);
    res.json({ ok: true, inventoryAllowed });
  } catch(e) { res.status(500).json({ error: 'Sync write failed' }); }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await User.find().select('-passwordHash -resetToken').sort({ createdAt: -1 });
  res.json(users);
});

app.patch('/api/admin/users/:id', adminAuth, async (req, res) => {
  const plan = req.body?.plan;
  const allowedPlans = ['trial','monthly','annual','admin'];
  if (!allowedPlans.includes(plan)) return res.status(400).json({ error: 'Invalid plan' });
  const user = await User.findByIdAndUpdate(
    req.params.id,
    { $set: { plan } },
    { new: true, runValidators: true }
  ).select('-passwordHash -resetToken');
  if (!user) return res.status(404).json({ error: 'User not found' });
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
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/refund', (req, res) => res.sendFile(path.join(__dirname, 'public', 'refund.html')));
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, setHeaders: (res, filePath) => { if (filePath.endsWith('.html') || filePath.endsWith('sw.js')) { res.set('Cache-Control', 'no-cache, no-store, must-revalidate'); res.set('Pragma', 'no-cache'); } } }));

// Page routes
app.get('/', (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset.html')));
app.get('/app', (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.setHeader('Cache-Control','no-cache, no-store, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});
app.get('/admin-panel', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ════════════════════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════════════════════
connectDB().then(() => {

// Health check endpoint for keep-alive pings
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

  app.listen(PORT, () => console.log(`Bullion Dealer Pro running on port ${PORT}`));
}).catch(e => { console.error('DB error:', e); process.exit(1); });
