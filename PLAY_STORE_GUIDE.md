# Bullion Dealer Pro — Google Play Store Submission Kit

## Quick Steps (5 mins)

1. Go to **https://pwabuilder.com**
2. Enter `https://bulliondealerpro.com` → **Start**
3. Click **Package For Stores** → **Android**
4. Choose **No signing key** (Google Play will sign it)
5. Download the `.aab` file

---

## Store Listing Content

### App Name
> **Bullion Dealer Pro: Gold & Silver**
*(under 50 chars, keywords for search)*

### Short Description (80 chars max)
> Live gold & silver spot prices, melt calculators, coin values & portfolio P&L.

### Full Description
Paste this into the Play Console:

---

Bullion Dealer Pro is the essential toolkit for precious metals dealers, coin collectors, and bullion investors. Track live spot prices, calculate melt values, compare dealer premiums, and manage your inventory — all in one place.

**LIVE SPOT PRICES**
Real-time gold, silver, platinum, palladium, and copper prices updated directly from market data. Free to access — no account required.

**SILVER COIN MELT CALCULATOR**
Calculate melt values for 90% silver coins instantly: Morgan dollars, Peace dollars, Walking Liberty halves, Franklin halves, Kennedy halves, Washington quarters, Mercury dimes, Roosevelt dimes, and Barber coinage.

**DEALER PREMIUM COMPARISON**
Compare pricing across APMEX, JM Bullion, SD Bullion, and other top dealers side-by-side. Find the best deal before you buy.

**INVENTORY TRACKER**
Track your holdings with cost basis, real-time market value, and profit/loss per item and by category. Cloud-synced across devices.

**KEY DATE COIN VALUES**
Reference values for hundreds of key date US coins — from G4 through MS65 grades — including the 1909-S VDB cent, 1916-D Mercury dime, 1893-S Morgan dollar, and more.

**PROFESSIONAL DEAL CALCULATOR**
Instant buy/sell pricing engine with customizable margins for any bullion product.

**Built for:**
- Coin dealers and pawn shops
- Precious metals investors and stackers
- Coin collectors and numismatists
- Anyone tracking gold and silver prices

**Free to use. No account needed for live spot prices.**

---

### Category
> **Finance**

### Tags
> Investment tracking · Commodities · Portfolio management · Financial news & data · Calculator

### Content Rating
> **Everyone** (complete the IARC questionnaire in Play Console)

---

## Graphics Requirements

| Asset | Size | Notes |
|---|---|---|
| **App Icon** | 512x512 PNG | Use your existing `/favicon-512.png` or dragon-logo.png |
| **Feature Graphic** | 1024x500 PNG | Banner with "Live Gold & Silver Prices" text (I can make this) |
| **Phone Screenshots** | min 4, up to 8 | 1080x1920 or similar |
| **Privacy Policy URL** | — | `https://bulliondealerpro.com/privacy` |

### Screenshot Ideas
1. Home screen showing live gold + silver prices
2. Silver coin melt calculator in use
3. Dealer premium comparison table
4. Inventory tracker with portfolio value
5. Key date coin reference
6. Dealer calculator with margins

---

## Critical Setup — One-Time

### 1. Privacy Policy
Your privacy page is at `https://bulliondealerpro.com/privacy` — link this in the Play Console under "App content → Privacy policy."

### 2. Financial Features Declaration
In Play Console go to **Policy → App content → Financial features**:
- Answer: **Yes**, the app includes financial features
- Type: **Informational tools** (you display prices and calculate values, no trading/loans)
- No additional licenses needed

### 3. Digital Asset Links (assetlinks.json)
Your file already exists at:
```
https://bulliondealerpro.com/.well-known/assetlinks.json
```

**IMPORTANT:** After you generate the `.aab` and Google signs it, you'll get a SHA256 fingerprint from Google Play → **Setup → App integrity**. Copy that fingerprint and update `public/.well-known/assetlinks.json` with it. Without this step, the app will open in a browser tab instead of as a standalone app.

Current placeholder package name: `com.bulliondealerpro.twa`

### After Google signs the app:
1. Go to **Play Console → Setup → App integrity**
2. Copy the **SHA256 certificate fingerprint**
3. Let me know and I'll update `public/.well-known/assetlinks.json` with it

### 4. Data Safety Section
In Play Console → **App content → Data safety**:
- If you don't collect personal data beyond basic analytics, declare:
  - "No data collected" or "Data collected but anonymized"
  - Google Analytics is used — declare that under "App activity"
- No financial info, location, or personal data is collected by the app itself

---

## Deployment Checklist

- [ ] Generate `.aab` from PWABuilder
- [ ] Upload to Play Console → create new app
- [ ] Fill in store listing (copy the description above)
- [ ] Upload screenshots and feature graphic
- [ ] Complete Financial Features declaration
- [ ] Complete IARC content rating questionnaire
- [ ] Link privacy policy
- [ ] Fill out Data Safety section
- [ ] After Google signs the app: copy SHA256 fingerprint → update assetlinks.json → redeploy
- [ ] Submit for review
