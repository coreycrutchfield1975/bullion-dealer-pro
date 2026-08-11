# Bullion Dealer Pro V3 — Blueprint Build

This is a real working front-end preview based on the approved blueprint and Gold Center concept.

## What is implemented
- permanent desktop left navigation
- professional inline SVG icons next to every navigation item
- live top market strip connected to the existing `/api/metals/:symbol` endpoints
- responsive mobile navigation drawer
- Gold Center matching the approved dashboard hierarchy
- live Gold Spot value
- purity table
- working quick Gold calculator
- Goldback preview cards
- popular gold coin cards using the repo's existing new-look assets
- Gold Tools card grid
- page shells for Dashboard, Live Markets, Silver, Coins, Goldbacks, Calculators,
  Dealer Tools, Inventory, Alerts, News, Resources, and Account
- deep links via URL hash

## Why preview first
Do NOT replace the current `/app` yet. This is intentionally installed as `/bdp-v3.html`
so the visual shell can be reviewed without risking the production application.

## Install with Hermes
From the repository root:
`python <package-folder>/INSTALL_PREVIEW.py`

Then visit:
`https://bulliondealerpro.com/bdp-v3.html#gold`

## Next integration
Once the V3 shell is approved visually, move the existing BDP calculators and data tables
into these center modules one by one. The current app remains the source of working logic;
V3 becomes the new presentation and navigation architecture.

## Important
Do not call this production-complete until the existing Silver, Coin, Goldback, Dealer,
Inventory, Alert and other working logic has been mounted into the new V3 modules and tested.
