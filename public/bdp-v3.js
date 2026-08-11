const nav=[
["dashboard","i-grid","Dashboard"],["markets","i-chart","Live Markets"],["gold","i-bars","Gold"],["silver","i-coins","Silver"],["coins","i-coin","Coins"],["goldbacks","i-note","Goldbacks"],["calculators","i-calc","Calculators"],["dealer","i-tools","Dealer Tools","PRO"],["inventory","i-box","Inventory","PRO"],["alerts","i-bell","Alerts"],["news","i-news","News"],["resources","i-book","Resources"],["account","i-user","Account"]];
const marketDefs=[["XAU","GOLD"],["XAG","SILVER"],["XPT","PLATINUM"],["XPD","PALLADIUM"],["RATIO","GOLD/SILVER"]];
let prices={XAU:2387.45,XAG:28.74,XPT:978.50,XPD:1021.35,XCU:4.28};
const fmt=n=>'$'+Number(n||0).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});
function icon(id){return `<svg><use href="#${id}"/></svg>`}
function buildNav(){
 sideNav.innerHTML=nav.map(n=>`<a class="nav-item" data-page="${n[0]}">${icon(n[1])}<span>${n[2]}</span>${n[3]?`<b class="badge">${n[3]}</b>`:''}</a>`).join('');
 sideNav.querySelectorAll('a').forEach(a=>a.onclick=()=>go(a.dataset.page));
}
async function getMetal(sym){
 try{const r=await fetch('/api/metals/'+sym);if(!r.ok)throw 0;return await r.json()}catch(e){return null}
}
async function loadMarkets(){
 const syms=['XAU','XAG','XPT','XPD','XCU'];
 const vals=await Promise.all(syms.map(getMetal));
 vals.forEach((v,i)=>{if(v&&Number(v.price))prices[syms[i]]=Number(v.price)});
 drawMarket();
 if(location.hash.replace('#','')==='gold')renderGold();
}
function drawMarket(){
 const ratio=prices.XAU/prices.XAG;
 marketStrip.innerHTML=marketDefs.map(([s,n],i)=>{
  const val=s==='RATIO'?ratio:prices[s];
  const ch=[.79,1.27,-.53,.62,.22][i];
  return `<div class="market-tile"><small>${n}</small><strong>${s==='RATIO'?val.toFixed(2):fmt(val)}</strong><em class="${ch>=0?'up':'down'}">${ch>=0?'+':''}${ch.toFixed(2)}%</em></div>`;
 }).join('');
}
function chartSVG(){
 return `<div class="chart"><svg viewBox="0 0 500 150" preserveAspectRatio="none"><path class="area" d="M0 125 L25 118 50 122 75 100 100 108 125 86 150 92 175 58 200 80 225 72 250 96 275 82 300 67 325 62 350 48 375 60 400 42 425 34 450 40 475 22 500 16 L500 150 L0 150Z"/><path class="line" d="M0 125 L25 118 50 122 75 100 100 108 125 86 150 92 175 58 200 80 225 72 250 96 275 82 300 67 325 62 350 48 375 60 400 42 425 34 450 40 475 22 500 16"/></svg></div>`
}
function setActive(p){
 document.querySelectorAll('.nav-item').forEach(a=>a.classList.toggle('active',a.dataset.page===p));
 sidebar.classList.remove('open');
}
function go(p){location.hash=p}
window.onhashchange=render;
function render(){const p=location.hash.replace('#','')||'gold';setActive(p); if(p==='gold')renderGold(); else renderGeneric(p)}
function renderGold(){
 const au=prices.XAU, gram=au/31.1034768;
 const karats=[[24,.9999],[22,.9167],[18,.75],[14,.5833],[10,.4167]];
 page.innerHTML=`<section class="hero" style="--hero:url('/img/newlook/card-gold.png')"><h1>GOLD CENTER</h1><p>Real-time gold prices, calculators, Goldbacks, and tools to help you buy, sell and profit with confidence.</p></section>
 <div class="subnav"><button class="active">▰ OVERVIEW</button><button>KARAT CALCULATOR</button><button>GOLDBACKS</button><button>BULLION & COINS</button><button>SCRAP GOLD</button><button>HISTORICAL CHARTS</button></div>
 <div class="page">
 <div class="grid three">
 <section class="card"><div class="card-head">GOLD SPOT PRICE <span class="up">● LIVE</span></div><div class="card-body"><div class="price-big">${fmt(au)}</div><div class="up">+18.67 (+0.79%) ↗</div>${chartSVG()}<div class="statbar"><div><small>OPEN</small><strong>${fmt(au-18.67)}</strong></div><div><small>HIGH</small><strong>${fmt(au+4.66)}</strong></div><div><small>LOW</small><strong>${fmt(au-25.0)}</strong></div><div><small>PREV CLOSE</small><strong>${fmt(au-18.67)}</strong></div></div></div></section>
 <section class="card"><div class="card-head">GOLD BY PURITY <small>(MELT VALUE PER GRAM)</small></div><div class="card-body"><table><thead><tr><th>KARAT</th><th>PURITY</th><th>GRAM PRICE</th><th>OZT PRICE</th></tr></thead><tbody>${karats.map(k=>`<tr><td>${k[0]}K</td><td>${(k[1]*100).toFixed(2)}%</td><td>${fmt(gram*k[1])}</td><td>${fmt(au*k[1])}</td></tr>`).join('')}</tbody></table></div></section>
 <section class="card"><div class="card-head">QUICK GOLD CALCULATOR</div><div class="card-body"><div class="form-row"><div class="field"><label>WEIGHT</label><input id="gWeight" type="number" value="10"></div><div class="field"><label>UNIT</label><select id="gUnit"><option>Grams</option><option>Troy Ounces</option></select></div></div><div class="form-row"><div class="field"><label>KARAT</label><select id="gKarat"><option value=".5833">14K (58.33%)</option><option value=".75">18K (75%)</option><option value=".9167">22K (91.67%)</option><option value=".9999">24K (99.99%)</option></select></div><div class="field"><label>PAYOUT %</label><input id="gPay" type="number" value="80"></div></div><div class="calc-result"><div><small>MELT VALUE</small><strong id="rMelt">—</strong></div><div><small>PAYOUT</small><strong class="up" id="rPay">—</strong></div><div><small>DEALER SPREAD</small><strong id="rSpread" style="color:var(--gold2)">—</strong></div></div><button class="gold-btn" onclick="goldCalc()">▣ CALCULATE NOW</button></div></section>
 </div>
 <div class="grid three" style="margin-top:12px">
 <section class="card"><div class="card-head">GOLDBACKS · LIVE VALUES</div><div class="card-body"><div class="tile-row">${[1,5,10,25,50].map(n=>`<div class="image-tile"><img src="/img/newlook/card-goldbacks.png"><b>${n} GOLDBACK</b><small>${fmt(n*5.78)}</small></div>`).join('')}</div></div></section>
 <section class="card"><div class="card-head">POPULAR GOLD COINS · MELT VALUE</div><div class="card-body"><div class="tile-row">${[['EAGLE','gold-coin-eagle.png'],['BUFFALO','gold-coin-buffalo.png'],['KRUGERRAND','gold-coin-krugerrand.png'],['MAPLE','gold-coin-eagle.png']].map(c=>`<div class="image-tile"><img src="/img/newlook/${c[1]}"><b>${c[0]}</b><small>${fmt(au)}</small></div>`).join('')}</div></div></section>
 <section class="card"><div class="card-head">GOLD TOOLS</div><div class="card-body"><div class="tool-grid">${[['i-bars','Scrap Gold Calculator'],['i-calc','Karat Calculator'],['i-coin','Gold Jewelry Value'],['i-bell','Gold Price Alerts'],['i-tools','Compare Dealers'],['i-chart','Historical Charts']].map(t=>`<div class="tool">${icon(t[0])}<span>${t[1]}</span></div>`).join('')}</div></div></section>
 </div></div>`;
 goldCalc();
}
function goldCalc(){
 const w=Number(document.querySelector('#gWeight')?.value||0),k=Number(document.querySelector('#gKarat')?.value||.5833),pay=Number(document.querySelector('#gPay')?.value||80)/100,u=document.querySelector('#gUnit')?.value;
 const grams=u==='Troy Ounces'?w*31.1034768:w,melt=grams*(prices.XAU/31.1034768)*k,payout=melt*pay;
 if(rMelt){rMelt.textContent=fmt(melt);rPay.textContent=fmt(payout);rSpread.textContent=fmt(melt-payout)}
}
const pageMeta={
 dashboard:["DASHBOARD","Executive overview of the BDP platform",["Market Snapshot","My Market","Quick Actions","Dealer Opportunity","Market News","Portfolio Preview"]],
 markets:["LIVE MARKETS","Real-time precious-metals command center",["Interactive Price Chart","Market Status","Key Ratios","Session Intelligence","Futures","Market News"]],
 silver:["SILVER CENTER","Silver stacker and dealer workspace",["Silver Spot","Constitutional Silver","Roll Values","Quick Silver Deal","Popular Bullion","Silver Tools"]],
 coins:["COIN CENTER","Bullion and numismatic research",["Coin Search","Popular Categories","Melt vs Numismatic","Key Dates","Grading Reference","Coin Tools"]],
 goldbacks:["GOLDBACK CENTER","Rates, notes, denominations and transaction tools",["Working Rate","Denominations","State / Series","Transaction Converter","Retailer Links","Education"]],
 calculators:["CALCULATOR CENTER","One professional hub for every BDP calculator",["Precious Metals","Dealer Pricing","Coins","Conversions","Active Calculator","Saved Defaults"]],
 dealer:["DEALER TOOLS","Professional quote, spread and profit workspace",["Deal Sheet","Quick Benchmarks","Compare Dealers","Scrap Buyer","Trading Sheet","Dealer Reference"]],
 inventory:["INVENTORY","Track holdings, basis and profit",["Portfolio Summary","Holdings Table","Add Item","Filters","Profit / Loss","Export"]],
 alerts:["PRICE ALERTS","Actionable price and ratio alerts",["Alert Builder","Active Alerts","Distance to Trigger","History","Suggested Alerts","Notifications"]],
 news:["MARKET NEWS","Curated precious-metals news",["Lead Story","Latest News","Category Filters","Source / Time","Market Impact","Saved Stories"]],
 resources:["RESOURCE CENTER","Guides, references and trusted links",["Beginner Guides","Dealer Reference","Market Education","Trusted Links","Coin References","Goldback Guides"]],
 account:["ACCOUNT","Profile, subscription and preferences",["Profile","Subscription","Preferences","Data","Security","Support"]]
};
const heroMap={silver:"card-silver.png",coins:"coins-hero.png",goldbacks:"card-goldbacks.png",markets:"fx-hero.png",dealer:"card-dealer.png"};
function renderGeneric(p){
 const m=pageMeta[p]||pageMeta.dashboard;
 page.innerHTML=`<section class="hero" style="--hero:url('/img/newlook/${heroMap[p]||'card-market.png'}')"><h1>${m[0]}</h1><p>${m[1]}</p></section><div class="page"><div class="generic-grid">${m[2].map((x,i)=>`<section class="generic-card"><h3>${x}</h3><p>${['Live, compact and decision-oriented.','Designed to match the BDP premium dashboard shell.','Existing BDP logic can be mounted inside this module.'][i%3]}</p><div class="fake"></div></section>`).join('')}</div></div>`;
}
menuBtn.onclick=()=>sidebar.classList.toggle('open');
buildNav();drawMarket();render();loadMarkets();setInterval(loadMarkets,60000);
