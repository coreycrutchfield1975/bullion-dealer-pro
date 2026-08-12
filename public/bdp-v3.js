const sidebar=document.getElementById('sidebar');
const sideNav=document.getElementById('sideNav');
const menuBtn=document.getElementById('menuBtn');
const marketStrip=document.getElementById('marketStrip');
const page=document.getElementById('page');
const utilityBackdrop=document.getElementById('utilityBackdrop');
const utilityPanel=document.getElementById('utilityPanel');
const utilityTitle=document.getElementById('utilityTitle');
const utilityBody=document.getElementById('utilityBody');
const engineBackdrop=document.getElementById('engineBackdrop');
const engineDrawer=document.getElementById('engineDrawer');
const engineTitle=document.getElementById('engineTitle');
const engineOpenTab=document.getElementById('engineOpenTab');
const engineFrame=document.getElementById('engineFrame');

const nav=[
["dashboard","i-grid","Dashboard","","dashboard"],["markets","i-chart","Live Markets","","markets"],["gold","i-bars","Gold","","gold"],["silver","i-coins","Silver","","silver"],["coins","i-coin","Coins","","coins"],["goldbacks","i-note","Goldbacks","","goldbacks"],["calculators","i-calc","Calculators","","calculators"],["dealer","i-tools","Dealer Tools","PRO","dealer"],["inventory","i-box","Inventory","PRO","inventory"],["alerts","i-bell","Alerts","","alerts"],["news","i-news","News","","news"],["resources","i-book","Resources","","resources"],["account","i-user","Account","","account"]];
const marketDefs=[["XAU","GOLD"],["XAG","SILVER"],["XPT","PLATINUM"],["XPD","PALLADIUM"],["RATIO","GOLD/SILVER"]];
const referencePrices={XAU:2387.45,XAG:28.74,XPT:978.50,XPD:1021.35,XCU:4.28};
let prices={...referencePrices};
let feedState={
 XAU:{state:'reference'},XAG:{state:'reference'},XPT:{state:'reference'},XPD:{state:'reference'},XCU:{state:'reference'}
};
let lastMarketRefresh=0;
const fmt=n=>'$'+Number(n||0).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});
function marketBasis(sym){return sym==='XCU'?'USD / LB':sym==='RATIO'?'RATIO':'USD / OZT'}
function feedPct(sym){
 const f=feedState[sym]; if(!f||!Number(f.prev)||!Number(prices[sym]))return null;
 return ((Number(prices[sym])-Number(f.prev))/Number(f.prev))*100;
}
function feedChangeText(sym){
 const f=feedState[sym];
 if(!f||f.state==='reference')return 'REFERENCE VALUE · WAITING FOR LIVE FEED';
 if(f.state==='stale')return 'STALE · LAST SUCCESSFUL PRICE';
 const pct=feedPct(sym),ch=Number(f.ch||0);
 if(pct===null)return 'LIVE PRICE';
 return `${ch>=0?'+':''}${fmt(ch)} (${pct>=0?'+':''}${pct.toFixed(2)}%) ${ch>=0?'↗':'↘'}`;
}
function feedChangeMarkup(sym){
 const f=feedState[sym];
 if(!f||f.state!=='live')return `<span class="feed-state ${f?.state==='stale'?'feed-stale':'feed-reference'}">${f?.state==='stale'?'STALE':'REFERENCE'}</span>`;
 const pct=feedPct(sym);
 return `<span class="${Number(pct)>=0?'up':'down'}">${pct===null?'LIVE':`${pct>=0?'+':''}${pct.toFixed(2)}%`}</span>`;
}
function feedBadge(sym){
 const state=feedState[sym]?.state||'reference';
 return `<span class="feed-badge feed-${state}">${state==='live'?'● LIVE':state==='stale'?'● STALE':'◇ REFERENCE'}</span>`;
}
function sessionMoveSVG(sym){
 const f=feedState[sym];
 if(!f||f.state==='reference'||!Number(f.prev)||!Number(prices[sym])){
  return `<div class="session-chart session-offline"><div><b>SESSION MOVE</b><span>Waiting for market API data.</span></div></div>`;
 }
 const prev=Number(f.prev),cur=Number(prices[sym]),up=cur>=prev;
 const y1=up?105:35,y2=up?35:105;
 return `<div class="session-chart"><svg viewBox="0 0 500 140" preserveAspectRatio="none"><line x1="18" y1="${y1}" x2="482" y2="${y2}" class="${up?'move-up':'move-down'}"/><circle cx="18" cy="${y1}" r="5"/><circle cx="482" cy="${y2}" r="5"/></svg><div class="session-label left"><small>PREV CLOSE</small><b>${fmt(prev)}</b></div><div class="session-label right"><small>${f.state==='stale'?'LAST PRICE':'CURRENT'}</small><b>${fmt(cur)}</b></div></div>`;
}
function ratioPct(){
 const g=feedState.XAU,s=feedState.XAG;
 if(g?.state!=='live'||s?.state!=='live'||!Number(g.prev)||!Number(s.prev))return null;
 const prevRatio=Number(g.prev)/Number(s.prev),cur=prices.XAU/prices.XAG;
 return ((cur-prevRatio)/prevRatio)*100;
}
function goldbackWorkingRate(){
 const apiOne=goldbackApi?.rates?.find(r=>String(r.label||'').startsWith('1 Goldback'));
 if(apiOne&&Number(apiOne.marketValue||apiOne.rate))return Number(apiOne.marketValue||apiOne.rate);
 return (prices.XAU/1000)*1.94;
}
function icon(id){return `<svg><use href="#${id}"/></svg>`}
function buildNav(){
 sideNav.innerHTML=nav.map(n=>`<a href="#${n[0]}" class="nav-item" data-page="${n[0]}"><span class="nav-photo-wrap"><img class="nav-photo" src="/img/nav/nav-${n[4]}.png" alt="" aria-hidden="true" loading="eager" decoding="async">${icon(n[1])}</span><span class="nav-label">${n[2]}</span>${n[3]?`<b class="badge">${n[3]}</b>`:''}</a>`).join('');
}
async function getMetal(sym){
 try{const r=await fetch('/api/metals/'+sym);if(!r.ok)throw 0;return await r.json()}catch(e){return null}
}
async function loadMarkets(){
 const syms=['XAU','XAG','XPT','XPD','XCU'];
 const vals=await Promise.all(syms.map(getMetal));
 vals.forEach((v,i)=>{
  const sym=syms[i];
  if(v&&Number(v.price)){
   prices[sym]=Number(v.price);
   feedState[sym]={state:'live',prev:Number(v.prev_close_price||v.price),ch:Number(v.ch||0),updated:Date.now()};
  }else{
   feedState[sym]={...(feedState[sym]||{}),state:feedState[sym]?.updated?'stale':'reference'};
  }
 });
 lastMarketRefresh=Date.now();
 drawMarket();
 if(utilityPanel?.classList.contains('open')&&utilityTitle?.textContent==='WATCHLIST')renderWatchlist();
 const current=location.hash.replace('#','')||'dashboard';
 if(current==='gold')renderGold();
 else if(current==='silver')renderSilver();
 else if(current==='calculators')renderCalculators();
 else if(current==='dealer')renderDealer();
 else if(current==='markets')renderMarkets();
 else if(current==='coins')renderCoins();
 else if(current==='goldbacks')renderGoldbacks();
 else if(current==='dashboard')renderDashboard();
 else if(current==='inventory')renderInventory();
 else if(current==='alerts')renderAlerts();
}
function drawMarket(){
 const ratio=prices.XAU/prices.XAG;
 marketStrip.innerHTML=marketDefs.map(([s,n])=>{
  const val=s==='RATIO'?ratio:prices[s];
  let change;
  if(s==='RATIO'){
   const pct=ratioPct();
   change=pct===null?`<span class="feed-state feed-reference">REFERENCE</span>`:`<span class="${pct>=0?'up':'down'}">${pct>=0?'+':''}${pct.toFixed(2)}%</span>`;
  }else change=feedChangeMarkup(s);
  return `<div class="market-tile"><small>${n}</small><strong>${s==='RATIO'?val.toFixed(2):fmt(val)}</strong><em>${change}</em></div>`;
 }).join('');
}

const WATCH_KEY='bdp-v3-watchlist';
let lastUtilityFocus=null;
let lastEngineFocus=null;
function openUtility(type){
 lastUtilityFocus=document.activeElement;
 utilityTitle.textContent=type==='converter'?'WEIGHT CONVERTER':'WATCHLIST';
 utilityPanel.classList.add('open');utilityBackdrop.classList.add('open');utilityPanel.setAttribute('aria-hidden','false');
 if(type==='converter')renderConverter(); else renderWatchlist();
 utilityPanel.focus({preventScroll:true});
}
function closeUtility(){
 const wasOpen=utilityPanel.classList.contains('open');
 utilityPanel.classList.remove('open');utilityBackdrop.classList.remove('open');utilityPanel.setAttribute('aria-hidden','true');
 if(wasOpen&&lastUtilityFocus&&typeof lastUtilityFocus.focus==='function')lastUtilityFocus.focus({preventScroll:true});
 lastUtilityFocus=null;
}
function watchlistItems(){
 try{const a=JSON.parse(localStorage.getItem(WATCH_KEY)||'["XAU","XAG"]');return Array.isArray(a)?a:["XAU","XAG"]}catch(e){return ["XAU","XAG"]}
}
function toggleWatch(sym){
 let a=watchlistItems();a=a.includes(sym)?a.filter(x=>x!==sym):[...a,sym];localStorage.setItem(WATCH_KEY,JSON.stringify(a));renderWatchlist();
}
function renderWatchlist(){
 const syms=[['XAU','Gold'],['XAG','Silver'],['XPT','Platinum'],['XPD','Palladium'],['XCU','Copper']];
 const selected=watchlistItems();
 utilityBody.innerHTML=`<p class="utility-copy">Choose the metals you want at a glance. Watchlist preferences stay in this browser.</p><div class="watch-grid">${syms.map(([s,n])=>`<button class="${selected.includes(s)?'selected':''}" onclick="toggleWatch('${s}')"><span>${selected.includes(s)?'★':'☆'}</span><div><small>${n.toUpperCase()} · ${marketBasis(s)}</small><strong>${fmt(prices[s])}</strong>${feedChangeMarkup(s)}</div></button>`).join('')}</div><div class="utility-foot">Market labels show LIVE only after a successful BDP API response.</div>`;
}
const UNIT_TO_GRAMS={g:1,ozt:31.1034768,dwt:1.55517384,grain:.06479891,kg:1000};
const UNIT_NAMES={g:'Grams',ozt:'Troy Ounces',dwt:'Pennyweight',grain:'Grains',kg:'Kilograms'};
function renderConverter(){
 utilityBody.innerHTML=`<p class="utility-copy">Precious-metals weight converter. Troy ounces are used—not avoirdupois ounces.</p><div class="converter-box"><label>AMOUNT<input id="cvAmount" type="number" value="1" min="0" step="any" oninput="convertWeight()"></label><div class="converter-units"><label>FROM<select id="cvFrom" onchange="convertWeight()">${Object.entries(UNIT_NAMES).map(([v,n])=>`<option value="${v}">${n}</option>`).join('')}</select></label><span>→</span><label>TO<select id="cvTo" onchange="convertWeight()">${Object.entries(UNIT_NAMES).map(([v,n])=>`<option value="${v}" ${v==='g'?'selected':''}>${n}</option>`).join('')}</select></label></div><div class="converter-result"><small>CONVERTED VALUE</small><strong id="cvResult">—</strong><span id="cvFormula"></span></div></div>`;
 convertWeight();
}
function convertWeight(){
 const amount=Math.max(0,Number(document.querySelector('#cvAmount')?.value||0)),from=document.querySelector('#cvFrom')?.value||'ozt',to=document.querySelector('#cvTo')?.value||'g';
 const grams=amount*UNIT_TO_GRAMS[from],result=grams/UNIT_TO_GRAMS[to];
 const resultEl=document.querySelector('#cvResult'),formulaEl=document.querySelector('#cvFormula');
 if(resultEl)resultEl.textContent=Number(result).toLocaleString(undefined,{maximumFractionDigits:6});
 if(formulaEl)formulaEl.textContent=`${amount} ${UNIT_NAMES[from]} = ${Number(result).toLocaleString(undefined,{maximumFractionDigits:6})} ${UNIT_NAMES[to]}`;
}

function chartSVG(){
 return `<div class="chart"><svg viewBox="0 0 500 150" preserveAspectRatio="none"><path class="area" d="M0 125 L25 118 50 122 75 100 100 108 125 86 150 92 175 58 200 80 225 72 250 96 275 82 300 67 325 62 350 48 375 60 400 42 425 34 450 40 475 22 500 16 L500 150 L0 150Z"/><path class="line" d="M0 125 L25 118 50 122 75 100 100 108 125 86 150 92 175 58 200 80 225 72 250 96 275 82 300 67 325 62 350 48 375 60 400 42 425 34 450 40 475 22 500 16"/></svg></div>`
}
function setActive(p){
 const meta = pageMeta[p];
 const label = document.getElementById('currentCenterLabel');
 if(label) label.textContent = meta ? meta.title : (p==='gold'?'GOLD CENTER':'BULLION DEALER PRO');
 document.querySelectorAll('.nav-item').forEach(a=>{
  const active=a.dataset.page===p;
  a.classList.toggle('active',active);
  if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');
 });
 sidebar.classList.remove('open');
 menuBtn.setAttribute('aria-expanded','false');
}
function go(p){location.hash=p}
function scrollToModule(id){const el=document.getElementById(id);if(el)el.scrollIntoView({behavior:'smooth',block:'center'})}
window.onhashchange=render;
function render(){
 const p=location.hash.replace('#','')||'dashboard';
 setActive(p);
 if(p==='gold')renderGold();
 else if(p==='silver')renderSilver();
 else if(p==='calculators')renderCalculators();
 else if(p==='dealer')renderDealer();
 else if(p==='markets')renderMarkets();
 else if(p==='coins')renderCoins();
 else if(p==='goldbacks')renderGoldbacks();
 else if(p==='dashboard')renderDashboard();
 else if(p==='inventory')renderInventory();
 else if(p==='alerts')renderAlerts();
 else if(p==='account')renderAccount();
 else if(p==='news')renderNews();
 else if(p==='resources')renderResources();
 else renderGeneric(p);
}
function renderGold(){
 const au=prices.XAU, gram=au/31.1034768, auFeed=feedState.XAU, auPrev=Number(auFeed.prev||au), auCh=Number(auFeed.ch||0), gbPreviewRate=goldbackWorkingRate();
 const karats=[[24,.9999],[22,.9167],[18,.75],[14,.5833],[10,.4167]];
 page.innerHTML=`<section class="hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>GOLD CENTER</h1><p>Real-time gold prices, calculators, Goldbacks, and tools to help you buy, sell and profit with confidence.</p></section>
 <div class="subnav"><button class="active">▰ OVERVIEW</button><button onclick="scrollToModule('goldKaratCard')">KARAT CALCULATOR</button><button onclick="go('goldbacks')">GOLDBACKS</button><button onclick="go('coins')">BULLION & COINS</button><button onclick="scrollToModule('goldKaratCard')">SCRAP GOLD</button><button onclick="go('markets')">HISTORICAL CHARTS</button></div>
 <div class="page">
 <div class="grid three">
 <section class="card"><div class="card-head">GOLD SPOT PRICE ${feedBadge('XAU')}</div><div class="card-body"><div class="price-big">${fmt(au)}</div><div class="${auCh>=0?'up':'down'}">${feedChangeText('XAU')}</div>${sessionMoveSVG('XAU')}<div class="statbar"><div><small>CURRENT</small><strong>${fmt(au)}</strong></div><div><small>PREV CLOSE</small><strong>${fmt(auPrev)}</strong></div><div><small>CHANGE</small><strong class="${auCh>=0?'up':'down'}">${auFeed.state==='live'?(auCh>=0?'+':'')+fmt(auCh):'—'}</strong></div><div><small>BASIS</small><strong>USD/OZT</strong></div></div></div></section>
 <section class="card"><div class="card-head">GOLD BY PURITY <small>(MELT VALUE PER GRAM)</small></div><div class="card-body"><table><thead><tr><th>KARAT</th><th>PURITY</th><th>GRAM PRICE</th><th>OZT PRICE</th></tr></thead><tbody>${karats.map(k=>`<tr><td>${k[0]}K</td><td>${(k[1]*100).toFixed(2)}%</td><td>${fmt(gram*k[1])}</td><td>${fmt(au*k[1])}</td></tr>`).join('')}</tbody></table></div></section>
 <section class="card" id="goldKaratCard"><div class="card-head">QUICK GOLD / SCRAP CALCULATOR</div><div class="card-body"><div class="form-row"><div class="field"><label>WEIGHT</label><input id="gWeight" type="number" value="10"></div><div class="field"><label>UNIT</label><select id="gUnit"><option>Grams</option><option>Troy Ounces</option></select></div></div><div class="form-row"><div class="field"><label>KARAT</label><select id="gKarat"><option value=".5833">14K (58.33%)</option><option value=".75">18K (75%)</option><option value=".9167">22K (91.67%)</option><option value=".9999">24K (99.99%)</option></select></div><div class="field"><label>PAYOUT %</label><input id="gPay" type="number" value="80"></div></div><div class="calc-result"><div><small>MELT VALUE</small><strong id="rMelt">—</strong></div><div><small>PAYOUT</small><strong class="up" id="rPay">—</strong></div><div><small>DEALER SPREAD</small><strong id="rSpread" style="color:var(--gold2)">—</strong></div></div><button class="gold-btn" onclick="goldCalc()">▣ CALCULATE NOW</button></div></section>
 </div>
 <div class="grid three" style="margin-top:12px">
 <section class="card"><div class="card-head">GOLDBACKS · LIVE VALUES</div><div class="card-body"><div class="tile-row">${[1,5,10,25,50].map(n=>`<div class="image-tile"><img src="/img/newlook/card-goldbacks.png"><b>${n} GOLDBACK</b><small>${fmt(n*gbPreviewRate)}</small></div>`).join('')}</div></div></section>
 <section class="card"><div class="card-head">POPULAR GOLD COINS · MELT VALUE</div><div class="card-body"><div class="tile-row">${[['EAGLE','gold-coin-eagle.png'],['BUFFALO','gold-coin-buffalo.png'],['KRUGERRAND','gold-coin-krugerrand.png'],['MAPLE','gold-coin-maple.png']].map(c=>`<div class="image-tile"><img src="/img/newlook/${c[1]}"><b>${c[0]}</b><small>${fmt(au)}</small></div>`).join('')}</div></div></section>
 <section class="card"><div class="card-head">GOLD TOOLS</div><div class="card-body"><div class="tool-grid">${[['i-bars','Scrap Gold Calculator','scroll','goldKaratCard'],['i-calc','Karat Calculator','scroll','goldKaratCard'],['i-coin','Gold Jewelry Value','scroll','goldKaratCard'],['i-bell','Gold Price Alerts','go','alerts'],['i-tools','Compare Dealers','go','dealer'],['i-chart','Historical Charts','go','markets']].map(t=>t[2]==='scroll'?`<button class="tool tool-button" onclick="scrollToModule('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`:`<button class="tool tool-button" onclick="go('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`).join('')}</div></div></section>
 </div></div>`;
 goldCalc();
}
function goldCalc(){
 const w=Number(document.querySelector('#gWeight')?.value||0),k=Number(document.querySelector('#gKarat')?.value||.5833),pay=Number(document.querySelector('#gPay')?.value||80)/100,u=document.querySelector('#gUnit')?.value;
 const grams=u==='Troy Ounces'?w*31.1034768:w,melt=grams*(prices.XAU/31.1034768)*k,payout=melt*pay;
 const meltEl=document.querySelector('#rMelt'),payEl=document.querySelector('#rPay'),spreadEl=document.querySelector('#rSpread');
 if(meltEl){meltEl.textContent=fmt(melt);payEl.textContent=fmt(payout);spreadEl.textContent=fmt(melt-payout)}
}

const CLASSIC_ENGINE='/app-classic.html';

function openClassic(hash='',title='Working BDP Tool'){
 lastEngineFocus=document.activeElement;
 const url=CLASSIC_ENGINE+(hash||'');
 engineTitle.textContent=title;
 engineFrame.src=url;
 engineOpenTab.href=url;
 engineDrawer.classList.add('open');
 engineBackdrop.classList.add('open');
 engineDrawer.setAttribute('aria-hidden','false');
 document.body.classList.add('drawer-open');
 engineDrawer.focus({preventScroll:true});
}
function closeClassic(){
 const wasOpen=engineDrawer.classList.contains('open');
 engineDrawer.classList.remove('open');
 engineBackdrop.classList.remove('open');
 engineDrawer.setAttribute('aria-hidden','true');
 document.body.classList.remove('drawer-open');
 setTimeout(()=>{if(!engineDrawer.classList.contains('open'))engineFrame.src='about:blank'},220);
 if(wasOpen&&lastEngineFocus&&typeof lastEngineFocus.focus==='function')lastEngineFocus.focus({preventScroll:true});
 lastEngineFocus=null;
}
document.addEventListener('keydown',e=>{
 if(e.key==='Escape'){
  closeClassic();closeUtility();
  sidebar.classList.remove('open');
  menuBtn.setAttribute('aria-expanded','false');
  menuBtn.setAttribute('aria-label','Open navigation');
 }
});
document.addEventListener('click',e=>{
 const el=e.target.closest('[data-classic]');
 if(el){e.preventDefault();openClassic(el.dataset.classic||'',el.dataset.title||el.textContent.trim())}
});

function renderSilver(){
 const ag=prices.XAG, agFeed=feedState.XAG, agCh=Number(agFeed.ch||0);
 const coins=[
  ['90% Dime',0.07234],['90% Quarter',0.18084],['90% Half',0.36169],['Silver Dollar',0.77344]
 ];
 const rolls=[
  ['Dime Roll',50,0.07234],['Quarter Roll',40,0.18084],['Half Roll',20,0.36169]
 ];
 page.innerHTML=`<section class="hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>SILVER CENTER</h1><p>Live silver, constitutional values, rolls, bullion and dealer pricing in one compact workspace.</p></section>
 <div class="subnav"><button class="active">OVERVIEW</button><button onclick="scrollToModule('silverConstitutional')">CONSTITUTIONAL</button><button onclick="scrollToModule('silverBullion')">BULLION</button><button onclick="scrollToModule('silverRolls')">ROLLS</button><button onclick="go('markets')">HISTORICAL CHARTS</button></div>
 <div class="page">
  <div class="grid three">
   <section class="card"><div class="card-head">SILVER SPOT ${feedBadge('XAG')}</div><div class="card-body"><div class="price-big silver-price">${fmt(ag)}</div><div class="${agCh>=0?'up':'down'}">${feedChangeText('XAG')}</div>${sessionMoveSVG('XAG')}<div class="statbar"><div><small>PER GRAM</small><strong>${fmt(ag/31.1034768)}</strong></div><div><small>5% UNDER</small><strong>${fmt(ag*.95)}</strong></div><div><small>SPOT</small><strong>${fmt(ag)}</strong></div><div><small>5% OVER</small><strong>${fmt(ag*1.05)}</strong></div></div></div></section>
   <section class="card" id="silverConstitutional"><div class="card-head">CONSTITUTIONAL SILVER</div><div class="card-body"><table><thead><tr><th>TYPE</th><th>FINE OZT</th><th>FINE GRAMS</th><th>MELT</th><th>5% UNDER</th></tr></thead><tbody>${coins.map(c=>`<tr><td>${c[0]}</td><td>${c[1].toFixed(5)}</td><td>${(c[1]*31.1034768).toFixed(3)} g</td><td>${fmt(c[1]*ag)}</td><td>${fmt(c[1]*ag*.95)}</td></tr>`).join('')}</tbody></table><button class="module-open" onclick="scrollToModule(\'constitutionalCalc\')">CALCULATE A QUANTITY ↓</button></div></section>
   <section class="card"><div class="card-head">QUICK SILVER DEAL</div><div class="card-body">
    <div class="form-row">
      <div class="field"><label>SILVER WEIGHT</label><input id="sWeight" type="number" min="0" step="any" value="10" oninput="silverCalc()"></div>
      <div class="field"><label>WEIGHT UNIT</label><select id="sUnit" onchange="silverCalc()"><option value="ozt">Troy Ounces</option><option value="g">Grams</option></select></div>
    </div>
    <div class="form-row"><div class="field"><label>SILVER SPOT / TROY OZ</label><input id="sSpot" type="number" value="${ag.toFixed(2)}" oninput="silverCalc()"></div><div class="field"><label>SPOT / GRAM</label><input id="sGramSpot" type="text" value="${(ag/31.1034768).toFixed(4)}" readonly></div></div>
    <div class="form-row"><div class="field"><label>BUY % UNDER</label><input id="sUnder" type="number" value="5" oninput="silverCalc()"></div><div class="field"><label>SELL % OVER</label><input id="sOver" type="number" value="5" oninput="silverCalc()"></div></div>
    <div class="silver-weight-conversion">
      <div><small>TROY OUNCES</small><strong id="sOztEquivalent">—</strong></div>
      <div><small>GRAMS</small><strong id="sGramEquivalent">—</strong></div>
      <div><small>PRICE / GRAM</small><strong id="sPerGram">—</strong></div>
    </div>
    <div class="calc-result"><div><small>MELT</small><strong id="sMelt">—</strong></div><div><small>BUY TARGET</small><strong id="sBuy" class="up">—</strong></div><div><small>SELL TARGET</small><strong id="sSell" style="color:var(--gold2)">—</strong></div></div>
    <button class="gold-btn" onclick="silverCalc()">CALCULATE SILVER DEAL</button>
   </div></section>
  </div>
  <section class="card" id="constitutionalCalc" style="margin-top:12px"><div class="card-head">CONSTITUTIONAL SILVER QUANTITY CALCULATOR</div><div class="card-body">
   <div class="form-row"><div class="field"><label>COIN TYPE</label><select id="csType" onchange="constitutionalCalc()"><option value=".07234">90% Dime</option><option value=".18084">90% Quarter</option><option value=".36169">90% Half Dollar</option><option value=".77344">Silver Dollar</option></select></div><div class="field"><label>QUANTITY</label><input id="csQty" type="number" min="0" step="1" value="10" oninput="constitutionalCalc()"></div></div>
   <div class="constitutional-results"><div><small>FINE SILVER OZT</small><strong id="csOzt">—</strong></div><div><small>FINE SILVER GRAMS</small><strong id="csGrams">—</strong></div><div><small>MELT VALUE</small><strong id="csMelt">—</strong></div><div><small>5% UNDER / OVER</small><strong id="csRange">—</strong></div></div>
   <p class="local-note">Fine-silver content uses the same BDP constitutional-silver weights shown above.</p>
  </div></section>
  <div class="grid three" style="margin-top:12px">
   <section class="card" id="silverRolls"><div class="card-head">ROLL VALUES</div><div class="card-body"><table><thead><tr><th>ROLL</th><th>COINS</th><th>FINE OZT</th><th>FINE GRAMS</th><th>MELT</th></tr></thead><tbody>${rolls.map(r=>{const ozt=r[1]*r[2];return `<tr><td>${r[0]}</td><td>${r[1]}</td><td>${ozt.toFixed(4)}</td><td>${(ozt*31.1034768).toFixed(2)} g</td><td>${fmt(ozt*ag)}</td></tr>`}).join('')}</tbody></table></div></section>
   <section class="card" id="silverBullion"><div class="card-head">SILVER BULLION</div><div class="card-body"><div class="silver-art"><img src="/img/newlook/card-silver.png" alt="Silver bullion"><div><b>STACKER WORKSPACE</b><span>Eagles · rounds · bars · premium tools</span><button onclick="scrollToModule('silverBullion')">OPEN SILVER BULLION TOOLS →</button></div></div></div></section>
   <section class="card"><div class="card-head">SILVER TOOLS</div><div class="card-body"><div class="tool-grid">${[['i-calc','Melt Calculator','scroll','silverConstitutional'],['i-coins','Roll Values','scroll','silverRolls'],['i-tools','Dealer Spread','go','dealer'],['i-chart','Historical Charts','go','markets'],['i-star','Premium Tools','go','dealer'],['i-news','Silver Reference','go','resources']].map(t=>t[2]==='scroll'?`<button class="tool tool-button" onclick="scrollToModule('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`:`<button class="tool tool-button" onclick="go('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`).join('')}</div></div></section>
  </div>
 </div>`;
 silverCalc();constitutionalCalc();
}
function constitutionalCalc(){
 const perCoin=Math.max(0,Number(document.querySelector('#csType')?.value||0));
 const qty=Math.max(0,Number(document.querySelector('#csQty')?.value||0));
 const ozt=perCoin*qty,grams=ozt*31.1034768,melt=ozt*Number(prices.XAG||0);
 const el=document.querySelector('#csOzt');
 if(el){
  el.textContent=ozt.toLocaleString(undefined,{maximumFractionDigits:6})+' ozt';
  document.querySelector('#csGrams').textContent=grams.toLocaleString(undefined,{maximumFractionDigits:4})+' g';
  document.querySelector('#csMelt').textContent=fmt(melt);
  document.querySelector('#csRange').textContent=`${fmt(melt*.95)} / ${fmt(melt*1.05)}`;
 }
}
function silverCalc(){
 const rawWeight=Math.max(0,Number(document.querySelector('#sWeight')?.value||0));
 const unit=document.querySelector('#sUnit')?.value||'ozt';
 const spotv=Math.max(0,Number(document.querySelector('#sSpot')?.value||prices.XAG));
 const under=Math.min(100,Math.max(0,Number(document.querySelector('#sUnder')?.value||0)));
 const over=Number(document.querySelector('#sOver')?.value||0);
 const grams=unit==='g'?rawWeight:rawWeight*31.1034768;
 const oz=unit==='g'?rawWeight/31.1034768:rawWeight;
 const perGram=spotv/31.1034768;
 const melt=oz*spotv;

 const meltEl=document.querySelector('#sMelt');
 if(meltEl){
  meltEl.textContent=fmt(melt);
  document.querySelector('#sBuy').textContent=fmt(melt*(1-under/100));
  document.querySelector('#sSell').textContent=fmt(melt*(1+over/100));
  document.querySelector('#sOztEquivalent').textContent=oz.toLocaleString(undefined,{maximumFractionDigits:6})+' ozt';
  document.querySelector('#sGramEquivalent').textContent=grams.toLocaleString(undefined,{maximumFractionDigits:4})+' g';
  document.querySelector('#sPerGram').textContent=fmt(perGram);
  document.querySelector('#sGramSpot').value=perGram.toFixed(4);
 }
}


function fxConvertAmount(amount,from,to){
 const rates=fxData?.rates||{};
 const fromRate=from==='USD'?1:Number(rates[from]||0);
 const toRate=to==='USD'?1:Number(rates[to]||0);
 if(!fromRate||!toRate)return null;
 return (Number(amount||0)/fromRate)*toRate;
}
async function loadFxRates(force=false){
 if(fxState==='loading')return;
 if(fxData&&!force){fxState='live';drawFxConverter();return}
 fxState='loading';drawFxConverter();
 try{
  const r=await fetch('/api/fx');
  if(r.status===401){fxState='auth';fxData=null;drawFxConverter();return}
  if(!r.ok)throw new Error('FX unavailable');
  const d=await r.json();
  if(!d||!d.rates)throw new Error('Invalid FX response');
  fxData=d;fxState='live';drawFxConverter();
 }catch(e){
  fxState='error';fxData=null;drawFxConverter();
 }
}
function currencyOptions(selected){
 return FX_CURRENCIES.map(c=>`<option value="${c}" ${c===selected?'selected':''}>${c}</option>`).join('');
}
function drawFxConverter(){
 const host=document.querySelector('#fxConverter');
 if(!host)return;
 if(fxState==='loading'){
  host.innerHTML=`<div class="fx-state"><b>LOADING EXCHANGE RATES</b><span>Using the authenticated BDP currency endpoint.</span></div>`;
  return;
 }
 if(fxState==='auth'){
  host.innerHTML=`<div class="fx-state fx-auth"><b>SIGN IN REQUIRED</b><span>Currency rates are available to authenticated BDP accounts.</span><a href="/login">SIGN IN ↗</a></div>`;
  return;
 }
 if(fxState==='error'){
  host.innerHTML=`<div class="fx-state fx-error"><b>EXCHANGE RATES UNAVAILABLE</b><span>No conversion is being estimated or fabricated.</span><button onclick="loadFxRates(true)">RETRY</button></div>`;
  return;
 }
 if(fxState!=='live'||!fxData){
  host.innerHTML=`<button class="gold-btn" onclick="loadFxRates()">LOAD CURRENCY RATES</button>`;
  return;
 }
 host.innerHTML=`<div class="fx-form">
   <div class="field"><label>AMOUNT</label><input id="fxAmount" type="number" min="0" step="any" value="100" oninput="calcFx()"></div>
   <div class="fx-pair">
    <div class="field"><label>FROM</label><select id="fxFrom" onchange="calcFx()">${currencyOptions('USD')}</select></div>
    <button class="fx-swap" onclick="swapFx()" title="Swap currencies">⇄</button>
    <div class="field"><label>TO</label><select id="fxTo" onchange="calcFx()">${currencyOptions('EUR')}</select></div>
   </div>
   <div class="fx-result"><small>CONVERTED VALUE</small><strong id="fxResult">—</strong><span id="fxRateLine">—</span></div>
   <div class="fx-meta"><span>BDP authenticated FX endpoint</span><span>${fxData.timestamp?'Updated '+new Date(fxData.timestamp*1000).toLocaleString():'Rate timestamp unavailable'}</span></div>
  </div>`;
 calcFx();
}
function calcFx(){
 if(!fxData)return;
 const amount=Math.max(0,Number(document.querySelector('#fxAmount')?.value||0));
 const from=document.querySelector('#fxFrom')?.value||'USD';
 const to=document.querySelector('#fxTo')?.value||'EUR';
 const result=fxConvertAmount(amount,from,to);
 const one=fxConvertAmount(1,from,to);
 const resultEl=document.querySelector('#fxResult'),lineEl=document.querySelector('#fxRateLine');
 if(resultEl)resultEl.textContent=result===null?'—':`${Number(result).toLocaleString(undefined,{maximumFractionDigits:6})} ${to}`;
 if(lineEl)lineEl.textContent=one===null?'Rate unavailable':`1 ${from} = ${Number(one).toLocaleString(undefined,{maximumFractionDigits:6})} ${to}`;
}
function swapFx(){
 const from=document.querySelector('#fxFrom'),to=document.querySelector('#fxTo');
 if(!from||!to)return;
 const a=from.value;from.value=to.value;to.value=a;calcFx();
}

function renderCalculators(){
 page.innerHTML=`<section class="hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>CALCULATOR CENTER</h1><p>One workspace for metals, dealer pricing, coin math and unit conversion.</p></section>
 <div class="subnav"><button class="active" onclick="scrollToModule('universalCalc')">UNIVERSAL METAL CALCULATOR</button><button onclick="go('gold')">KARAT GOLD</button><button onclick="go('silver')">SILVER / ROLLS</button><button onclick="go('dealer')">DEALER PRICING</button><button onclick="scrollToModule('fxCard');loadFxRates()">CURRENCY EXCHANGE</button></div>
 <div class="page"><div class="grid two">
  <section class="card" id="universalCalc"><div class="card-head">UNIVERSAL METAL VALUE</div><div class="card-body">
   <div class="form-row"><div class="field"><label>METAL</label><select id="cMetal" onchange="multiCalc();updateCalcBasis()"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option><option value="XCU">Copper</option></select><small id="cBasis" class="input-basis">SPOT BASIS: USD / OZT</small></div><div class="field"><label>WEIGHT</label><input id="cWeight" type="number" value="1" oninput="multiCalc()"></div></div>
   <div class="form-row"><div class="field"><label>UNIT</label><select id="cUnit" onchange="multiCalc()"><option value="ozt">Troy Ounces</option><option value="g">Grams</option></select></div><div class="field"><label>PURITY %</label><input id="cPurity" type="number" value="100" oninput="multiCalc()"></div></div>
   <div class="form-row"><div class="field"><label>BUY % UNDER</label><input id="cUnder" type="number" value="5" oninput="multiCalc()"></div><div class="field"><label>SELL % OVER</label><input id="cOver" type="number" value="5" oninput="multiCalc()"></div></div>
   <div class="calc-result four-result"><div><small>MELT</small><strong id="cMelt">—</strong></div><div><small>BUY</small><strong id="cBuy" class="up">—</strong></div><div><small>SELL</small><strong id="cSell">—</strong></div><div><small>SPREAD</small><strong id="cSpread">—</strong></div></div>
   <button class="gold-btn" onclick="multiCalc()">CALCULATE</button>
  </div></section>
  <section class="card"><div class="card-head">CALCULATOR LIBRARY</div><div class="card-body"><div class="calculator-launchers">
   ${[['Gold Karat','go','gold'],['Scrap Gold','go','gold'],['Constitutional Silver','go','silver'],['Coin Rolls','go','silver'],['Dealer Spread','go','dealer'],['Premium Calculator','go','dealer'],['Copper Pennies','scroll','copperPenniesCard'],['Market Ratios','go','markets']].map(x=>x[1]==='scroll'?`<button onclick="scrollToModule('${x[2]}')">${x[0]}<span>↓</span></button>`:`<button onclick="go('${x[2]}')">${x[0]}<span>→</span></button>`).join('')}
  </div></div></section>
 </div>
 <section class="card" id="copperPenniesCard" style="margin-top:12px"><div class="card-head">PRE-1982 COPPER PENNIES <span class="copper-basis">95% COPPER · 3.11G</span></div><div class="card-body">
  <div class="form-row"><div class="field"><label>PENNY QUANTITY</label><input id="cpQty" type="number" min="0" step="1" value="50" oninput="calcCopperPennies()"></div><div class="field"><label>COPPER PRICE / LB</label><input id="cpSpot" type="number" min="0" step=".0001" value="${prices.XCU.toFixed(4)}" oninput="calcCopperPennies()"></div></div>
  <div class="copper-penny-stats"><div><small>COPPER VALUE / PENNY</small><strong id="cpEach">—</strong></div><div><small>TOTAL COPPER VALUE</small><strong id="cpTotal">—</strong></div><div><small>TOTAL COIN WEIGHT</small><strong id="cpWeight">—</strong></div><div><small>COPPER CONTENT</small><strong id="cpCopperWeight">—</strong></div></div>
  <p class="local-note">Uses the BDP pre-1982 reference: 3.11 g coin weight and 95% copper. This reports copper-content value only and does not add the 5% zinc component.</p>
 </div></section>

 <section class="card" id="fxCard" style="margin-top:12px"><div class="card-head">CURRENCY EXCHANGE <span class="fx-lock-note">ACCOUNT DATA</span></div><div class="card-body"><div id="fxConverter"><button class="gold-btn" onclick="loadFxRates()">LOAD CURRENCY RATES</button></div></div></section>
 </div>`;
 multiCalc();updateCalcBasis();calcCopperPennies();
 if(fxData)drawFxConverter();
}
function updateCalcBasis(){const el=document.querySelector('#cBasis'),m=document.querySelector('#cMetal')?.value;if(el)el.textContent=`SPOT BASIS: ${marketBasis(m)}`}
function multiCalc(){
 const metal=document.querySelector('#cMetal')?.value||'XAU';
 const raw=Math.max(0,Number(document.querySelector('#cWeight')?.value||0));
 const unit=document.querySelector('#cUnit')?.value||'ozt';
 const purity=Math.min(100,Math.max(0,Number(document.querySelector('#cPurity')?.value||100)))/100;
 const under=Math.min(100,Math.max(0,Number(document.querySelector('#cUnder')?.value||0)));
 const over=Number(document.querySelector('#cOver')?.value||0);
 const spotv=prices[metal]||0;
 let melt;
 if(metal==='XCU'){
  const grams=unit==='g'?raw:raw*31.1034768;
  melt=(grams/453.59237)*spotv*purity;
 }else{
  const ozt=unit==='g'?raw/31.1034768:raw;
  melt=ozt*spotv*purity;
 }
 const buy=melt*(1-under/100), sell=melt*(1+over/100);
 const meltEl=document.querySelector('#cMelt'),buyEl=document.querySelector('#cBuy'),sellEl=document.querySelector('#cSell'),spreadEl=document.querySelector('#cSpread');
 if(meltEl){
  meltEl.textContent=fmt(melt); buyEl.textContent=fmt(buy); sellEl.textContent=fmt(sell); spreadEl.textContent=fmt(sell-buy);
 }
}


function calcCopperPennies(){
 const qty=Math.max(0,Number(document.querySelector('#cpQty')?.value||0));
 const copperLb=Math.max(0,Number(document.querySelector('#cpSpot')?.value||prices.XCU||0));
 const each=copperLb*.00220462262*3.11*.95;
 const total=each*qty;
 const totalWeight=3.11*qty;
 const copperWeight=totalWeight*.95;
 const eachEl=document.querySelector('#cpEach');
 if(eachEl){
  eachEl.textContent=fmt(each);
  document.querySelector('#cpTotal').textContent=fmt(total);
  document.querySelector('#cpWeight').textContent=totalWeight.toLocaleString(undefined,{maximumFractionDigits:2})+' g';
  document.querySelector('#cpCopperWeight').textContent=copperWeight.toLocaleString(undefined,{maximumFractionDigits:2})+' g';
 }
}

function renderDealer(){
 const au=prices.XAU,ag=prices.XAG;
 page.innerHTML=`<section class="hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>DEALER TOOLS</h1><p>Quote a deal, check margins, compare benchmarks and jump directly into the working dealer engine.</p></section>
 <div class="subnav"><button class="active" onclick="scrollToModule('dealerDealSheet')">DEAL SHEET</button><button onclick="scrollToModule('dealerTradingCard')">ALL TOOLS</button><button onclick="scrollToModule('dealerPremiumCard')">PREMIUMS</button><button onclick="go('markets')">MARKETS</button></div>
 <div class="page">
  <div class="grid three">
   <section class="card" id="dealerDealSheet"><div class="card-head">QUICK DEAL SHEET</div><div class="card-body">
    <div class="form-row"><div class="field"><label>METAL</label><select id="dMetal" onchange="dealerCalc()"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option></select></div><div class="field"><label>WEIGHT</label><input id="dWeight" type="number" min="0" step="any" value="1" oninput="dealerCalc()"></div></div>
    <div class="form-row"><div class="field"><label>WEIGHT UNIT</label><select id="dUnit" onchange="dealerCalc()"><option value="ozt">Troy Ounces</option><option value="g">Grams</option></select></div><div class="field"><label>PURITY %</label><input id="dPurity" type="number" value="100" oninput="dealerCalc()"></div></div>
    <div class="dealer-weight-conversion"><span><small>TROY OUNCES</small><b id="dOztEquivalent">—</b></span><span><small>GRAMS</small><b id="dGramEquivalent">—</b></span></div>
    <div class="form-row"><div class="field"><label>BUY % UNDER</label><input id="dUnder" type="number" value="5" oninput="dealerCalc()"></div><div class="field"><label>SELL % OVER</label><input id="dOver" type="number" value="5" oninput="dealerCalc()"></div></div>
    <div class="calc-result"><div><small>MELT</small><strong id="dMelt">—</strong></div><div><small>BUY TARGET</small><strong id="dBuy" class="up">—</strong></div><div><small>SELL TARGET</small><strong id="dSell">—</strong></div></div>
    <div class="dealer-profit"><small>PROJECTED GROSS SPREAD</small><strong id="dProfit">—</strong></div>
   </div></section>
   <section class="card"><div class="card-head">GOLD BENCHMARKS</div><div class="card-body">${benchmarkTable('Gold',au)}</div></section>
   <section class="card"><div class="card-head">SILVER BENCHMARKS</div><div class="card-body">${benchmarkTable('Silver',ag)}</div></section>
  </div>
  <div class="grid two dealer-workbench" style="margin-top:12px">
   <section class="card"><div class="card-head">SCRAP BUYER</div><div class="card-body"><p class="module-copy">Use the complete existing scrap-gold workflow while it is migrated into V3.</p><button class="gold-btn" onclick="go('gold')">OPEN NATIVE GOLD / SCRAP CALCULATOR →</button></div></section>
   <section class="card" id="dealerCompareCard"><div class="card-head">COMPARE DEALER QUOTES <span class="manual-badge">MANUAL INPUT</span></div><div class="card-body">
    <p class="module-copy">Enter quotes you already have. BDP compares only the numbers you enter here; these are not scraped or live dealer offers.</p>
    <div class="dealer-compare-mode"><label>TRANSACTION</label><select id="dcMode" onchange="dealerCompare()"><option value="buy">Buying from dealer — lowest quote wins</option><option value="sell">Selling to dealer — highest quote wins</option></select></div>
    <div class="dealer-quote-grid">
     ${[1,2,3].map(i=>`<div class="dealer-quote-row"><input id="dcName${i}" placeholder="Dealer ${i}" value="Dealer ${i}" oninput="dealerCompare()"><input id="dcQuote${i}" type="number" min="0" step=".01" placeholder="Quote $" oninput="dealerCompare()"></div>`).join('')}
    </div>
    <div class="dealer-compare-result"><small>BEST ENTERED QUOTE</small><strong id="dcBest">Enter at least one quote</strong><span id="dcSpread"></span></div>
   </div></section>
   <section class="card" id="dealerPremiumCard"><div class="card-head">PREMIUM ANALYZER</div><div class="card-body">
    <div class="form-row"><div class="field"><label>METAL</label><select id="pmMetal" onchange="premiumCalc()"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option></select></div><div class="field"><label>DEALER PRICE</label><input id="pmPrice" type="number" min="0" step=".01" placeholder="Total quoted price" oninput="premiumCalc()"></div></div>
    <div class="form-row"><div class="field"><label>WEIGHT</label><input id="pmWeight" type="number" min="0" step="any" value="1" oninput="premiumCalc()"></div><div class="field"><label>UNIT</label><select id="pmUnit" onchange="premiumCalc()"><option value="ozt">Troy Ounces</option><option value="g">Grams</option></select></div></div>
    <div class="form-row"><div class="field"><label>PURITY %</label><input id="pmPurity" type="number" min="0" max="100" value="100" oninput="premiumCalc()"></div><div class="field"><label>SPOT BASIS</label><input id="pmSpot" type="text" readonly></div></div>
    <div class="premium-results"><div><small>MELT VALUE</small><strong id="pmMelt">—</strong></div><div><small>PREMIUM $</small><strong id="pmDollars">—</strong></div><div><small>PREMIUM %</small><strong id="pmPercent">—</strong></div><div><small>PRICE / OZT</small><strong id="pmPerOzt">—</strong></div></div>
    <p class="local-note">Premium is calculated from the dealer price you enter versus live/reference BDP spot for the selected metal and fine-metal content.</p>
   </div></section>
   <section class="card" id="dealerTradingCard"><div class="card-head">TRADING / PURCHASE SHEET</div><div class="card-body"><p class="module-copy">Use the native V3 quick deal sheet above for purchase pricing. The legacy trading sheet is being migrated.</p><button class="gold-btn" onclick="scrollToModule('dealerDealSheet')">OPEN DEAL SHEET ↑</button></div></section>
  </div>
 </div>`;
 dealerCalc();premiumCalc();dealerCompare();
}

function premiumMath(price,spot,weight,unit,purityPct){
 const grams=unit==='g'?Number(weight||0):Number(weight||0)*31.1034768;
 const ozt=grams/31.1034768;
 const purity=Math.max(0,Math.min(100,Number(purityPct||0)))/100;
 const fineOzt=ozt*purity;
 const melt=fineOzt*Number(spot||0);
 const premium=Number(price||0)-melt;
 const premiumPct=melt>0?(premium/melt)*100:null;
 const perOzt=ozt>0?Number(price||0)/ozt:null;
 return {grams,ozt,fineOzt,melt,premium,premiumPct,perOzt};
}
function premiumCalc(){
 const metal=document.querySelector('#pmMetal')?.value||'XAU';
 const price=Math.max(0,Number(document.querySelector('#pmPrice')?.value||0));
 const weight=Math.max(0,Number(document.querySelector('#pmWeight')?.value||0));
 const unit=document.querySelector('#pmUnit')?.value||'ozt';
 const purity=Math.max(0,Math.min(100,Number(document.querySelector('#pmPurity')?.value||100)));
 const spot=Number(prices[metal]||0);
 const r=premiumMath(price,spot,weight,unit,purity);
 const basis=document.querySelector('#pmSpot');
 if(basis)basis.value=`${fmt(spot)} / OZT · ${feedState[metal]?.state?.toUpperCase()||'REFERENCE'}`;
 const melt=document.querySelector('#pmMelt');
 if(melt){
  melt.textContent=fmt(r.melt);
  document.querySelector('#pmDollars').textContent=(r.premium>=0?'+':'')+fmt(r.premium);
  document.querySelector('#pmDollars').className=r.premium>=0?'up':'down';
  document.querySelector('#pmPercent').textContent=r.premiumPct===null?'—':`${r.premiumPct>=0?'+':''}${r.premiumPct.toFixed(2)}%`;
  document.querySelector('#pmPercent').className=r.premiumPct===null?'':r.premiumPct>=0?'up':'down';
  document.querySelector('#pmPerOzt').textContent=r.perOzt===null?'—':fmt(r.perOzt);
 }
}
function bestDealerQuote(mode,quotes){
 const valid=quotes.filter(x=>Number.isFinite(Number(x.quote))&&Number(x.quote)>0).map(x=>({...x,quote:Number(x.quote)}));
 if(!valid.length)return {best:null,spread:null,count:0};
 const sorted=[...valid].sort((a,b)=>mode==='sell'?b.quote-a.quote:a.quote-b.quote);
 const best=sorted[0];
 const spread=valid.length>1?Math.max(...valid.map(x=>x.quote))-Math.min(...valid.map(x=>x.quote)):0;
 return {best,spread,count:valid.length};
}
function dealerCompare(){
 const mode=document.querySelector('#dcMode')?.value||'buy';
 const quotes=[1,2,3].map(i=>({
  name:(document.querySelector(`#dcName${i}`)?.value||`Dealer ${i}`).trim()||`Dealer ${i}`,
  quote:Number(document.querySelector(`#dcQuote${i}`)?.value||0)
 }));
 const r=bestDealerQuote(mode,quotes);
 const best=document.querySelector('#dcBest'),spread=document.querySelector('#dcSpread');
 if(!best||!spread)return;
 if(!r.best){
  best.textContent='Enter at least one quote';spread.textContent='';return;
 }
 best.textContent=`${r.best.name}: ${fmt(r.best.quote)}`;
 spread.textContent=r.count>1?`Entered quote range: ${fmt(r.spread)}`:'Add another quote to compare spread.';
}

function benchmarkTable(name,spotv){
 return `<table><thead><tr><th>LEVEL</th><th>QUOTE</th></tr></thead><tbody>
 <tr><td>10% UNDER</td><td>${fmt(spotv*.90)}</td></tr>
 <tr><td>5% UNDER</td><td>${fmt(spotv*.95)}</td></tr>
 <tr><td>SPOT</td><td>${fmt(spotv)}</td></tr>
 <tr><td>5% OVER</td><td>${fmt(spotv*1.05)}</td></tr>
 <tr><td>10% OVER</td><td>${fmt(spotv*1.10)}</td></tr></tbody></table>`;
}
function dealerCalc(){
 const metal=document.querySelector('#dMetal')?.value||'XAU';
 const rawWeight=Math.max(0,Number(document.querySelector('#dWeight')?.value||0));
 const unit=document.querySelector('#dUnit')?.value||'ozt';
 const purity=Math.min(100,Math.max(0,Number(document.querySelector('#dPurity')?.value||100)))/100;
 const under=Math.min(100,Math.max(0,Number(document.querySelector('#dUnder')?.value||0)));
 const over=Number(document.querySelector('#dOver')?.value||0);
 const grams=unit==='g'?rawWeight:rawWeight*31.1034768;
 const oz=unit==='g'?rawWeight/31.1034768:rawWeight;
 const melt=oz*(prices[metal]||0)*purity, buy=melt*(1-under/100), sell=melt*(1+over/100);
 const meltEl=document.querySelector('#dMelt');
 if(meltEl){
  meltEl.textContent=fmt(melt);
  document.querySelector('#dBuy').textContent=fmt(buy);
  document.querySelector('#dSell').textContent=fmt(sell);
  document.querySelector('#dProfit').textContent=fmt(sell-buy);
  document.querySelector('#dOztEquivalent').textContent=oz.toLocaleString(undefined,{maximumFractionDigits:6})+' ozt';
  document.querySelector('#dGramEquivalent').textContent=grams.toLocaleString(undefined,{maximumFractionDigits:4})+' g';
 }
}


const GOLDBACK_DENOMS=[
 {n:.25,label:'¼',oz:1/4000},{n:.5,label:'½',oz:1/2000},{n:1,label:'1',oz:1/1000},
 {n:2,label:'2',oz:1/500},{n:5,label:'5',oz:1/200},{n:10,label:'10',oz:1/100},
 {n:25,label:'25',oz:1/40},{n:50,label:'50',oz:1/20},{n:100,label:'100',oz:1/10}
];

function renderMarkets(){
 const ratio=prices.XAU/prices.XAG;
 const cards=[
  ['GOLD','XAU',prices.XAU,'/img/newlook/mkt-gold.png'],
  ['SILVER','XAG',prices.XAG,'/img/newlook/mkt-silver.png'],
  ['PLATINUM','XPT',prices.XPT,'/img/newlook/mkt-platinum.png'],
  ['PALLADIUM','XPD',prices.XPD,'/img/newlook/mkt-palladium.png'],
  ['COPPER','XCU',prices.XCU,'/img/newlook/mkt-copper.png'],
  ['GOLD / SILVER','RATIO',ratio,'/img/newlook/mkt-ratio.png']
 ];
 page.innerHTML=`<section class="hero markets-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>LIVE MARKETS</h1><p>Precious-metals pricing, ratios and dealer benchmarks in one high-visibility command center.</p></section>
 <div class="subnav"><button class="active">MARKET OVERVIEW</button><button onclick="scrollToModule('marketDealerBoard')">DEALER BOARD</button><button onclick="scrollToModule('marketIntelligence')">INTELLIGENCE</button><button onclick="go('news')">MARKET NEWS</button></div>
 <div class="page">
  <div class="market-command-grid">${cards.map((c,i)=>`<section class="market-command-card" style="--market-art:url('${c[3]}')">
   <small>${c[0]} · ${marketBasis(c[1])}</small><strong>${c[1]==='RATIO'?Number(c[2]).toFixed(2):fmt(c[2])}</strong>
   ${c[1]==='RATIO'?(ratioPct()===null?'<span class="feed-state feed-reference">REFERENCE</span>':`<span class="${ratioPct()>=0?'up':'down'}">${ratioPct()>=0?'+':''}${ratioPct().toFixed(2)}%</span>`):feedChangeMarkup(c[1])}
   <div class="micro-spark">${miniSpark(i)}</div>
  </section>`).join('')}</div>
  <div class="grid two markets-main">
   <section class="card intel-card" id="marketTrend"><div class="card-head">PRECIOUS METALS TREND</div><div class="card-body">
    <img class="card-bg" src="/img/newlook/card-trend.png" alt="">
    <div class="trend-overlay">
     <div class="market-tabs">${[['XAU','GOLD'],['XAG','SILVER'],['XPT','PLATINUM'],['XPD','PALLADIUM']].map((x,i)=>`<button class="${i===0?'active':''}" onclick="selectMarketChart('${x[0]}',this)">${x[1]}</button>`).join('')}</div>
     <div id="marketChartPrice" class="price-big">${fmt(prices.XAU)}</div>
     <div id="marketChart">${sessionMoveSVG('XAU')}</div>
     <div class="market-range"><button class="active">1D</button><button>5D</button><button>1M</button><button>3M</button><button>1Y</button></div>
    </div>
   </div></section>
   <section class="card intel-card" id="marketDealerBoard"><div class="card-head">DEALER MARKET BOARD</div><div class="card-body">
    <img class="card-bg" src="/img/newlook/card-dealerboard.png" alt="">
    <div class="trend-overlay"><table><thead><tr><th>METAL</th><th>10% UNDER</th><th>5% UNDER</th><th>SPOT</th><th>5% OVER</th><th>10% OVER</th></tr></thead><tbody>
     ${[['Gold',prices.XAU],['Silver',prices.XAG],['Platinum',prices.XPT],['Palladium',prices.XPD]].map(x=>`<tr><td>${x[0]}</td><td>${fmt(x[1]*.90)}</td><td>${fmt(x[1]*.95)}</td><td>${fmt(x[1])}</td><td>${fmt(x[1]*1.05)}</td><td>${fmt(x[1]*1.10)}</td></tr>`).join('')}
    </tbody></table>
    <div class="ratio-panel"><small>GOLD / SILVER RATIO</small><strong>${ratio.toFixed(2)}</strong><span>oz silver per oz gold</span></div>
    </div>
   </div></section>
  </div>
  <section class="card intel-card intel-wide" id="marketIntelligence" style="margin-top:12px"><div class="card-head">MARKET INTELLIGENCE</div><div class="card-body">
   <img class="card-bg" src="/img/newlook/card-intel.png" alt="">
   <div class="intel-overlay">
    <div class="intel-metrics">
     <div><small>GOLD / SILVER</small><strong>${ratio.toFixed(2)}</strong><span>${ratioPct()===null?'—':(ratioPct()>=0?'+':'')+ratioPct().toFixed(2)+'%'}</span></div>
     <div><small>GOLD / PLATINUM</small><strong>${(prices.XAU/prices.XPT).toFixed(2)}</strong><span>oz Au per oz Pt</span></div>
     <div><small>PLATINUM / PALLADIUM</small><strong>${(prices.XPT/prices.XPD).toFixed(2)}</strong><span>oz Pt per oz Pd</span></div>
     <div><small>GOLD / COPPER</small><strong>${(prices.XAU/(prices.XCU*16)).toFixed(0)}</strong><span>oz Au per lb Cu</span></div>
    </div>
    <div class="intel-note">Ratios update live with market feed. Use them to judge relative value between metals before pricing a deal.</div>
   </div>
  </div></section>
 </div>`;
}
function miniSpark(i){
 const sets=[[18,26,21,38,34,48,43,59],[48,44,50,41,53,56,63,70],[60,54,50,56,46,42,49,43],[20,28,25,35,42,39,48,53],[35,36,38,41,40,45,47,50],[20,23,25,29,27,31,35,37]];
 const pts=sets[i].map((v,j)=>`${j*16},${70-v}`).join(' ');
 return `<svg viewBox="0 0 112 55" preserveAspectRatio="none"><polyline points="${pts}"/></svg>`;
}
function selectMarketChart(sym,btn){
 document.querySelectorAll('.market-tabs button').forEach(x=>x.classList.remove('active'));
 btn.classList.add('active');
 const priceEl=document.querySelector('#marketChartPrice'),chartEl=document.querySelector('#marketChart');
 if(priceEl)priceEl.textContent=fmt(prices[sym]||0);
 if(chartEl)chartEl.innerHTML=sessionMoveSVG(sym);
}
function ratioRows(){
 const rows=[
  ['Gold / Silver',prices.XAU/prices.XAG],
  ['Gold / Platinum',prices.XAU/prices.XPT],
  ['Platinum / Palladium',prices.XPT/prices.XPD]
 ];
 return `<table><tbody>${rows.map(r=>`<tr><td>${r[0]}</td><td>${r[1].toFixed(2)}</td></tr>`).join('')}</tbody></table>`;
}

const COIN_LIBRARY=[
 {id:'eagle',name:'American Gold Eagle',metal:'Gold',oz:1,img:'gold-coin-eagle.png',note:'1 troy oz nominal bullion reference'},
 {id:'buffalo',name:'American Gold Buffalo',metal:'Gold',oz:1,img:'gold-coin-buffalo.png',note:'1 troy oz .9999 fine gold'},
 {id:'krugerrand',name:'Krugerrand',metal:'Gold',oz:1,img:'gold-coin-krugerrand.png',note:'1 troy oz gold bullion reference'},
 {id:'maple',name:'Gold Maple Leaf',metal:'Gold',oz:1,img:'gold-coin-maple.png',note:'1 troy oz .9999 fine gold'},
 {id:'silver-eagle',name:'American Silver Eagle',metal:'Silver',oz:1,img:'card-silver.png',note:'1 troy oz silver bullion reference'},
 {id:'morgan',name:'Morgan Silver Dollar',metal:'Silver',oz:.77344,img:'coins-hero.png',note:'Common melt reference; collector value varies'},
 {id:'peace',name:'Peace Silver Dollar',metal:'Silver',oz:.77344,img:'coins-hero.png',note:'Common melt reference; collector value varies'},
 {id:'half',name:'90% Silver Half Dollar',metal:'Silver',oz:.36169,img:'card-coins.png',note:'Constitutional silver melt reference'}
];

function renderCoins(){
 page.innerHTML=`<section class="hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>COIN CENTER</h1><p>Bullion coins, constitutional silver and numismatic reference presented as a visual research workspace.</p></section>
 <div class="subnav"><button class="active">COIN OVERVIEW</button><button onclick="scrollToModule('coinReferenceHub')">NUMISMATIC GUIDE</button><button onclick="go('silver')">MELT VALUES</button><button onclick="scrollToModule('coinReferenceHub')">KEY DATES</button><button onclick="scrollToModule('coinGradingHub')">GRADING</button></div>
 <div class="page">
  <section class="coin-search-panel">
   <div><small>COIN SEARCH</small><h2>Find a bullion or melt reference</h2></div>
   <div class="coin-search-controls"><input id="coinSearch" placeholder="Search Eagle, Morgan, Buffalo..." oninput="drawCoinLibrary()"><select id="coinMetal" onchange="drawCoinLibrary()"><option value="all">All metals</option><option value="Gold">Gold</option><option value="Silver">Silver</option></select></div>
  </section>
  <div id="coinLibrary" class="coin-library"></div>
  <div class="grid three" style="margin-top:12px">
   <section class="card"><div class="card-head">MELT VS COLLECTOR VALUE</div><div class="card-body"><p class="module-copy">BDP keeps intrinsic metal value separate from numismatic value. Melt is computed here; collector value should be checked against numismatic references and current market information.</p><button class="gold-btn" onclick="scrollToModule('coinReferenceHub')">OPEN COIN REFERENCE HUB →</button></div></section>
   <section class="card"><div class="card-head">CONSTITUTIONAL SILVER</div><div class="card-body"><table><tbody><tr><td>Dime</td><td>${fmt(prices.XAG*.07234)}</td></tr><tr><td>Quarter</td><td>${fmt(prices.XAG*.18084)}</td></tr><tr><td>Half</td><td>${fmt(prices.XAG*.36169)}</td></tr><tr><td>Silver Dollar</td><td>${fmt(prices.XAG*.77344)}</td></tr></tbody></table></div></section>
   <section class="card"><div class="card-head">COIN TOOLS</div><div class="card-body"><div class="tool-grid">${[
 ['i-calc','Coin Melt','go','silver'],
 ['i-book','Key Dates','scroll','coinReferenceHub'],
 ['i-star','Grading','scroll','coinGradingHub'],
 ['i-tools','Dealer Spread','go','dealer'],
 ['i-coins','Roll Values','go','silver'],
 ['i-chart','Metal Markets','go','markets']
].map(t=>t[2]==='scroll'?`<button class="tool tool-button" onclick="scrollToModule('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`:`<button class="tool tool-button" onclick="go('${t[3]}')">${icon(t[0])}<span>${t[1]}</span></button>`).join('')}</div></div></section>
  </div>
  <div class="grid two" style="margin-top:12px">
   <section class="card" id="coinGradingHub"><div class="card-head">GRADING & ATTRIBUTION SOURCES</div><div class="card-body"><div class="coin-source-grid">
    <a href="https://www.pcgs.com/photograde" target="_blank" rel="noopener"><small>PCGS</small><b>Photograde</b><span>Visual grading reference ↗</span></a>
    <a href="https://www.ngccoin.com/resources/grading-standards/" target="_blank" rel="noopener"><small>NGC</small><b>Grading Standards</b><span>Official grading reference ↗</span></a>
    <a href="https://www.pcgs.com/coinfacts" target="_blank" rel="noopener"><small>PCGS</small><b>CoinFacts</b><span>Coin and variety reference ↗</span></a>
    <a href="https://en.numista.com" target="_blank" rel="noopener"><small>NUMISTA</small><b>Catalog</b><span>World coin catalog ↗</span></a>
   </div></div></section>
   <section class="card" id="coinReferenceHub"><div class="card-head">BDP NUMISMATIC DATABASE</div><div class="card-body"><p class="module-copy">The existing BDP database contains deeper key-date, series, grading, error, specification, and coin-value tables. V3 keeps one controlled fallback to that database while the larger reference library is migrated.</p><button class="gold-btn" onclick="go('resources')">OPEN BDP RESOURCE CENTER ↗</button></div></section>
  </div>
 </div>`;
 drawCoinLibrary();
}
function drawCoinLibrary(){
 const q=(document.querySelector('#coinSearch')?.value||'').toLowerCase();
 const metal=document.querySelector('#coinMetal')?.value||'all';
 const data=COIN_LIBRARY.filter(c=>(metal==='all'||c.metal===metal)&&(!q||c.name.toLowerCase().includes(q)));
 const host=document.querySelector('#coinLibrary');
 if(!host)return;
 host.innerHTML=data.map(c=>{
  const spotv=c.metal==='Gold'?prices.XAU:prices.XAG;
  const melt=spotv*c.oz;
  return `<article class="coin-card"><div class="coin-art"><img src="/img/newlook/${c.img}" alt="${c.name}"></div><div class="coin-copy"><small>${c.metal.toUpperCase()} · ${c.oz.toFixed(5).replace(/0+$/,'').replace(/\.$/,'')} OZT</small><h3>${c.name}</h3><p>${c.note}</p><div class="coin-value"><span>INTRINSIC METAL VALUE</span><strong>${fmt(melt)}</strong></div><button onclick="${c.metal==='Gold'?"go('gold')":"scrollToModule('coinReferenceHub')"}">${c.metal==='Gold'?'OPEN GOLD CENTER →':'OPEN COIN REFERENCES →'}</button></div></article>`;
 }).join('') || `<div class="empty-state">No matching coin reference.</div>`;
}


let selectedGoldbackState=localStorage.getItem('bdp-v3-goldback-state')||'Utah';
function selectGoldbackState(state){
 selectedGoldbackState=state;
 localStorage.setItem('bdp-v3-goldback-state',state);
 document.querySelectorAll('.state-grid button[data-gb-state]').forEach(btn=>btn.classList.toggle('active',btn.dataset.gbState===state));
 const label=document.querySelector('#gbSelectedState');
 if(label)label.textContent=state.toUpperCase();
}

function renderGoldbacks(){
 const official=Number(localStorage.getItem('bdp-v3-goldback-rate')||0);
 const mult=Number(localStorage.getItem('bdp-v3-goldback-mult')||1.94);
 const intrinsic=prices.XAU/1000;
 const apiOne=goldbackApi?.rates?.find(r=>String(r.label||'').startsWith('1 Goldback'));
 const estimate=Number(apiOne?.marketValue||apiOne?.rate||intrinsic*mult);
 const working=official>0?official:estimate;
 page.innerHTML=`<section class="hero goldback-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>GOLDBACK CENTER</h1><p>Separate intrinsic 24K gold content from the working exchange value, then quote denominations and transactions clearly.</p></section>
 <div class="subnav"><button class="active" onclick="scrollToModule('goldbackRatePanel')">RATE & VALUES</button><button onclick="scrollToModule('goldbackDenoms')">DENOMINATIONS</button><button onclick="scrollToModule('goldbackRetailerCard')">RETAILERS</button><a class="subnav-link" href="https://goldback.com/exchange-rates/" target="_blank" rel="noopener">VERIFY OFFICIAL RATE ↗</a></div>
 <div class="page">
  <section class="gb-rate-hero" id="goldbackRatePanel">
   <div class="gb-rate-copy"><small>GOLDBACK WORKING RATE</small><h2 id="gbWorking">${fmt(working)} <em>/ 1 GB</em></h2><p id="gbSource">${official>0?'User-entered official daily rate':goldbackApi?'Server-calculated BDP estimate — not the official daily exchange rate':'BDP modeled estimate — not the official daily exchange rate'}</p></div>
   <div class="gb-rate-inputs">
    <label>OFFICIAL 1 GOLDBACK RATE<input id="gbOfficial" type="number" min="0" step=".01" value="${official||''}" placeholder="Enter daily rate" oninput="saveGbRate()"></label>
    <label>BDP ESTIMATE MULTIPLIER<input id="gbMult" type="number" min="1" step=".01" value="${mult.toFixed(2)}" oninput="saveGbRate()"></label>
   </div>
   <div class="gb-rate-stats"><div><small>GOLD SPOT</small><strong>${fmt(prices.XAU)}</strong></div><div><small>1 GB INTRINSIC</small><strong>${fmt(intrinsic)}</strong></div><div><small>BDP ESTIMATE</small><strong>${fmt(estimate)}</strong></div></div>
  </section>
  <section id="goldbackDenoms"><div class="section-line"><span>DENOMINATIONS</span><small>WORKING RATE VS INTRINSIC GOLD</small></div><div id="gbDenoms" class="gb-denom-grid"></div></section>
  <div class="grid two" style="margin-top:12px">
   <section class="card"><div class="card-head">TRANSACTION CONVERTER</div><div class="card-body">
    <div class="form-row"><div class="field"><label>PURCHASE TOTAL (USD)</label><input id="gbUsd" type="number" value="25" min="0" step=".01" oninput="calcGbTxn()"></div><div class="field"><label>GOLDBACKS TENDERED</label><input id="gbTendered" type="number" value="0" min="0" step=".25" oninput="calcGbTxn()"></div></div>
    <div class="calc-result"><div><small>GOLDBACKS DUE</small><strong id="gbDue">—</strong></div><div><small>TENDER VALUE</small><strong id="gbTenderValue">—</strong></div><div><small>REMAINING / CHANGE</small><strong id="gbBalance">—</strong></div></div>
   </div></section>
   <section class="card"><div class="card-head">STATE / SERIES WORKSPACE <span class="gb-selected-state" id="gbSelectedState">${selectedGoldbackState.toUpperCase()}</span></div><div class="card-body"><div class="state-grid">${['Utah','Nevada','Wyoming','New Hampshire','South Dakota','Florida','Arizona','Oklahoma'].map(s=>`<button data-gb-state="${s}" class="${selectedGoldbackState===s?'active':''}" onclick="selectGoldbackState('${s}')"><span>${s.slice(0,2).toUpperCase()}</span><b>${s}</b><small>${selectedGoldbackState===s?'SELECTED':'SELECT SERIES'}</small></button>`).join('')}</div></div></section>
  </div>
  <div class="grid two" style="margin-top:12px">
   <section class="card"><div class="card-head">EXCHANGE VALUE VS MELT</div><div class="card-body"><p class="module-copy">Goldbacks contain defined fractions of a troy ounce of 24K gold. The intrinsic melt value follows gold spot; the exchange or retail value is a separate number. V3 keeps those values visibly separate.</p><button class="gold-btn" onclick="go('resources')">OPEN BDP RESOURCE CENTER →</button></div></section>
   <section class="card" id="goldbackRetailerCard"><div class="card-head">RETAILER / DEALER LINKS</div><div class="card-body"><div class="goldback-art"><img src="/img/newlook/card-goldbacks.png" alt="Goldbacks"><div><b>GOLDBACK DEALER WORKSPACE</b><p>Open the existing retailer and dealer-link tools while they are migrated into V3.</p><div class="gb-link-row"><button onclick="go('resources')">OPEN RETAILERS ↗</button><a href="https://goldback.com/exchange-rates/" target="_blank" rel="noopener">OFFICIAL RATES ↗</a></div></div></div></div></section>
  </div>
 </div>`;
 drawGbDenoms();
 calcGbTxn();
}
function getGbModel(){
 const official=Math.max(0,Number(document.querySelector('#gbOfficial')?.value||localStorage.getItem('bdp-v3-goldback-rate')||0));
 const mult=Math.max(1,Number(document.querySelector('#gbMult')?.value||localStorage.getItem('bdp-v3-goldback-mult')||1.94));
 const intrinsic=prices.XAU/1000;
 const apiOne=goldbackApi?.rates?.find(r=>String(r.label||'').startsWith('1 Goldback'));
 const estimate=Number(apiOne?.marketValue||apiOne?.rate||intrinsic*mult);
 return {official,mult,intrinsic,estimate,working:official>0?official:estimate};
}
function saveGbRate(){
 const m=getGbModel();
 if(m.official>0)localStorage.setItem('bdp-v3-goldback-rate',m.official.toFixed(2)); else localStorage.removeItem('bdp-v3-goldback-rate');
 localStorage.setItem('bdp-v3-goldback-mult',m.mult.toFixed(2));
 const workingEl=document.querySelector('#gbWorking'),sourceEl=document.querySelector('#gbSource');
 if(workingEl)workingEl.innerHTML=`${fmt(m.working)} <em>/ 1 GB</em>`;
 if(sourceEl)sourceEl.textContent=m.official>0?'User-entered official daily rate':goldbackApi?'Server-calculated BDP estimate — not the official daily exchange rate':'BDP modeled estimate — not the official daily exchange rate';
 drawGbDenoms();calcGbTxn();
}
function drawGbDenoms(){
 const host=document.querySelector('#gbDenoms');
 if(!host)return;
 const m=getGbModel();
 host.innerHTML=GOLDBACK_DENOMS.map(d=>`<article class="gb-denom-card"><div class="gb-note-art"><img src="/img/newlook/card-goldbacks.png" alt="${d.label} Goldback"></div><small>${d.oz.toFixed(5)} OZT 24K</small><h3>${d.label} GOLDBACK</h3><strong>${fmt(m.working*d.n)}</strong><span>intrinsic ${fmt(prices.XAU*d.oz)}</span></article>`).join('');
}
function calcGbTxn(){
 const dueEl=document.querySelector('#gbDue'),tenderEl=document.querySelector('#gbTenderValue'),balanceEl=document.querySelector('#gbBalance');
 if(!dueEl||!tenderEl||!balanceEl)return;
 const m=getGbModel();
 const usd=Math.max(0,Number(document.querySelector('#gbUsd')?.value||0));
 const tendered=Math.max(0,Number(document.querySelector('#gbTendered')?.value||0));
 const due=m.working>0?usd/m.working:0, tenderVal=tendered*m.working, diff=usd-tenderVal;
 dueEl.textContent=due.toFixed(2)+' GB';
 tenderEl.textContent=fmt(tenderVal);
 balanceEl.textContent=diff>0?fmt(diff)+' due':diff<0?fmt(Math.abs(diff))+' change':'PAID';
 balanceEl.className=diff>0?'down':diff<0?'up':'up';
}


const INV_KEY='bdp-v3-inventory';
const ALERT_KEY='bdp-v3-alerts';
let currentUser=null;
let cloudSync=null;
let syncMode='local';
let liveNewsItems=[];
let goldbackApi=null;
let fxData=null;
let fxState='idle';
const FX_CURRENCIES=['USD','EUR','GBP','CAD','AUD','JPY','CHF','CNY','MXN'];

function syncSlotForKey(key){return key===INV_KEY?'inventory':key===ALERT_KEY?'alerts':null}
function localLoad(key,fallback=[]){
 try{const raw=localStorage.getItem(key);return raw?JSON.parse(raw):fallback}catch(e){return fallback}
}
function loadJson(key,fallback=[]){
 const slot=syncSlotForKey(key);
 if(slot&&cloudSync&&Array.isArray(cloudSync[slot])) return cloudSync[slot];
 return localLoad(key,fallback);
}
function saveJson(key,value){
 localStorage.setItem(key,JSON.stringify(value));
 const slot=syncSlotForKey(key);
 if(slot&&cloudSync){
  cloudSync[slot]=value;
  persistCloudSync().catch(()=>{syncMode='cloud-error';updateSyncBadges()});
 }
}
async function persistCloudSync(){
 if(!cloudSync||!currentUser)return;
 const r=await fetch('/api/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cloudSync)});
 if(!r.ok)throw new Error('cloud sync write failed');
 syncMode='cloud';updateSyncBadges();
}
async function hydrateUserSync(){
 try{
  const me=await fetch('/api/me');
  if(!me.ok){syncMode='local';updateSyncBadges();return}
  currentUser=await me.json();
  const s=await fetch('/api/sync');
  if(!s.ok)throw new Error('sync unavailable');
  cloudSync=await s.json();
  cloudSync.inventory=Array.isArray(cloudSync.inventory)?cloudSync.inventory:[];
  cloudSync.alerts=Array.isArray(cloudSync.alerts)?cloudSync.alerts:[];
  cloudSync.slabs=Array.isArray(cloudSync.slabs)?cloudSync.slabs:[];
  cloudSync.typesets=cloudSync.typesets||{};
  cloudSync.presets=cloudSync.presets||{};
  syncMode='cloud';
  updateSyncBadges();
  const current=location.hash.replace('#','')||'dashboard';
  if(['dashboard','inventory','alerts','account'].includes(current))render();
 }catch(e){
  syncMode=currentUser?'cloud-error':'local';
  updateSyncBadges();
 }
}
function syncBadge(){
 const label=syncMode==='cloud'?'CLOUD SYNC':syncMode==='cloud-error'?'SYNC RETRY':'LOCAL MODE';
 const cls=syncMode==='cloud'?'sync-cloud':syncMode==='cloud-error'?'sync-error':'sync-local';
 return `<span class="sync-badge ${cls}">${label}</span>`;
}
function updateSyncBadges(){
 document.querySelectorAll('[data-sync-badge]').forEach(el=>el.innerHTML=syncBadge());
}
function metalSpot(sym){return sym==='RATIO'?(Number(prices.XAU||0)/Number(prices.XAG||1)):Number(prices[sym]||0)}
function inventoryValue(item){
 const oz=Math.max(0,Number(item.qty||0))*Math.max(0,Number(item.weight||0));
 const purity=Math.max(0,Math.min(100,Number(item.purity||100)))/100;
 return oz*metalSpot(item.metal)*purity;
}
function inventorySummary(){
 const inv=loadJson(INV_KEY,[]);
 return inv.reduce((a,x)=>{
  const current=inventoryValue(x),cost=Math.max(0,Number(x.cost||0));
  a.cost+=cost;a.current+=current;a.count+=1;return a;
 },{cost:0,current:0,count:0});
}
function inventoryByMetal(){
 const inv=loadJson(INV_KEY,[]);
 const groups={};
 inv.forEach(x=>{
  const name=metalName(x.metal);
  if(!groups[name])groups[name]={count:0,cost:0,current:0};
  groups[name].count+=1;
  groups[name].cost+=Math.max(0,Number(x.cost||0));
  groups[name].current+=inventoryValue(x);
 });
 return groups;
}
function csvCell(v){
 const s=String(v??'');
 return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s;
}
function exportInventoryCsv(){
 const inv=loadJson(INV_KEY,[]);
 if(!inv.length)return;
 const rows=[['Item','Metal','Quantity','Ozt Each','Purity %','Cost Basis','Live Value','P/L']];
 inv.forEach(x=>{
  const live=inventoryValue(x),cost=Math.max(0,Number(x.cost||0));
  rows.push([x.name||'Unnamed',metalName(x.metal),x.qty,x.weight,x.purity,cost.toFixed(2),live.toFixed(2),(live-cost).toFixed(2)]);
 });
 const csv=rows.map(r=>r.map(csvCell).join(',')).join('\n');
 const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');
 a.href=url;
 a.download=`BDP-Inventory-${new Date().toISOString().slice(0,10)}.csv`;
 document.body.appendChild(a);
 a.click();
 a.remove();
 URL.revokeObjectURL(url);
}

function activeAlertSummary(){
 const alerts=loadJson(ALERT_KEY,[]);
 let triggered=0;alerts.forEach(a=>{if(alertTriggered(a))triggered++});
 return {count:alerts.length,triggered};
}
function alertValueFmt(metal,value){
 return metal==='RATIO'?Number(value||0).toFixed(2):fmt(value);
}
function alertTriggered(a){
 const current=metalSpot(a.metal),target=Number(a.target||0);
 return a.direction==='above'?current>=target:current<=target;
}

function renderDashboard(){
 const inv=inventorySummary(),al=activeAlertSummary(),pnl=inv.current-inv.cost,ratio=prices.XAU/prices.XAG;
 page.innerHTML=`<section class="hero dashboard-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>DASHBOARD</h1><p>Your precious-metals command center — live pricing, quick actions, dealer benchmarks, alerts and portfolio value.</p></section>
 <div class="page">
  <div class="dashboard-kpis">
   ${[['GOLD',fmt(prices.XAU),'up'],['SILVER',fmt(prices.XAG),'up'],['G/S RATIO',ratio.toFixed(2),'up'],['PORTFOLIO',fmt(inv.current),pnl>=0?'up':'down'],['ALERTS',String(al.triggered)+' / '+String(al.count),al.triggered?'down':'up']].map(x=>`<article><small>${x[0]}</small><strong>${x[1]}</strong><span class="${x[2]}">${x[0]==='PORTFOLIO'?(pnl>=0?'+':'')+fmt(pnl).replace('$','')+' P/L':x[0]==='ALERTS'?'triggered / total':x[0]==='G/S RATIO'?(ratioPct()===null?'REFERENCE':'LIVE'):(x[0]==='GOLD'?(feedState.XAU.state.toUpperCase()):x[0]==='SILVER'?feedState.XAG.state.toUpperCase():'LIVE')}</span></article>`).join('')}
  </div>
  <div class="grid three">
   <section class="card"><div class="card-head">MARKET SNAPSHOT</div><div class="card-body">${chartSVG()}<div class="statbar"><div><small>GOLD</small><strong>${fmt(prices.XAU)}</strong></div><div><small>SILVER</small><strong>${fmt(prices.XAG)}</strong></div><div><small>PLATINUM</small><strong>${fmt(prices.XPT)}</strong></div><div><small>PALLADIUM</small><strong>${fmt(prices.XPD)}</strong></div></div><button class="module-open" onclick="go('markets')">OPEN LIVE MARKETS ↗</button></div></section>
   <section class="card"><div class="card-head">QUICK ACTIONS</div><div class="card-body"><div class="dash-actions">${[['i-bars','Price Gold Deal','gold'],['i-coins','Price Silver Deal','silver'],['i-calc','Calculator Center','calculators'],['i-note','Goldbacks','goldbacks'],['i-tools','Dealer Tools','dealer'],['i-box','Inventory','inventory']].map(x=>`<button onclick="go('${x[2]}')">${icon(x[0])}<span>${x[1]}</span></button>`).join('')}</div></div></section>
   <section class="card"><div class="card-head">DEALER OPPORTUNITY</div><div class="card-body"><table><thead><tr><th>METAL</th><th>5% UNDER</th><th>SPOT</th><th>5% OVER</th></tr></thead><tbody><tr><td>Gold</td><td>${fmt(prices.XAU*.95)}</td><td>${fmt(prices.XAU)}</td><td>${fmt(prices.XAU*1.05)}</td></tr><tr><td>Silver</td><td>${fmt(prices.XAG*.95)}</td><td>${fmt(prices.XAG)}</td><td>${fmt(prices.XAG*1.05)}</td></tr></tbody></table><button class="module-open" onclick="go('dealer')">OPEN DEALER TOOLS ↗</button></div></section>
  </div>
  <div class="grid three" style="margin-top:12px">
   <section class="card"><div class="card-head">PORTFOLIO / INVENTORY</div><div class="card-body"><div class="portfolio-big"><small>CURRENT METAL VALUE</small><strong>${fmt(inv.current)}</strong><span class="${pnl>=0?'up':'down'}">${pnl>=0?'+':''}${fmt(pnl)} vs cost basis</span></div><div class="statbar"><div><small>ITEMS</small><strong>${inv.count}</strong></div><div><small>COST</small><strong>${fmt(inv.cost)}</strong></div><div><small>VALUE</small><strong>${fmt(inv.current)}</strong></div><div><small>P/L</small><strong class="${pnl>=0?'up':'down'}">${fmt(pnl)}</strong></div></div><button class="module-open" onclick="go('inventory')">MANAGE INVENTORY ↗</button></div></section>
   <section class="card"><div class="card-head">PRICE ALERTS</div><div class="card-body"><div class="alert-summary-ring"><strong>${al.triggered}</strong><span>TRIGGERED</span></div><p class="module-copy">${al.count?`${al.count} local alert${al.count===1?'':'s'} configured.`:'No alerts configured yet.'}</p><button class="module-open" onclick="go('alerts')">MANAGE ALERTS ↗</button></div></section>
   <section class="card"><div class="card-head">BDP PRO</div><div class="card-body"><div class="pro-dashboard-card"><small>PREMIUM TOOLKIT</small><strong>BDP PRO</strong><span>See current plans and pricing</span><p>Inventory, alerts, saved workflow and advanced dealer features.</p><button onclick="go('account')">VIEW PRO OPTIONS ↗</button></div></div></section>
  </div>
 </div>`;
}

function renderInventory(){
 const inv=loadJson(INV_KEY,[]),sum=inventorySummary(),pnl=sum.current-sum.cost;
 page.innerHTML=`<section class="hero inventory-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>INVENTORY</h1><p>Track metal holdings, cost basis and current melt value using live BDP prices.</p></section>
 <div class="subnav"><button class="active" onclick="scrollToModule('inventoryHoldings')">HOLDINGS</button><button onclick="scrollToModule('inventoryAdd')">ADD ITEM</button><button onclick="exportInventoryCsv()">EXPORT CSV</button><button onclick="go('account')">ACCOUNT TOOLS</button><div class="subnav-status" data-sync-badge>${syncBadge()}</div></div>
 <div class="page">
  <div class="inventory-summary">${[['ITEMS',sum.count],['COST BASIS',fmt(sum.cost)],['CURRENT VALUE',fmt(sum.current)],['UNREALIZED P/L',fmt(pnl)]].map((x,i)=>`<article><small>${x[0]}</small><strong class="${i===3?(pnl>=0?'up':'down'):''}">${x[1]}</strong></article>`).join('')}</div>
  <div class="inventory-allocation">${Object.entries(inventoryByMetal()).length?Object.entries(inventoryByMetal()).map(([metal,g])=>`<article><small>${metal.toUpperCase()}</small><strong>${fmt(g.current)}</strong><span>${g.count} item${g.count===1?'':'s'} · ${sum.current?((g.current/sum.current)*100).toFixed(1):'0.0'}%</span></article>`).join(''):`<article class="allocation-empty"><small>PORTFOLIO ALLOCATION</small><span>Add holdings to see allocation by metal.</span></article>`}</div>
  <div class="grid two">
   <section class="card" id="inventoryAdd"><div class="card-head">ADD INVENTORY ITEM</div><div class="card-body">
    <div class="form-row"><div class="field"><label>ITEM NAME</label><input id="invName" placeholder="1 oz Gold Eagle"></div><div class="field"><label>METAL</label><select id="invMetal"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option></select></div></div>
    <div class="form-row"><div class="field"><label>QUANTITY</label><input id="invQty" type="number" min="0" step="1" value="1"></div><div class="field"><label>OZT EACH</label><input id="invWeight" type="number" min="0" step=".00001" value="1"></div></div>
    <div class="form-row"><div class="field"><label>PURITY %</label><input id="invPurity" type="number" min="0" max="100" value="100"></div><div class="field"><label>TOTAL COST BASIS</label><input id="invCost" type="number" min="0" step=".01" placeholder="0.00"></div></div>
    <button class="gold-btn" onclick="addInventory()">ADD TO INVENTORY</button>
    <p class="local-note">Signed-in accounts use BDP cloud sync. Signed-out use is stored locally in this browser.</p>
   </div></section>
   <section class="card"><div class="card-head">PORTFOLIO VALUE</div><div class="card-body">${chartSVG()}<div class="portfolio-big"><small>LIVE METAL VALUE</small><strong>${fmt(sum.current)}</strong><span class="${pnl>=0?'up':'down'}">${pnl>=0?'+':''}${fmt(pnl)} vs cost</span></div></div></section>
  </div>
  <section class="card" id="inventoryHoldings" style="margin-top:12px"><div class="card-head">HOLDINGS</div><div class="card-body"><div class="inventory-table-wrap">${inv.length?`<table><thead><tr><th>ITEM</th><th>METAL</th><th>QTY</th><th>OZT EACH</th><th>PURITY</th><th>COST</th><th>LIVE VALUE</th><th>P/L</th><th></th></tr></thead><tbody>${inv.map((x,i)=>{const v=inventoryValue(x),pl=v-Number(x.cost||0);return `<tr><td>${escapeHtml(x.name||'Unnamed')}</td><td>${metalName(x.metal)}</td><td>${x.qty}</td><td>${Number(x.weight).toFixed(5)}</td><td>${Number(x.purity).toFixed(2)}%</td><td>${fmt(x.cost)}</td><td>${fmt(v)}</td><td class="${pl>=0?'up':'down'}">${fmt(pl)}</td><td><button class="row-delete" onclick="removeInventory(${i})">×</button></td></tr>`}).join('')}</tbody></table>`:`<div class="empty-state">No inventory yet. Add your first holding above. CSV export becomes available when holdings exist.</div>`}</div></div></section>
 </div>`;
}
function addInventory(){
 const nameEl=document.querySelector('#invName'),metalEl=document.querySelector('#invMetal'),qtyEl=document.querySelector('#invQty'),weightEl=document.querySelector('#invWeight'),purityEl=document.querySelector('#invPurity'),costEl=document.querySelector('#invCost');
 if(!nameEl||!metalEl||!qtyEl||!weightEl||!purityEl||!costEl)return;
 const item={name:(nameEl.value||'').trim()||'Unnamed item',metal:metalEl.value,qty:Math.max(0,Number(qtyEl.value||0)),weight:Math.max(0,Number(weightEl.value||0)),purity:Math.max(0,Math.min(100,Number(purityEl.value||100))),cost:Math.max(0,Number(costEl.value||0))};
 const inv=loadJson(INV_KEY,[]);inv.push(item);saveJson(INV_KEY,inv);renderInventory();
}
function removeInventory(i){const inv=loadJson(INV_KEY,[]);inv.splice(i,1);saveJson(INV_KEY,inv);renderInventory()}
function metalName(sym){return {XAU:'Gold',XAG:'Silver',XPT:'Platinum',XPD:'Palladium',XCU:'Copper',RATIO:'Gold/Silver Ratio'}[sym]||sym}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]))}

function renderAlerts(){
 const alerts=loadJson(ALERT_KEY,[]);
 page.innerHTML=`<section class="hero alerts-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>PRICE ALERTS</h1><p>Create simple local price triggers and see exactly how far the market is from your target.</p></section>
 <div class="page"><div class="sync-row"><span>ALERT STORAGE</span><span data-sync-badge>${syncBadge()}</span></div><div class="grid two">
  <section class="card"><div class="card-head">CREATE ALERT</div><div class="card-body">
   <div class="form-row"><div class="field"><label>METAL</label><select id="aMetal" onchange="syncAlertTarget()"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option><option value="RATIO">Gold / Silver Ratio</option></select></div><div class="field"><label>TRIGGER</label><select id="aDirection"><option value="above">Price rises above</option><option value="below">Price falls below</option></select></div></div>
   <div class="field"><label id="aTargetLabel">TARGET PRICE</label><input id="aTarget" type="number" step=".01" value="${prices.XAU.toFixed(2)}"></div>
   <div class="alert-presets"><small>QUICK TARGETS FROM CURRENT PRICE</small><div><button onclick="applyAlertPreset(-10)">−10%</button><button onclick="applyAlertPreset(-5)">−5%</button><button onclick="applyAlertPreset(5)">+5%</button><button onclick="applyAlertPreset(10)">+10%</button></div></div>
   <div id="alertFormMsg" class="alert-form-msg"></div>
   <button class="gold-btn" onclick="addAlert()">SAVE ALERT</button>
   <p class="local-note">Signed-in alert definitions sync to BDP cloud storage. Trigger evaluation is shown in-app; push/email delivery is not claimed here.</p>
  </div></section>
  <section class="card"><div class="card-head">ALERT OVERVIEW</div><div class="card-body"><div class="alert-kpis"><div><small>TOTAL</small><strong>${alerts.length}</strong></div><div><small>TRIGGERED</small><strong class="${alerts.some(alertTriggered)?'down':'up'}">${alerts.filter(alertTriggered).length}</strong></div><div><small>WATCHING</small><strong>${alerts.filter(a=>!alertTriggered(a)).length}</strong></div></div>${chartSVG()}</div></section>
 </div>
 <section class="card" style="margin-top:12px"><div class="card-head">ACTIVE ALERTS</div><div class="card-body">${alerts.length?`<div class="alerts-grid">${alerts.map((a,i)=>alertCard(a,i)).join('')}</div>`:`<div class="empty-state">No alerts configured yet.</div>`}</div></section>
 </div>`;
}
function syncAlertTarget(){
 const metalEl=document.querySelector('#aMetal'),targetEl=document.querySelector('#aTarget');
 if(!metalEl||!targetEl)return;
 const metal=metalEl.value;
 const spot=metalSpot(metal)||0;
 targetEl.value=spot.toFixed(2);
 const label=document.querySelector('#aTargetLabel');
 if(label)label.textContent=metal==='RATIO'?'TARGET RATIO':'TARGET PRICE';
 const msg=document.querySelector('#alertFormMsg');
 if(msg){msg.textContent='';msg.classList.remove('error')}
}
function applyAlertPreset(pct){
 const spot=metalSpot(document.querySelector('#aMetal')?.value||'XAU');
 const target=spot*(1+Number(pct||0)/100);
 const dir=document.querySelector('#aDirection');
 const targetEl=document.querySelector('#aTarget');
 if(dir)dir.value=pct>=0?'above':'below';
 if(targetEl)targetEl.value=target.toFixed(2);
 const msg=document.querySelector('#alertFormMsg');
 if(msg){msg.classList.remove('error');msg.textContent=`Target set ${pct>=0?'+':''}${pct}% from current ${alertValueFmt(document.querySelector('#aMetal')?.value||'XAU',spot)}.`}
}
function addAlert(){
 const metalEl=document.querySelector('#aMetal'),directionEl=document.querySelector('#aDirection'),targetEl=document.querySelector('#aTarget');
 if(!metalEl||!directionEl||!targetEl)return;
 const alert={metal:metalEl.value,direction:directionEl.value,target:Math.max(0,Number(targetEl.value||0)),created:Date.now()};
 const alerts=loadJson(ALERT_KEY,[]);
 const duplicate=alerts.some(x=>x.metal===alert.metal&&x.direction===alert.direction&&Math.abs(Number(x.target)-alert.target)<.005);
 if(duplicate){
  const msg=document.querySelector('#alertFormMsg');
  if(msg){msg.textContent='That alert already exists.';msg.classList.add('error')}
  return;
 }
 alerts.push(alert);
 saveJson(ALERT_KEY,alerts);
 renderAlerts();
}
function removeAlert(i){const alerts=loadJson(ALERT_KEY,[]);alerts.splice(i,1);saveJson(ALERT_KEY,alerts);renderAlerts()}
function alertCard(a,i){
 const current=metalSpot(a.metal),target=Number(a.target||0),hit=alertTriggered(a),distance=target?Math.abs((current-target)/target*100):0;
 return `<article class="alert-card ${hit?'triggered':''}"><div><small>${metalName(a.metal).toUpperCase()}</small><h3>${a.direction==='above'?'ABOVE':'BELOW'} ${alertValueFmt(a.metal,target)}</h3><p>Current ${alertValueFmt(a.metal,current)} · ${distance.toFixed(2)}% from target</p></div><div class="alert-state"><strong class="${hit?'down':'up'}">${hit?'TRIGGERED':'WATCHING'}</strong><button onclick="removeAlert(${i})">×</button></div></article>`;
}

function renderAccount(){
 const inv=inventorySummary(),alerts=activeAlertSummary();
 page.innerHTML=`<section class="hero account-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>ACCOUNT</h1><p>Profile, preferences and BDP Pro access in the same premium workspace.</p></section>
 <div class="page">
  <div class="grid three">
   <section class="card"><div class="card-head">PROFILE <span data-sync-badge>${syncBadge()}</span></div><div class="card-body">${currentUser?`<div class="profile-live"><small>SIGNED IN</small><strong>${escapeHtml(currentUser.email||'Account')}</strong><span>Plan: ${escapeHtml(String(currentUser.plan||'free').toUpperCase())}</span></div>`:`<p class="module-copy">Sign in to use the existing secure account system and cloud synchronization.</p>`}<div class="account-buttons" style="margin-top:12px"><a href="/login">LOGIN / SECURITY</a><a href="/pricing">PRICING</a></div></div></section>
   <section class="card pro-pricing-card"><div class="card-head">BDP PRO</div><div class="card-body"><small>CURRENT PLANS &amp; PRICING</small><div class="pro-price">BDP PRO</div><div class="pro-year">See the live pricing page for current options.</div><ul><li>Advanced dealer workflow</li><li>Inventory workspace</li><li>Price alerts</li><li>Saved preferences</li></ul><a href="/pricing">VIEW CURRENT PRICING ↗</a><p class="billing-note">The pricing page is the source of truth for current subscription offers.</p></div></section>
   <section class="card"><div class="card-head">YOUR BDP DATA</div><div class="card-body"><div class="account-stats"><div><small>INVENTORY ITEMS</small><strong>${inv.count}</strong></div><div><small>LOCAL ALERTS</small><strong>${alerts.count}</strong></div><div><small>PORTFOLIO VALUE</small><strong>${fmt(inv.current)}</strong></div></div></div></section>
  </div>
  <div class="grid two" style="margin-top:12px">
   <section class="card"><div class="card-head">PREFERENCES</div><div class="card-body"><div class="form-row"><div class="field"><label>DEFAULT METAL</label><select id="prefMetal" onchange="savePref()"><option value="XAU">Gold</option><option value="XAG">Silver</option><option value="XPT">Platinum</option><option value="XPD">Palladium</option></select></div><div class="field"><label>DEFAULT PAYOUT %</label><input id="prefPayout" type="number" value="${localStorage.getItem('bdp-v3-pref-payout')||80}" oninput="savePref()"></div></div><p class="local-note">Preferences are currently stored locally; inventory and alert definitions can use BDP cloud sync when signed in.</p></div></section>
   <section class="card"><div class="card-head">SECURITY & BILLING</div><div class="card-body"><p class="module-copy">Authentication and subscription management continue to use BDP's existing secure account pages until the final production integration.</p><div class="account-buttons"><a href="/login">LOGIN / SECURITY</a><a href="/pricing">PRICING</a><a href="/register">CREATE ACCOUNT</a></div></div></section>
  </div>
 </div>`;
 const pm=localStorage.getItem('bdp-v3-pref-metal')||'XAU';const prefMetalEl=document.querySelector('#prefMetal');if(prefMetalEl)prefMetalEl.value=pm;
}
function savePref(){
 const metalEl=document.querySelector('#prefMetal'),payoutEl=document.querySelector('#prefPayout');
 if(!metalEl||!payoutEl)return;
 localStorage.setItem('bdp-v3-pref-metal',metalEl.value);
 localStorage.setItem('bdp-v3-pref-payout',String(payoutEl.value||80));
}


async function loadGoldbackApi(){
 try{
  const r=await fetch('/api/goldback-rate');
  const d=await r.json();
  if(r.ok&&d&&Array.isArray(d.rates)){goldbackApi=d}
 }catch(e){}
 if((location.hash.replace('#','')||'dashboard')==='goldbacks')renderGoldbacks();
}
async function loadLiveNews(){
 try{
  const r=await fetch('/api/news');
  const d=await r.json();
  liveNewsItems=Array.isArray(d)?d.filter(x=>x&&x.title&&x.link).slice(0,12):[];
 }catch(e){liveNewsItems=[]}
 if((location.hash.replace('#','')||'dashboard')==='news')renderNews();
}
function safeExternalUrl(u){
 try{const x=new URL(u,location.origin);return /^https?:$/.test(x.protocol)?x.href:'#'}catch(e){return '#'}
}
function newsAge(date){
 const t=Date.parse(date||'');if(!Number.isFinite(t))return 'RECENT';
 const mins=Math.max(0,Math.round((Date.now()-t)/60000));
 if(mins<60)return `${mins} MIN AGO`;
 const hrs=Math.round(mins/60);if(hrs<48)return `${hrs} HR${hrs===1?'':'S'} AGO`;
 return `${Math.round(hrs/24)} DAYS AGO`;
}
function drawLiveNews(){
 const host=document.querySelector('#liveNewsGrid');
 if(!host)return;
 host.innerHTML=liveNewsItems.length?liveNewsItems.map(x=>`<a class="live-news-card" href="${safeExternalUrl(x.link)}" target="_blank" rel="noopener"><small>${newsAge(x.date)}</small><h3>${escapeHtml(x.title)}</h3><span>OPEN ORIGINAL SOURCE ↗</span></a>`).join(''):`<div class="empty-state">Live feed is unavailable right now. Use the trusted source cards below.</div>`;
}
const NEWS_SOURCES=[
 {name:'KITCO',desc:'Metals markets, pricing context and precious-metals coverage.',url:'https://www.kitco.com/',art:'card-market.png',tag:'MARKETS'},
 {name:'APMEX',desc:'Bullion education, product-market context and metals information.',url:'https://www.apmex.com/',art:'card-gold.png',tag:'BULLION'},
 {name:'NGC',desc:'Coin collecting, grading and numismatic reference.',url:'https://www.ngccoin.com/',art:'coins-hero.png',tag:'COINS'},
 {name:'SD BULLION',desc:'Bullion-market commentary and precious-metals education.',url:'https://sdbullion.com/',art:'card-silver.png',tag:'BULLION'},
 {name:'GOLDBACK',desc:'Goldback exchange-rate and product reference.',url:'https://www.goldback.com/',art:'card-goldbacks.png',tag:'GOLDBACKS'}
];
const RESOURCE_GROUPS=[
 {title:'PRECIOUS METALS BASICS',icon:'i-bars',items:[['Gold Center','gold'],['Silver Center','silver'],['Live Markets','markets'],['Calculator Center','calculators']]},
 {title:'COINS & GOLDBACKS',icon:'i-coin',items:[['Coin Center','coins'],['Goldback Center','goldbacks'],['Numismatic Sources','coins'],['Goldback Reference','goldbacks']]},
 {title:'DEALER REFERENCE',icon:'i-tools',items:[['Dealer Tools','dealer'],['Inventory','inventory'],['Price Alerts','alerts'],['Calculator Center','calculators']]},
 {title:'MARKET REFERENCE',icon:'i-chart',items:[['Market Ratios','markets'],['Dealer / Trading Tools','dealer'],['Currency Exchange','calculators'],['News Sources','news']]}
];

function renderNews(){
 page.innerHTML=`<section class="hero news-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>MARKET NEWS</h1><p>A clean precious-metals news gateway without pretending unverified headlines are live BDP data.</p></section>
 <div class="subnav"><button class="active">NEWS SOURCES</button><button onclick="filterNews('MARKETS',this)">MARKETS</button><button onclick="filterNews('BULLION',this)">BULLION</button><button onclick="filterNews('COINS',this)">COINS</button><button onclick="filterNews('GOLDBACKS',this)">GOLDBACKS</button></div>
 <div class="page">
  <section class="news-lead">
   <div><small>BDP NEWS CENTER</small><h2>Know what is moving the metals market.</h2><p>Use trusted specialist sources, then jump back into BDP to price the deal.</p></div>
   <button onclick="go('markets')">OPEN LIVE MARKETS ↗</button>
  </section>
  <div class="section-line"><span>LIVE FEED</span><small>FROM BDP /API/NEWS</small></div>
  <div id="liveNewsGrid" class="live-news-grid"></div>
  <div class="section-line"><span>TRUSTED SPECIALIST SOURCES</span><small>OPENS AT SOURCE</small></div>
  <div id="newsSourceGrid" class="news-source-grid"></div>
  <div class="grid three" style="margin-top:12px">
   <section class="card"><div class="card-head">MARKET TOPICS</div><div class="card-body"><div class="topic-pills"><button onclick="go('markets')">Gold Spot</button><button onclick="go('markets')">Silver Spot</button><button onclick="go('markets')">G/S Ratio</button><button onclick="go('markets')">Futures</button><button onclick="go('markets')">Macro</button></div></div></section>
   <section class="card"><div class="card-head">FROM NEWS TO ACTION</div><div class="card-body"><p class="module-copy">After reading the market, move directly into the tool you need.</p><div class="dash-actions"><button onclick="go('gold')">${icon('i-bars')}<span>Gold Center</span></button><button onclick="go('silver')">${icon('i-coins')}<span>Silver Center</span></button><button onclick="go('dealer')">${icon('i-tools')}<span>Dealer Tools</span></button><button onclick="go('alerts')">${icon('i-bell')}<span>Set Alert</span></button></div></div></section>
   <section class="card"><div class="card-head">SOURCE STANDARD</div><div class="card-body"><p class="module-copy">V3 only labels information as live when it comes from an actual connected data endpoint. External news sources are clearly identified and opened at the publisher.</p><button class="module-open" onclick="go('resources')">VIEW RESOURCE CENTER ↗</button></div></section>
  </div>
 </div>`;
 drawLiveNews();drawNewsSources('ALL');
}
function drawNewsSources(filter='ALL'){
 const host=document.querySelector('#newsSourceGrid');
 if(!host)return;
 const items=NEWS_SOURCES.filter(x=>filter==='ALL'||x.tag===filter);
 host.innerHTML=items.map(x=>`<a class="news-source-card" href="${x.url}" target="_blank" rel="noopener" style="--news-art:url('/img/newlook/${x.art}')"><div><small>${x.tag}</small><h3>${x.name}</h3><p>${x.desc}</p><span>OPEN SOURCE ↗</span></div></a>`).join('');
}
function filterNews(filter,btn){
 document.querySelectorAll('.subnav button').forEach(x=>x.classList.remove('active'));
 btn.classList.add('active');drawNewsSources(filter);
}

function renderResources(){
 page.innerHTML=`<section class="hero resources-hero" style="--hero:url('/bdp-mountain-bullion-banner-v328.png')"><h1>RESOURCE CENTER</h1><p>BDP tools, educational pathways and trusted specialist references organized visually instead of buried in link lists.</p></section>
 <div class="page">
  <section class="resource-intro"><small>LEARN · CHECK · CALCULATE · ACT</small><h2>Everything should lead to a useful next step.</h2><p>Use BDP Centers for calculations and working values; use specialist external sources for deeper market, coin and Goldback reference.</p></section>
  <div class="resource-groups">${RESOURCE_GROUPS.map(g=>`<section class="resource-group"><div class="resource-group-head">${icon(g.icon)}<h3>${g.title}</h3></div><div class="resource-links">${g.items.map(i=>`<button onclick="go('${i[1]}')">${i[0]}<span>→</span></button>`).join('')}</div></section>`).join('')}</div>
  <div class="section-line"><span>TRUSTED EXTERNAL REFERENCES</span><small>OPENS AT SOURCE</small></div>
  <div class="trusted-grid">
   ${NEWS_SOURCES.map(x=>`<a href="${x.url}" target="_blank" rel="noopener"><img src="/img/newlook/${x.art}" alt=""><div><small>${x.tag}</small><b>${x.name}</b><span>${x.desc}</span></div></a>`).join('')}
  </div>
  <div class="grid two" style="margin-top:12px">
   <section class="card"><div class="card-head">BDP REFERENCE PATH</div><div class="card-body"><p class="module-copy">Use the native Coin Center for grading sources and the controlled deep numismatic database, or open Goldbacks and Markets for specialist reference.</p><button class="gold-btn" onclick="go('coins')">OPEN COIN REFERENCE HUB →</button></div></section>
   <section class="card"><div class="card-head">START WITH A QUESTION</div><div class="card-body"><div class="question-links"><button onclick="go('gold')">What is my gold worth?</button><button onclick="go('silver')">What is my silver worth?</button><button onclick="go('coins')">What coin am I looking at?</button><button onclick="go('goldbacks')">What is a Goldback worth?</button><button onclick="go('dealer')">What should I pay or sell for?</button><button onclick="go('markets')">What is the market doing?</button></div></div></section>
  </div>
 </div>`;
}
const pageMeta={
 dashboard:{title:"DASHBOARD",sub:"Your precious-metals command center",hero:"card-market.png",mods:[
 ["MARKET SNAPSHOT","Live Gold, Silver, Platinum and Palladium pricing with movement at a glance.","chart"],
 ["QUICK ACTIONS","Price a gold deal · Price a silver deal · Calculate melt · View Goldbacks","actions"],
 ["DEALER OPPORTUNITY","Instant 5% / 10% under and over spot working benchmarks.","bench"],
 ["MY MARKET","Gold/Silver ratio, session status, daily movers and 24-hour direction.","chart"],
 ["MARKET NEWS","A compact precious-metals news feed designed for fast scanning.","news"],
 ["PORTFOLIO PREVIEW","Inventory value, basis and unrealized profit for BDP Pro.","pro"]]},
 markets:{title:"LIVE MARKETS",sub:"Real-time precious-metals command center",hero:"fx-hero.png",mods:[
 ["INTERACTIVE PRICE CHART","Gold · Silver · Platinum · Palladium · Copper","chart"],
 ["MARKET STATUS","New York · London · Shanghai · Tokyo · COMEX","status"],
 ["KEY RATIOS","Gold/Silver · Gold/Platinum · Platinum/Palladium","bench"],
 ["SESSION INTELLIGENCE","Open · High · Low · Previous Close · Daily Range","stats"],
 ["FUTURES","Fast futures reference and market-session context.","chart"],
 ["MARKET NEWS","Latest macro and metals headlines.","news"]]},
 silver:{title:"SILVER CENTER",sub:"Spot, constitutional silver, bullion, rolls and dealer calculations",hero:"card-silver.png",mods:[
 ["SILVER SPOT","Live price, daily movement and 24-hour chart.","chart"],
 ["CONSTITUTIONAL SILVER","Dimes · Quarters · Halves with melt and dealer benchmarks.","table"],
 ["QUICK SILVER DEAL","Face value or ounces → melt, buy target, sell target and margin.","calc"],
 ["ROLL VALUES","Half-dollar · Quarter · Dime roll values.","table"],
 ["POPULAR SILVER BULLION","Silver Eagle · Maple · Britannia · rounds · bars.","coins"],
 ["SILVER TOOLS","Melt · Rolls · Premium · Dealer Spread · Historical Charts.","actions"]]},
 coins:{title:"COIN CENTER",sub:"Bullion and numismatic research in one visual workspace",hero:"coins-hero.png",mods:[
 ["COIN SEARCH","Search denomination, year, mint mark and type.","search"],
 ["POPULAR CATEGORIES","Morgan · Peace · Walking Liberty · Mercury · Lincoln · Gold Eagles.","coins"],
 ["MELT VS NUMISMATIC","See intrinsic metal value beside collector-value reference.","bench"],
 ["KEY DATES","Fast sortable key-date reference.","table"],
 ["GRADING REFERENCE","Circulated · AU · Mint State · Proof reference.","coins"],
 ["COIN TOOLS","Melt · Key Dates · Dealer Spread · Roll Values · Grading.","actions"]]},
 goldbacks:{title:"GOLDBACK CENTER",sub:"Rates, denominations, state series and transaction tools",hero:"card-goldbacks.png",mods:[
 ["WORKING RATE","Keep official exchange-rate data clearly separate from intrinsic melt.","stats"],
 ["DENOMINATIONS","1/4 · 1/2 · 1 · 2 · 5 · 10 · 25 · 50 · 100 where supported.","notes"],
 ["STATE / SERIES","Visual selector for supported Goldback issues.","actions"],
 ["TRANSACTION CONVERTER","USD ↔ Goldback working transaction calculator.","calc"],
 ["DEALER LINKS","Graphic retailer tiles instead of a long text-link list.","notes"],
 ["GOLDBACK EDUCATION","Gold content, exchange value and intrinsic value explained clearly.","news"]]},
 calculators:{title:"CALCULATOR CENTER",sub:"Every BDP calculator in one professional workspace",hero:"card-gold.png",mods:[
 ["PRECIOUS METALS","Gold Karat · Silver Melt · Platinum · Palladium · Copper.","calc"],
 ["DEALER PRICING","Buy Under Spot · Sell Over Spot · Spread · Margin · Premium %.","bench"],
 ["COINS","Constitutional Silver · Rolls · Gold Coin · Silver Coin Melt.","coins"],
 ["CONVERSIONS","Troy oz · gram · dwt · grain · kilogram.","calc"],
 ["ACTIVE CALCULATOR","Selected calculator opens here without leaving the workspace.","calc"],
 ["SAVED DEFAULTS","Store preferred payout and dealer percentages.","pro"]]},
 dealer:{title:"DEALER TOOLS",sub:"Quote, spread, scrap and profit tools built for the counter",hero:"card-dealer.png",mods:[
 ["DEAL SHEET","Item · quantity · purity · spot · purchase · target sale → profit.","calc"],
 ["QUICK BENCHMARKS","Gold and Silver at 10% under, 5% under, spot, 5% over and 10% over.","bench"],
 ["COMPARE DEALERS","Buy price · sell price · spread · last checked.","table"],
 ["SCRAP BUYER","Weight · karat · payout · refinery margin · customer offer.","calc"],
 ["TRADING / PURCHASE SHEET","Clean working sheet designed for printing or export.","table"],
 ["DEALER REFERENCE","Weights · fineness · coin silver content · market hours.","news"]]},
 inventory:{title:"INVENTORY",sub:"Track holdings, cost basis, current value and profit",hero:"card-coins.png",mods:[
 ["PORTFOLIO SUMMARY","Units · total cost · melt value · estimated retail · P/L.","stats"],
 ["HOLDINGS TABLE","Item · category · qty · weight · purity · basis · current value.","table"],
 ["ADD ITEM","Fast entry for Gold · Silver · Coins · Goldbacks · Other.","calc"],
 ["FILTERS","Metal · category · date · profitable · underwater.","actions"],
 ["PROFIT / LOSS","Visual unrealized performance summary.","chart"],
 ["EXPORT","CSV and printable inventory report.","pro"]]},
 alerts:{title:"PRICE ALERTS",sub:"Actionable metal and ratio alerts without notification clutter",hero:"card-market.png",mods:[
 ["ALERT BUILDER","Metal · above/below · dollar price · % move · ratio threshold.","calc"],
 ["ACTIVE ALERTS","Trigger · current value · distance · enabled / paused.","table"],
 ["DISTANCE TO TRIGGER","Visual progress toward your configured thresholds.","chart"],
 ["ALERT HISTORY","Recently triggered alerts.","table"],
 ["SUGGESTED ALERTS","Useful preset ideas for Gold, Silver and G/S ratio.","actions"],
 ["NOTIFICATIONS","Manage BDP Pro alert preferences.","pro"]]},
 news:{title:"MARKET NEWS",sub:"Curated precious-metals information inside BDP",hero:"fx-hero.png",mods:[
 ["LEAD STORY","Large featured market story with source and timestamp.","news"],
 ["LATEST NEWS","Fast-scanning two-column metals headlines.","news"],
 ["CATEGORY FILTERS","Gold · Silver · Markets · Futures · Macro · Coins.","actions"],
 ["SOURCE / TIME","Clear source attribution and freshness.","table"],
 ["MARKET IMPACT","Optional BDP interpretation clearly labeled as analysis.","chart"],
 ["SAVED STORIES","Keep important references in one place.","pro"]]},
 resources:{title:"RESOURCE CENTER",sub:"Education, dealer reference and trusted links",hero:"card-coins.png",mods:[
 ["BEGINNER GUIDES","Buying Gold · Buying Silver · Spot · Premiums · Bullion vs Numismatic.","news"],
 ["DEALER REFERENCE","Weights · purity · constitutional silver · coin specs.","table"],
 ["MARKET EDUCATION","G/S Ratio · COMEX · LBMA · market hours · futures basics.","chart"],
 ["TRUSTED LINKS","Mints · grading services · exchanges · market sources.","actions"],
 ["COIN REFERENCES","Specifications, grading and collector resources.","coins"],
 ["GOLDBACK GUIDES","Gold content, series and transaction education.","notes"]]},
 account:{title:"ACCOUNT",sub:"Profile, subscription, preferences and data",hero:"card-gold.png",mods:[
 ["PROFILE","Name · email · password.","calc"],
 ["SUBSCRIPTION","Free / Pro · current plans and pricing are shown on the pricing page.","pro"],
 ["PREFERENCES","Default metal · units · calculator percentages.","actions"],
 ["DATA","Inventory export · favorites · saved settings.","table"],
 ["SECURITY","Password and session controls where supported.","status"],
 ["SUPPORT","BDP account and subscription help.","news"]]}
};
function moduleVisual(type){
 if(type==="chart") return chartSVG();
 if(type==="table") return `<table><tbody><tr><td>PRIMARY VALUE</td><td>${fmt(prices.XAU)}</td></tr><tr><td>SECONDARY</td><td>${fmt(prices.XAG)}</td></tr><tr><td>WORKING SPREAD</td><td class="up">+5.00%</td></tr></tbody></table>`;
 if(type==="bench") return `<div class="calc-result"><div><small>5% UNDER</small><strong>${fmt(prices.XAU*.95)}</strong></div><div><small>SPOT</small><strong>${fmt(prices.XAU)}</strong></div><div><small>5% OVER</small><strong>${fmt(prices.XAU*1.05)}</strong></div></div>`;
 if(type==="calc") return `<div class="form-row"><div class="field"><label>VALUE / WEIGHT</label><input placeholder="Enter value"></div><div class="field"><label>TYPE / UNIT</label><select><option>Select</option></select></div></div><button class="gold-btn">OPEN CALCULATOR</button>`;
 if(type==="coins") return `<div class="tile-row">${["gold-coin-eagle.png","gold-coin-buffalo.png","gold-coin-krugerrand.png"].map((x,i)=>`<div class="image-tile"><img src="/img/newlook/${x}"><b>${["EAGLE","BUFFALO","KRUGERRAND"][i]}</b></div>`).join("")}</div>`;
 if(type==="notes") return `<div class="tile-row">${[1,5,10].map(n=>`<div class="image-tile"><img src="/img/newlook/card-goldbacks.png"><b>${n} GOLDBACK</b></div>`).join("")}</div>`;
 if(type==="stats") return `<div class="statbar"><div><small>GOLD</small><strong>${fmt(prices.XAU)}</strong></div><div><small>SILVER</small><strong>${fmt(prices.XAG)}</strong></div><div><small>G/S</small><strong>${(prices.XAU/prices.XAG).toFixed(2)}</strong></div><div><small>STATUS</small><strong class="up">LIVE</strong></div></div>`;
 if(type==="actions") return `<div class="tool-grid">${[["i-calc","Quick Tool"],["i-chart","View Data"],["i-star","Save / Watch"]].map(t=>`<div class="tool">${icon(t[0])}<span>${t[1]}</span></div>`).join("")}</div>`;
 if(type==="pro") return `<div style="padding:14px;border:1px solid rgba(219,164,42,.35);border-radius:7px;background:linear-gradient(135deg,rgba(219,164,42,.12),transparent)"><b style="color:var(--gold2);font:700 22px Rajdhani">◇ BDP PRO</b><p style="color:#aaa;font-size:12px">Premium workflow module.</p></div>`;
 return `<div class="fake"></div>`;
}
function renderGeneric(p){ location.hash='dashboard'; }
menuBtn.onclick=()=>{
 const open=sidebar.classList.toggle('open');
 menuBtn.setAttribute('aria-expanded',String(open));
 menuBtn.setAttribute('aria-label',open?'Close navigation':'Open navigation');
};
document.querySelector('.brand')?.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();go('dashboard')}});
document.addEventListener('keydown',e=>{if(e.key==='Home'&&!/INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName||'')){go('dashboard')}});
buildNav();drawMarket();render();loadMarkets();hydrateUserSync();loadLiveNews();loadGoldbackApi();setInterval(loadMarkets,60000);setInterval(loadLiveNews,600000);setInterval(loadGoldbackApi,300000);
