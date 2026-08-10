// CLEAN BUILD: 20260504_190541


// ═══ THEME ═══
function toggleTheme(){
  const html=document.documentElement;
  const dark=html.getAttribute('data-theme')==='dark';
  const t=dark?'light':'dark';
  html.setAttribute('data-theme',t);
  localStorage.setItem('bdp-theme',t);
  const icon=document.getElementById('ham-theme-icon');
  const lbl=document.getElementById('ham-theme-label');
  if(icon) icon.textContent=t==='dark'?'☀️':'🌙';
  if(lbl) lbl.textContent=t==='dark'?'Light Mode':'Dark Mode';
}
function toggleHamMenu(e){
  if(e){e.preventDefault();e.stopPropagation();}
  const m=document.getElementById('ham-menu');
  m.classList.toggle('open');
}
function closeHamMenu(){
  const m=document.getElementById('ham-menu');
  if(m) m.classList.remove('open');
}
// Wire up ham button — click + touchend for tablet/mobile
(function(){
  function wireHam(){
    const btn=document.getElementById('ham-btn');
    const menu=document.getElementById('ham-menu');
    const themeBtn=document.getElementById('ham-theme-btn');
    const logoutBtn=document.getElementById('logout-btn');
    if(!btn||!menu) return;
    function onHamTap(e){e.preventDefault();e.stopPropagation();menu.classList.toggle('open');}
    btn.addEventListener('click',onHamTap);
    btn.addEventListener('touchend',onHamTap,{passive:false});
    if(themeBtn){
      function onThemeTap(e){e.preventDefault();e.stopPropagation();toggleTheme();closeHamMenu();}
      themeBtn.addEventListener('click',onThemeTap);
      themeBtn.addEventListener('touchend',onThemeTap,{passive:false});
    }
    if(logoutBtn){
      function onLogoutTap(e){e.preventDefault();e.stopPropagation();closeHamMenu();doLogout();}
      logoutBtn.addEventListener('click',onLogoutTap);
      logoutBtn.addEventListener('touchend',onLogoutTap,{passive:false});
    }
    // Close when tapping outside
    document.addEventListener('touchend',function(e){
      if(menu.classList.contains('open')&&!menu.contains(e.target)&&!btn.contains(e.target)){
        menu.classList.remove('open');
      }
    },{passive:true});
    document.addEventListener('click',function(e){
      if(menu.classList.contains('open')&&!menu.contains(e.target)&&!btn.contains(e.target)){
        menu.classList.remove('open');
      }
    });
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',wireHam);
  else wireHam();
})();
(function(){
  const s=localStorage.getItem('bdp-theme')||'light';
  document.documentElement.setAttribute('data-theme',s);
  window.addEventListener('DOMContentLoaded',function(){
    const icon=document.getElementById('ham-theme-icon');
    const lbl=document.getElementById('ham-theme-label');
    if(icon) icon.textContent=s==='dark'?'☀️':'🌙';
    if(lbl) lbl.textContent=s==='dark'?'Light Mode':'Dark Mode';
  });
})();

// ═══ UTILS ═══
const $=id=>document.getElementById(id);
const fmt=v=>v==null?'—':'$'+v.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});

// ═══ SPOT STATE ═══
const spot={XAU:0,XAG:0,HG:0,XPT:0,XPD:0,ZN:0};
let window_isPro=false;
let window_authReady=false;  // true once loadAccount resolves
let window_pendingTab=null;  // tab to open once auth resolves

async function fm(sym){
  try{
    const r=await fetch('/api/metals/'+sym+'?_='+Date.now(),{cache:'no-store'});
    if(!r.ok)return null;
    const d=await r.json();
    // normalize API response fields
    if(d && d.ch !== undefined){
      d.change = d.ch;
      d.changePercent = d.prev_close_price ? (d.ch / d.prev_close_price * 100) : 0;
    }
    return d;
  }catch{return null}
}
function fmtSpotChange(d){
  if(!d||d.change==null)return '';
  const arr=d.change>=0?'▲':'▼';
  const cls=d.change>=0?'up':'dn';
  return '<span class="'+cls+'">'+arr+Math.abs(d.changePercent||0).toFixed(2)+'%</span>';
}
function setTicker(ids,d,perLb=false){
  const p=d.price;
  const label=perLb?'$'+p.toFixed(2)+'/lb':'$'+p.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  const chg=fmtSpotChange(d);
  ids.forEach(id=>{const e=$(id);if(e)e.innerHTML=label+' '+chg;});
}
async function loadSpot(attempt){
  attempt = attempt||1;
  try{
    const [au,ag,cu,pt,pd]=await Promise.all([fm('XAU'),fm('XAG'),fm('XCU'),fm('XPT'),fm('XPD')]);
    const gotPrices = au?.price && ag?.price;
    if(au?.price){spot.XAU=au.price;spot._au=au;setTicker(['tkr-au','tkr-au2'],au);}
    if(ag?.price){spot.XAG=ag.price;spot._ag=ag;setTicker(['tkr-ag','tkr-ag2'],ag);}
    if(cu?.price){spot.HG=cu.price;setTicker(['tkr-cu','tkr-cu2'],cu,true);}
    if(pt?.price){spot.XPT=pt.price;setTicker(['tkr-pt','tkr-pt2'],pt);}
    if(pd?.price){spot.XPD=pd.price;setTicker(['tkr-pd','tkr-pd2'],pd);}
    fetch('/api/metals/ZN').then(r=>r.json()).then(d=>{if(d?.price)spot.ZN=d.price;}).catch(()=>{spot.ZN=1.30;});
    if(!gotPrices && attempt<4){
      // Didn't get prices — retry with backoff (2s, 4s, 8s)
      console.warn('[loadSpot] attempt '+attempt+' got no prices, retrying in '+(attempt*2)+'s...');
      setTimeout(()=>loadSpot(attempt+1), attempt*2000);
      return;
    }
    console.log('[loadSpot] prices loaded (attempt '+attempt+') AU:'+spot.XAU+' AG:'+spot.XAG);
    updateHeroPrices();
  }catch(e){
    console.error('[loadSpot] ERROR attempt '+attempt+':', e);
    if(attempt<4) setTimeout(()=>loadSpot(attempt+1), attempt*2000);
    return;
  }
  try{calcGold();calcConst();calcPenny();calcPlatPal();}catch(e){console.error('[loadSpot] calc ERROR:',e);}
  try{renderKaratTable();renderSilverMeltTable();renderConstRefTable();renderPennyRefTable();}catch(e){console.error('[loadSpot] render ERROR:',e);}
  try{renderInventory();renderSlabs();presetLoad();tsSyncSpot();}catch(e){console.error('[loadSpot] admin ERROR:',e);}
}
function setHdr(id,d,perLb=false){
  const el=$(id);if(!el)return;
  const p=d.price;
  const label=perLb?'$'+p.toFixed(2)+'/lb':'$'+p.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  const cls=d.change>=0?'up':'dn';
  const arr=d.change>=0?'▲':'▼';
  el.innerHTML=label+' <span class="'+cls+'">'+arr+Math.abs(d.changePercent||0).toFixed(2)+'%</span>';
}
function updateHeroPrices(){
  if(spot.XAU){
    const auFmt='$'+spot.XAU.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
    $('gold-hero-price').textContent=auFmt;
    // Gold:Silver ratio
    if(spot.XAG && spot.XAU){
      const ratio=(spot.XAU/spot.XAG);
      const ratioEl=$('gs-ratio');
      if(ratioEl)ratioEl.textContent=ratio.toFixed(1)+':1';
    }
    const ghcEl=$('gold-hero-chg');
    if(ghcEl){
      if(spot._au&&spot._au.change!=null){
        const arr=spot._au.change>=0?'▲':'▼';
        const cls=spot._au.change>=0?'up':'dn';
        const diff='$'+Math.abs(spot._au.change).toFixed(2);
        ghcEl.innerHTML='<span class="'+cls+'">'+arr+diff+' ('+Math.abs(spot._au.changePercent||0).toFixed(2)+'%)</span>';
      } else {ghcEl.textContent='Live spot';}
    }
    // spotlight extras
    const gPerG=(spot.XAU/31.1035).toFixed(2);
    const gPerDwt=(spot.XAU/20).toFixed(2);
    const gpg=$('gold-per-gram');if(gpg)gpg.textContent='$'+gPerG+' / g';
    const dpg=$('gold-per-dwt');if(dpg)dpg.textContent='$'+gPerDwt+' / dwt';
    // Auto-populate karat calculator spot input if user hasn't changed it
    const gkSpotEl=$('gk-spot');
    if(gkSpotEl&&(!gkSpotEl.value||parseFloat(gkSpotEl.value)===0))gkSpotEl.value=spot.XAU.toFixed(2);
    renderKaratTable();
  }
  if(spot.XAG){
    const agFmt='$'+spot.XAG.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
    ['silver-hero-price','const-hero-price','silver-spotlight-price'].forEach(id=>{const e=$(id);if(e)e.textContent=agFmt;});
    const ssc=$('silver-spotlight-chg');
    if(ssc){
      if(spot._ag&&spot._ag.change!=null){
        const arr2=spot._ag.change>=0?'▲':'▼';
        const cls2=spot._ag.change>=0?'up':'dn';
        const diff2='$'+Math.abs(spot._ag.change).toFixed(4);
        ssc.innerHTML='<span class="'+cls2+'">'+arr2+diff2+' ('+Math.abs(spot._ag.changePercent||0).toFixed(2)+'%)</span>';
      } else {ssc.innerHTML='<span style="opacity:0.8;font-size:12px">Live spot</span>';}
    }
    const sPerG=(spot.XAG/31.1035).toFixed(4);
    const spg=$('silver-per-gram');if(spg)spg.textContent='$'+sPerG+' / g';
    const spo=$('silver-per-oz');if(spo)spo.textContent='$'+spot.XAG.toFixed(2)+' / oz';
    // Auto-populate silver spot inputs if user hasn't changed them
    const agVal=spot.XAG.toFixed(2);
    ['deal-bul-spot','const-spot','const-roll-spot'].forEach(id=>{const el=$(id);if(el&&(!el.value||parseFloat(el.value)===32.45||parseFloat(el.value)===0))el.value=agVal;});
  }
  if(spot.HG&&spot.ZN){
    const m=(spot.HG*0.00220462262*3.11*0.95)+(spot.ZN*0.00220462262*3.11*0.05);
    const e=$('penny-hero-melt');if(e)e.textContent='$'+m.toFixed(4);
  }
}

// ═══ TABS ═══
const PRO_TABS=['const','trading','numismatic','typeset'];
function showTab(id){
  // Pro tab clicked — if not authenticated yet, queue it
  if(PRO_TABS.includes(id) && !window_authReady){
    window_pendingTab = id;
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    const tPend = Array.from(document.querySelectorAll('.tab')).find(t=>t.getAttribute('onclick')===`showTab('${id}')`);
    if(tPend) tPend.classList.add('active');
    return;
  }
  // Pro tab but not a PRO user — show upgrade prompt inside the tab, not full-screen
  if(PRO_TABS.includes(id) && !window_isPro){
    showProUpgrade(id);
    return;
  }
  // Normal tab switch
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  const sec = $('tab-'+id); if(sec) sec.classList.add('active');
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  const tBtn = Array.from(document.querySelectorAll('.tab')).find(t=>t.getAttribute('onclick')===`showTab('${id}')`);
  if(tBtn) tBtn.classList.add('active');
  if(id==='fx') loadFX();
  if(id==='gold'){renderGoldback();renderCoinVals();}
  if(id==='pennies') renderPennyCoinVals();
  if(id==='numismatic') renderAllKeyDates();
  if(id==='trading'){tsInit();}
  if(id==='typeset'){tsRenderSet(tsCurrentSet);tsUpdateOverall();}
  if(id==='admin'){renderInventory();renderSlabs();renderAlerts();presetLoad();}
}

function showProUpgrade(tabId){
  // Show a clean inline upgrade prompt — not a full-screen paywall
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  const sec = $('tab-'+tabId); if(sec) sec.classList.add('active');
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  const tBtn = Array.from(document.querySelectorAll('.tab')).find(t=>t.getAttribute('onclick')===`showTab('${tabId}')`);
  if(tBtn) tBtn.classList.add('active');
  // Inject upgrade prompt at top of section
  if(sec && !sec.querySelector('.upgrade-prompt')){
    const div = document.createElement('div');
    div.className = 'upgrade-prompt';
    div.style.cssText = 'text-align:center;padding:60px 20px;';
    div.innerHTML = '<div style="font-size:48px;margin-bottom:16px">🔒</div><div style="font-size:22px;font-weight:800;margin-bottom:10px;color:var(--text)">PRO Feature</div><div style="color:var(--muted);margin-bottom:28px;max-width:380px;margin-left:auto;margin-right:auto">Subscribe to unlock this tool and all dealer features.</div><a href="/pricing" style="display:inline-block;background:var(--blue);color:#fff;padding:12px 32px;border-radius:8px;font-weight:700;text-decoration:none;font-size:15px">View Plans →</a><div style="margin-top:16px"><a href="/login" style="color:var(--muted);font-size:13px">Already subscribed? Log in</a></div>';
    sec.insertBefore(div, sec.firstChild);
  }
}
function goldSec(s,btn){['karat','goldback','grading','keydate','errors','coinvals','scrapgold','goldcoins'].forEach(k=>{const e=$('gs-'+k);if(e)e.style.display=k===s?'':'none';});document.querySelectorAll('#tab-gold .sub-nav .seg').forEach(b=>b.classList.remove('active'));
  if(s==='scrapgold'){loadScrapPresets();calcScrapGold();}
  if(s==='goldcoins'){renderGoldCoins();}if(btn)btn.classList.add('active');if(s==='coinvals')renderCoinVals();if(s==='goldback')renderGoldback();}
function silverSec(s,btn){['calc','premiums','platpal','coins'].forEach(k=>{const e=$('ss-'+k);if(e)e.style.display=k===s?'':'none';});document.querySelectorAll('#tab-silver .sub-nav .seg').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');if(s==='premiums')renderPremiums();if(s==='coins')renderSilverCoins();if(s==='platpal'){renderPlatinumCoins();}}
function constSec(s,btn){['calc','rolls','ref','melt'].forEach(k=>{const e=$('cs-'+k);if(e)e.style.display=k===s?'':'none';});document.querySelectorAll('#tab-const .sub-nav .seg').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');if(s==='ref')renderConstRef();if(s==='rolls')calcConstRolls();}
function pennySec(s,btn){['calc'].forEach(k=>{const e=$('ps-'+k);if(e)e.style.display=k===s?'':'none';});document.querySelectorAll('#tab-pennies .sub-nav .seg').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');}
function numSec(s,btn){['keydate','grading','errors','coinvals','coinspecs'].forEach(k=>{const e=$('nm-'+k);if(e)e.style.display=k===s?'':'none';});document.querySelectorAll('#tab-numismatic .sub-nav .seg').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');if(s==='errors')renderErrors('nm-errors-grid');if(s==='grading')renderNmGrading();if(s==='keydate')renderAllKeyDates();if(s==='coinvals')renderNmCoinVals();if(s==='coinspecs')renderCoinSpecs();}

const COIN_SPECS=[
  // ── US SILVER HISTORIC ──────────────────────────────────────────────────────
  {cat:'US Silver',metal:'silver',name:'Barber Dime (1892–1916)',wt:2.50,dia:17.9,fine:'.900',oz:'0.07234'},
  {cat:'US Silver',metal:'silver',name:'Mercury Dime (1916–1945)',wt:2.50,dia:17.9,fine:'.900',oz:'0.07234'},
  {cat:'US Silver',metal:'silver',name:'Roosevelt Dime (1946–1964)',wt:2.50,dia:17.9,fine:'.900',oz:'0.07234'},
  {cat:'US Silver',metal:'silver',name:'War Nickel (1942–1945)',wt:5.00,dia:21.2,fine:'.350',oz:'0.05626'},
  {cat:'US Silver',metal:'silver',name:'Barber Quarter (1892–1916)',wt:6.25,dia:24.3,fine:'.900',oz:'0.18084'},
  {cat:'US Silver',metal:'silver',name:'Standing Liberty Quarter (1916–1930)',wt:6.25,dia:24.3,fine:'.900',oz:'0.18084'},
  {cat:'US Silver',metal:'silver',name:'Washington Quarter (1932–1964)',wt:6.25,dia:24.3,fine:'.900',oz:'0.18084'},
  {cat:'US Silver',metal:'silver',name:'Barber Half Dollar (1892–1915)',wt:12.50,dia:30.6,fine:'.900',oz:'0.36169'},
  {cat:'US Silver',metal:'silver',name:'Walking Liberty Half Dollar (1916–1947)',wt:12.50,dia:30.6,fine:'.900',oz:'0.36169'},
  {cat:'US Silver',metal:'silver',name:'Franklin Half Dollar (1948–1963)',wt:12.50,dia:30.6,fine:'.900',oz:'0.36169'},
  {cat:'US Silver',metal:'silver',name:'Kennedy Half Dollar 1964 (90%)',wt:12.50,dia:30.6,fine:'.900',oz:'0.36169'},
  {cat:'US Silver',metal:'silver',name:'Kennedy Half Dollar 1965–1970 (40%)',wt:11.50,dia:30.6,fine:'.400',oz:'0.14792'},
  {cat:'US Silver',metal:'silver',name:'Morgan Dollar (1878–1921)',wt:26.73,dia:38.1,fine:'.900',oz:'0.77344'},
  {cat:'US Silver',metal:'silver',name:'Peace Dollar (1921–1935)',wt:26.73,dia:38.1,fine:'.900',oz:'0.77344'},
  {cat:'US Silver',metal:'silver',name:'American Silver Eagle (1986–present)',wt:31.10,dia:40.6,fine:'.999',oz:'1.00000'},
  // ── US GOLD HISTORIC ────────────────────────────────────────────────────────
  {cat:'US Gold Historic',metal:'gold',name:'Gold Dollar — Liberty / Indian Head (1849–1889)',wt:1.67,dia:13.0,fine:'.900',oz:'0.04837'},
  {cat:'US Gold Historic',metal:'gold',name:'$2.50 Quarter Eagle — Liberty / Indian (1840–1929)',wt:4.18,dia:18.0,fine:'.900',oz:'0.12094'},
  {cat:'US Gold Historic',metal:'gold',name:'$3 Gold Piece (1854–1889)',wt:5.02,dia:20.6,fine:'.900',oz:'0.14512'},
  {cat:'US Gold Historic',metal:'gold',name:'$5 Half Eagle — Liberty / Indian (1839–1929)',wt:8.36,dia:21.6,fine:'.900',oz:'0.24187'},
  {cat:'US Gold Historic',metal:'gold',name:'$10 Eagle — Liberty / Indian (1838–1933)',wt:16.72,dia:27.0,fine:'.900',oz:'0.48375'},
  {cat:'US Gold Historic',metal:'gold',name:'$20 Liberty Head Double Eagle (1850–1907)',wt:33.44,dia:34.0,fine:'.900',oz:'0.96750'},
  {cat:'US Gold Historic',metal:'gold',name:'$20 Saint-Gaudens Double Eagle (1907–1933)',wt:33.44,dia:34.0,fine:'.900',oz:'0.96750'},
  // ── US GOLD MODERN ──────────────────────────────────────────────────────────
  {cat:'US Gold Modern',metal:'gold',name:'American Gold Eagle — 1 oz',wt:33.93,dia:32.7,fine:'.9167',oz:'1.00000'},
  {cat:'US Gold Modern',metal:'gold',name:'American Gold Eagle — 1/2 oz',wt:16.97,dia:27.0,fine:'.9167',oz:'0.50000'},
  {cat:'US Gold Modern',metal:'gold',name:'American Gold Eagle — 1/4 oz',wt:8.48,dia:22.0,fine:'.9167',oz:'0.25000'},
  {cat:'US Gold Modern',metal:'gold',name:'American Gold Eagle — 1/10 oz',wt:3.39,dia:16.5,fine:'.9167',oz:'0.10000'},
  {cat:'US Gold Modern',metal:'gold',name:'American Gold Buffalo — 1 oz',wt:31.10,dia:32.7,fine:'.9999',oz:'1.00000'},
  // ── WORLD GOLD ──────────────────────────────────────────────────────────────
  {cat:'World Gold',metal:'gold',name:'South African Krugerrand — 1 oz',wt:33.93,dia:32.6,fine:'.9167',oz:'1.00000'},
  {cat:'World Gold',metal:'gold',name:'South African Krugerrand — 1/2 oz',wt:16.97,dia:27.0,fine:'.9167',oz:'0.50000'},
  {cat:'World Gold',metal:'gold',name:'South African Krugerrand — 1/4 oz',wt:8.48,dia:22.6,fine:'.9167',oz:'0.25000'},
  {cat:'World Gold',metal:'gold',name:'South African Krugerrand — 1/10 oz',wt:3.39,dia:16.5,fine:'.9167',oz:'0.10000'},
  {cat:'World Gold',metal:'gold',name:'Canadian Gold Maple Leaf — 1 oz',wt:31.10,dia:30.0,fine:'.9999',oz:'1.00000'},
  {cat:'World Gold',metal:'gold',name:'Canadian Gold Maple Leaf — 1/2 oz',wt:15.55,dia:25.0,fine:'.9999',oz:'0.50000'},
  {cat:'World Gold',metal:'gold',name:'Canadian Gold Maple Leaf — 1/4 oz',wt:7.78,dia:20.0,fine:'.9999',oz:'0.25000'},
  {cat:'World Gold',metal:'gold',name:'Canadian Gold Maple Leaf — 1/10 oz',wt:3.11,dia:16.0,fine:'.9999',oz:'0.10000'},
  {cat:'World Gold',metal:'gold',name:'British Gold Sovereign (1817–present)',wt:7.99,dia:22.1,fine:'.9167',oz:'0.23540'},
  {cat:'World Gold',metal:'gold',name:'British Gold Britannia — 1 oz',wt:33.93,dia:32.7,fine:'.9999',oz:'1.00000'},
  {cat:'World Gold',metal:'gold',name:'Austrian Gold Philharmonic — 1 oz',wt:31.10,dia:37.0,fine:'.9999',oz:'1.00000'},
  {cat:'World Gold',metal:'gold',name:'Austrian Gold Philharmonic — 1/4 oz',wt:7.78,dia:22.0,fine:'.9999',oz:'0.25000'},
  {cat:'World Gold',metal:'gold',name:'Chinese Gold Panda — 30g (2016–present)',wt:30.00,dia:32.0,fine:'.9999',oz:'0.96450'},
  {cat:'World Gold',metal:'gold',name:'Australian Gold Kangaroo — 1 oz',wt:31.10,dia:32.1,fine:'.9999',oz:'1.00000'},
  {cat:'World Gold',metal:'gold',name:'Mexican Gold Centenario (50 Pesos)',wt:41.67,dia:37.0,fine:'.900',oz:'1.20565'},
  // ── WORLD SILVER ────────────────────────────────────────────────────────────
  {cat:'World Silver',metal:'silver',name:'Canadian Silver Maple Leaf — 1 oz',wt:31.10,dia:38.0,fine:'.9999',oz:'1.00000'},
  {cat:'World Silver',metal:'silver',name:'Austrian Silver Philharmonic — 1 oz',wt:31.10,dia:37.0,fine:'.999',oz:'1.00000'},
  {cat:'World Silver',metal:'silver',name:'British Silver Britannia — 1 oz',wt:31.10,dia:38.6,fine:'.999',oz:'1.00000'},
  {cat:'World Silver',metal:'silver',name:'Chinese Silver Panda — 30g (2016–present)',wt:30.00,dia:40.0,fine:'.999',oz:'0.96450'},
  {cat:'World Silver',metal:'silver',name:'Australian Silver Kookaburra — 1 oz',wt:31.10,dia:40.6,fine:'.999',oz:'1.00000'},
  {cat:'World Silver',metal:'silver',name:'Mexican Silver Libertad — 1 oz',wt:31.10,dia:40.0,fine:'.999',oz:'1.00000'},
  {cat:'World Silver',metal:'silver',name:'South African Silver Krugerrand — 1 oz',wt:31.10,dia:38.7,fine:'.999',oz:'1.00000'},
];

function renderCoinSpecs(){
  const q=($('cs-search').value||'').toLowerCase();
  const metal=$('cs-metal').value;
  const cat=$('cs-cat').value;
  let rows=COIN_SPECS.filter(c=>{
    if(metal&&c.metal!==metal)return false;
    if(cat&&c.cat!==cat)return false;
    if(q&&!c.name.toLowerCase().includes(q))return false;
    return true;
  });
  const cats=[...new Set(rows.map(r=>r.cat))];
  const catOrder=['US Silver','US Gold Historic','US Gold Modern','World Gold','World Silver'];
  cats.sort((a,b)=>catOrder.indexOf(a)-catOrder.indexOf(b));
  const catColors={
    'US Silver':'#1e40af','US Gold Historic':'#92400e','US Gold Modern':'#b45309',
    'World Gold':'#065f46','World Silver':'#4c1d95'
  };
  const metalIcon={gold:'🥇',silver:'🥈'};
  let html='';
  if(!rows.length){html='<div class="card" style="text-align:center;color:var(--muted);padding:32px">No coins match your search.</div>';}
  else{
    cats.forEach(c=>{
      const group=rows.filter(r=>r.cat===c);
      const col=catColors[c]||'#1a3a5c';
      html+=`<div class="card" style="margin-bottom:13px;overflow:hidden">
        <div style="background:${col};color:#fff;padding:8px 14px;margin:-14px -14px 12px;font-weight:700;font-size:12px;letter-spacing:.5px;text-transform:uppercase">${c}</div>
        <div class="tbl-wrap">
        <table class="dtable">
          <thead><tr>
            <th>Coin</th>
            <th style="text-align:right">Weight (g)</th>
            <th style="text-align:right">Diameter (mm)</th>
            <th style="text-align:right">Fineness</th>
            <th style="text-align:right">Pure ${group[0].metal==='gold'?'Gold':'Silver'} (troy oz)</th>
          </tr></thead>
          <tbody>`;
      group.forEach(r=>{
        html+=`<tr>
          <td><span style="margin-right:5px">${metalIcon[r.metal]}</span>${r.name}</td>
          <td style="text-align:right;font-family:monospace;font-weight:600">${r.wt.toFixed(2)}</td>
          <td style="text-align:right;font-family:monospace">${r.dia.toFixed(1)}</td>
          <td style="text-align:right;font-family:monospace">${r.fine}</td>
          <td style="text-align:right;font-family:monospace;font-weight:700;color:${r.metal==='gold'?'var(--gold2)':'var(--muted)'}">${r.oz}</td>
        </tr>`;
      });
      html+=`</tbody></table></div></div>`;
    });
  }
  $('cs-tbody-wrap').innerHTML=html;
}
function renderNmGrading(){const grades=[['PO-1','Poor','Barely identifiable, heavily worn'],['FR-2','Fair','Extremely worn, some design visible'],['AG-3','About Good','Very heavily worn, outline visible'],['G-4','Good','Heavily worn, major design clear'],['G-6','Good+','Slightly more detail than G-4'],['VG-8','Very Good','Well worn, main features clear'],['VG-10','Very Good+','More detail than VG-8'],['F-12','Fine','Moderate to considerable even wear'],['F-15','Fine+','More detail than F-12'],['VF-20','Very Fine','Moderate wear on high points'],['VF-25','Very Fine+','Slightly less wear than VF-30'],['VF-30','Choice Very Fine','Light wear on high points'],['VF-35','Choice VF+','Very light wear on highest points'],['EF-40','Extremely Fine','Light wear throughout'],['EF-45','Choice EF','Slight wear on highest points'],['AU-50','About Uncirculated','Slight wear on high points, half luster'],['AU-55','Choice AU','Slight wear, most luster'],['AU-58','Very Choice AU','Minimal wear, nearly full luster'],['MS-60','Mint State','No wear, many contact marks'],['MS-61','MS61','No wear, noticeable marks'],['MS-62','MS62','No wear, some distracting marks'],['MS-63','Choice BU','No wear, some noticeable marks'],['MS-64','Choice BU+','No wear, few marks'],['MS-65','Gem BU','No wear, strong luster, minor marks'],['MS-66','Gem BU+','No wear, superior luster, very minor marks'],['MS-67','Superb Gem','Virtually perfect, exceptional'],['MS-68','Superb Gem+','Nearly perfect coin'],['MS-69','MS69','Nearly perfect, only tiny imperfections'],['MS-70','Perfect','Absolutely perfect coin']];const tb=document.getElementById('nm-grade-tbody');if(tb)tb.innerHTML=grades.map(([g,n,d])=>`<tr><td style="font-weight:700;color:var(--gold)">${g}</td><td>${n}</td><td>${d}</td></tr>`).join('');}

function renderNmCoinVals(){
  // Uses CV[] which is defined inline in app.html
  const combined=typeof CV!=='undefined'?CV:[];
  const search=(document.getElementById('nm-cv-search')||{}).value||'';
  const series=(document.getElementById('nm-cv-series')||{}).value||'';
  // Populate series dropdown if empty
  const selEl=document.getElementById('nm-cv-series');
  if(selEl && selEl.options.length<=1 && combined.length){
    [...new Set(combined.map(c=>c.s))].forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;selEl.appendChild(o);});
  }
  const filtered=combined.filter(r=>{
    const s=search.toLowerCase();
    const matchSearch=!s||(r.s+r.d).toLowerCase().includes(s);
    const matchSeries=!series||r.s===series;
    return matchSearch&&matchSeries;
  });
  const tb=document.getElementById('nm-cv-tbody');
  if(!tb)return;
  if(!combined.length){tb.innerHTML='<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:20px">Coin value data loading...</td></tr>';return;}
  const grades=['G4','VG8','F12','VF20','EF40','AU50','MS63','MS65'];
  tb.innerHTML=filtered.length?filtered.slice(0,300).map(r=>`<tr><td>${r.s}</td><td style="font-weight:700">${r.d}</td>${grades.map(g=>`<td>${r[g]?'$'+r[g].toLocaleString():'—'}</td>`).join('')}</tr>`).join(''):'<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:20px">No results found</td></tr>';
}
function renderAllKeyDates(){
  const allKD=[
    // Indian Head Cents
    {date:'1877',series:'Indian Head',notes:'Lowest mintage Indian Head cent',rarity:'Key Date',value:'$500–$2,000+'},
    {date:'1909-S',series:'Indian Head',notes:'Last year San Francisco Indian Head',rarity:'Key Date',value:'$250–$1,000+'},
    {date:'1864-L',series:'Indian Head',notes:'Designer initial L on ribbon',rarity:'Semi-Key',value:'$100–$400+'},
    // Lincoln Cents
    {date:'1909-S VDB',series:'Lincoln Cent',notes:'Lowest mintage major Lincoln variety',rarity:'Key Date',value:'$700–$2,500+'},
    {date:'1909-S',series:'Lincoln Cent',notes:'First year San Francisco Lincoln',rarity:'Key Date',value:'$100–$500+'},
    {date:'1914-D',series:'Lincoln Cent',notes:'Scarce Denver mint issue',rarity:'Key Date',value:'$200–$1,500+'},
    {date:'1922 Plain',series:'Lincoln Cent',notes:'Missing D mintmark variety',rarity:'Key Date',value:'$500–$2,500+'},
    {date:'1931-S',series:'Lincoln Cent',notes:'Low mintage Depression era cent',rarity:'Key Date',value:'$75–$300+'},
    {date:'1955 DDO',series:'Lincoln Cent',notes:'Dramatic doubled die obverse',rarity:'Major Rarity',value:'$500–$1,500+'},
    {date:'1943 Copper',series:'Lincoln Cent',notes:'Struck on wrong planchet — extremely rare',rarity:'Major Rarity',value:'$100,000+'},
    // Buffalo Nickels
    {date:'1913-S T2',series:'Buffalo Nickel',notes:'Type 2 flat ground first year SF',rarity:'Key Date',value:'$200–$1,000+'},
    {date:'1916 DDO',series:'Buffalo Nickel',notes:'Doubled die obverse variety',rarity:'Semi-Key',value:'$300–$2,000+'},
    {date:'1918/7-D',series:'Buffalo Nickel',notes:'Overdate — rare in all grades',rarity:'Key Date',value:'$500–$5,000+'},
    {date:'1921-S',series:'Buffalo Nickel',notes:'Low mintage San Francisco issue',rarity:'Key Date',value:'$100–$800+'},
    {date:'1926-S',series:'Buffalo Nickel',notes:'Scarce late series SF nickel',rarity:'Key Date',value:'$150–$1,000+'},
    {date:'1937-D 3-Leg',series:'Buffalo Nickel',notes:'Missing buffalo front leg — die error',rarity:'Semi-Key',value:'$500–$3,000+'},
    // Mercury Dimes
    {date:'1916-D',series:'Mercury Dime',notes:'Lowest mintage Mercury dime — key date',rarity:'Key Date',value:'$800–$5,000+'},
    {date:'1921',series:'Mercury Dime',notes:'Low mintage post-WWI year',rarity:'Key Date',value:'$50–$400+'},
    {date:'1921-D',series:'Mercury Dime',notes:'Denver low mintage',rarity:'Key Date',value:'$75–$500+'},
    {date:'1942/1',series:'Mercury Dime',notes:'Overdate — Philly mint',rarity:'Major Rarity',value:'$500–$3,000+'},
    {date:'1942/1-D',series:'Mercury Dime',notes:'Overdate — Denver mint',rarity:'Major Rarity',value:'$700–$5,000+'},
    // Standing Liberty Quarters
    {date:'1916',series:'Standing Liberty',notes:'First year — very low mintage',rarity:'Key Date',value:'$3,000–$20,000+'},
    {date:'1918/7-S',series:'Standing Liberty',notes:'Overdate — rare San Francisco variety',rarity:'Major Rarity',value:'$2,000–$15,000+'},
    {date:'1921',series:'Standing Liberty',notes:'Low mintage post-WWI quarter',rarity:'Key Date',value:'$300–$2,000+'},
    {date:'1923-S',series:'Standing Liberty',notes:'Scarce San Francisco issue',rarity:'Key Date',value:'$200–$1,500+'},
    {date:'1927-S',series:'Standing Liberty',notes:'Low mintage San Francisco quarter',rarity:'Key Date',value:'$150–$1,000+'},
    // Walking Liberty Halves
    {date:'1916',series:'Walking Liberty',notes:'First year — scarce Philly issue',rarity:'Semi-Key',value:'$100–$600+'},
    {date:'1916-S Obv',series:'Walking Liberty',notes:'Mintmark on obverse — first year only',rarity:'Semi-Key',value:'$100–$800+'},
    {date:'1921',series:'Walking Liberty',notes:'Key date low mintage half',rarity:'Key Date',value:'$200–$1,500+'},
    {date:'1921-D',series:'Walking Liberty',notes:'Denver key date',rarity:'Key Date',value:'$200–$1,500+'},
    {date:'1921-S',series:'Walking Liberty',notes:'SF key date',rarity:'Key Date',value:'$250–$2,000+'},
    {date:'1938-D',series:'Walking Liberty',notes:'Low mintage final year Denver',rarity:'Semi-Key',value:'$50–$400+'},
    // Morgan Dollars
    {date:'1893-S',series:'Morgan',notes:'Rarest business strike Morgan',rarity:'Key Date',value:'$5,000–$100,000+'},
    {date:'1895',series:'Morgan',notes:'Proof only — no business strikes known',rarity:'Major Rarity',value:'$50,000+'},
    {date:'1889-CC',series:'Morgan',notes:'Rare Carson City Morgan',rarity:'Key Date',value:'$1,000–$10,000+'},
    {date:'1879-CC',series:'Morgan',notes:'Scarce first year Carson City',rarity:'Semi-Key',value:'$500–$5,000+'},
    {date:'1921',series:'Morgan',notes:'Final year — common but historically significant',rarity:'Semi-Key',value:'$25–$75+'},
    // Peace Dollars
    {date:'1921',series:'Peace',notes:'First year high relief — scarce',rarity:'Key Date',value:'$100–$700+'},
    {date:'1928',series:'Peace',notes:'Lowest mintage Philadelphia Peace dollar',rarity:'Key Date',value:'$200–$1,500+'},
    {date:'1934-S',series:'Peace',notes:'Scarce San Francisco issue',rarity:'Semi-Key',value:'$75–$500+'},
    {date:'1935-S',series:'Peace',notes:'Final year San Francisco Peace dollar',rarity:'Semi-Key',value:'$50–$300+'},
    // Saint-Gaudens
    {date:'1907 HR',series:'Saint-Gaudens',notes:'First year Ultra High Relief — rare',rarity:'Major Rarity',value:'$15,000–$50,000+'},
    {date:'1927-D',series:'Saint-Gaudens',notes:'Very rare Denver gold double eagle',rarity:'Key Date',value:'$10,000–$50,000+'},
    {date:'1933',series:'Saint-Gaudens',notes:'Recalled by govt — illegal to own most',rarity:'Major Rarity',value:'$millions'},
  ];
  const search=(document.getElementById('nm-kd-search')||{}).value||'';
  const series=(document.getElementById('nm-kd-series')||{}).value||'';
  const rarity=(document.getElementById('nm-kd-rarity')||{}).value||'';
  const filtered=allKD.filter(r=>{
    const s=search.toLowerCase();
    const matchSearch=!s||(r.date+r.series+r.notes).toLowerCase().includes(s);
    const matchSeries=!series||r.series.includes(series);
    const matchRarity=!rarity||r.rarity===rarity;
    return matchSearch&&matchSeries&&matchRarity;
  });
  const rarityColor={['Key Date']:'var(--red)',['Semi-Key']:'var(--gold)',['Major Rarity']:'#c084fc'};
  const tb=document.getElementById('nm-kd-tbody');
  if(tb)tb.innerHTML=filtered.length?filtered.map(r=>`<tr><td style="font-weight:700">${r.date}</td><td>${r.series}</td><td>${r.notes}</td><td><span style="color:${rarityColor[r.rarity]||'var(--text)'};font-weight:600">${r.rarity}</span></td><td class="green-col">${r.value}</td></tr>`).join(''):'<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No results found</td></tr>';
}
function dealType(t,btn){
  document.querySelectorAll('#ss-calc .seg-group .seg').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  ['coins','bullion','rolls'].forEach(p=>{const el=$('deal-panel-'+p);if(el)el.style.display=p===t?'':'none';});
  const agVal=spot.XAG?spot.XAG.toFixed(2):'32.45';
  if(t==='bullion'){
    const bs=$('deal-bul-spot');if(bs&&(!bs.value||parseFloat(bs.value)===32.45||parseFloat(bs.value)===0))bs.value=agVal;
    calcDealBullion();
  } else if(t==='rolls'){
    const rs=$('deal-roll-spot');if(rs&&(!rs.value||parseFloat(rs.value)===32.45||parseFloat(rs.value)===0))rs.value=agVal;
    calcDealRolls();
  }
}
let goldWUnit='g';
function goldUnit(u,btn){goldWUnit=u;document.querySelectorAll('.calc-hdr .seg-group .seg').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');calcGold();}
function adjustPad(){const h=$('header');const tb=$('tab-bar');if(!h||!tb)return;const off=h.offsetHeight+tb.offsetHeight;$('content').style.paddingTop=off+'px';$('tab-bar').style.top=h.offsetHeight+'px';}
window.addEventListener('load',adjustPad);window.addEventListener('resize',adjustPad);window.addEventListener('orientationchange',function(){setTimeout(adjustPad,300);});

// ═══ GOLD CALC ═══
function calcGold(){
  // Free usage limit (skip for Pro/Admin)
  if(!window_isPro){
    let used=parseInt(localStorage.getItem('bdp-karat-used')||'0');
    if(used>=5){
      const nb=$('karat-limit-nudge');if(nb)nb.style.display='block';
      return;
    }
    used++;
    localStorage.setItem('bdp-karat-used',used);
    const nb=$('karat-limit-nudge');
    if(nb){
      if(used>=5)nb.style.display='block';
      else nb.style.display='none';
    }
    const hint=$('karat-uses-hint');
    if(hint)hint.textContent=used<5?'ℹ Free: '+(5-used)+' calculations remaining':'';
  } else {
    // Pro/Admin — hide any limit nudge
    const nb=$('karat-limit-nudge');if(nb)nb.style.display='none';
    const hint=$('karat-uses-hint');if(hint)hint.textContent='';
  }
  const k=parseInt($('gk-karat').value||'14');const p=k/24;
  let w=parseFloat($('gk-weight').value)||0;
  const spOz=parseFloat($('gk-spot').value)||spot.XAU||0;
  const pct=parseFloat($('gk-pct').value)||30;
  const spg=spOz/31.1035;
  if(goldWUnit==='oz')w*=31.1035;else if(goldWUnit==='gr')w*=0.06479891;else if(goldWUnit==='dwt')w*=1.55517;
  const pureG=w*p;const melt=pureG*spg;const offer=melt*(1-pct/100);
  if($('gk-melt'))$('gk-melt').textContent=fmt(melt);
  if($('gk-offer'))$('gk-offer').textContent=fmt(offer);
  if($('gk-pure'))$('gk-pure').textContent=pureG.toFixed(3)+'g';
  if($('gk-pgram'))$('gk-pgram').textContent=fmt(spg*p);
  if($('gk-pgrain'))$('gk-pgrain').textContent=fmt(spg*p*0.06479891);
  if($('gk-pdwt'))$('gk-pdwt').textContent=fmt(spg*p*1.55517);
}
function renderKaratTable(){
  const spOz=spot.XAU||0;const spg=spOz/31.1035;
  const tb=$('karat-tbody');if(!tb)return;
  tb.innerHTML=[[24,24/24],[22,22/24],[18,18/24],[14,14/24],[10,10/24],[9,9/24]].map(([k,p])=>`<tr><td class="k-col">${k}k</td><td class="p-col">${(p*100).toFixed(1)}%</td><td class="price-col rv-gold">${fmt(spg*p)}</td><td class="green-col">${fmt(spg*p*0.70)}</td><td class="price-col">${fmt(spg*p*31.1035)}</td><td class="p-col">${fmt(spg*p*0.06479891)}</td></tr>`).join('');
}

// ═══ GOLDBACKS ═══
const GB=[
  {name:'Goldback Inc.',tag:'Official',url:'https://www.goldback.com/shop/'},
  {name:'Defy The Grid',tag:'Specialty',url:'https://defythegrid.com/collections/goldbacks'},
  {name:'Finest Known',tag:'Specialty',url:'https://finestknown.com/goldbacks-for-sale/'},
  {name:'APMEX',tag:'Large Selection',url:'https://www.apmex.com/category/19605/goldbacks'},
  {name:'JM Bullion',tag:'Fast Shipping',url:'https://www.jmbullion.com/gold/gold-notes/goldbacks/'},
  {name:'Money Metals',tag:'Competitive',url:'https://www.moneymetals.com/goldbacks'},
  {name:'Scottsdale Bullion',tag:'Quality Stock',url:'https://www.scottsdalebullion.com/goldbacks/'},
  {name:'Bold Precious Metals',tag:'Value Priced',url:'https://boldpreciousmetals.com/collections/goldbacks'},
  {name:'Gainesville Coins',tag:'Dealer',url:'https://www.gainesvillecoins.com/goldbacks'},
];
const GB_DENOMS=[{d:'1 (1/1000 oz)',n:'1'},{d:'5 (1/500 oz)',n:'5'},{d:'10 (1/200 oz)',n:'10'},{d:'25 (1/100 oz)',n:'25'},{d:'50 (1/50 oz)',n:'50'}];
let gbRates={};
async function renderGoldback(){
  const au = spot.XAU || 4500;
  const PREMIUM = 1.94; // spot × 94% premium = typical dealer purchase price
  const denoms = [
    {n:0.25, label:'¼ Goldback',  oz:0.00025},
    {n:0.5,  label:'½ Goldback',  oz:0.0005 },
    {n:1,    label:'1 Goldback',  oz:0.001  },
    {n:2,    label:'2 Goldback',  oz:0.002  },
    {n:5,    label:'5 Goldback',  oz:0.005  },
    {n:10,   label:'10 Goldback', oz:0.010  },
    {n:25,   label:'25 Goldback', oz:0.025  },
    {n:50,   label:'50 Goldback', oz:0.050  },
    {n:100,  label:'100 Goldback',oz:0.100  },
  ];

  const upd = $('gb-updated');
  if(upd) upd.innerHTML = 'Live gold $'+au.toFixed(2)+'/oz &nbsp;·&nbsp; Buy price &asymp; spot &times; 1.94 (spot + 94% &mdash; typical dealer purchase rate) &nbsp;·&nbsp; <a href="https://www.goldback.com/exchange-rates/" target="_blank" style="color:var(--blue)">Official rates &#8599;</a>';

  const denomCards = $('gb-denom-cards');
  if(denomCards){
    const cardSet = denoms.filter(d => [1,5,10,25,50].includes(d.n));
    denomCards.innerHTML = cardSet.map(d => {
      const sv = au * d.oz; const mv = sv * PREMIUM;
      return '<div style="background:linear-gradient(135deg,#78350f22,#d9770622);border:1px solid #d97706;border-radius:10px;padding:14px;text-align:center"><div style="font-size:15px;font-weight:800;color:var(--gold)">'+d.label+'</div><div style="font-size:11px;color:var(--muted);margin:3px 0">'+d.oz.toFixed(4)+' oz gold</div><div style="font-size:18px;font-weight:800;color:var(--gold)">$'+mv.toFixed(2)+'</div><div style="font-size:10px;color:var(--muted)">spot $'+sv.toFixed(3)+'</div></div>';
    }).join('');
  }

  const denomTbody = $('gb-denom-tbody');
  if(denomTbody){
    denomTbody.innerHTML = denoms.map(d => {
      const sv = au * d.oz; const mv = sv * PREMIUM;
      return '<tr><td style="font-weight:700;color:var(--gold)">'+d.label+'</td><td class="p-col">'+d.oz.toFixed(4)+'</td><td style="color:var(--muted);">$'+sv.toFixed(3)+'</td><td style="font-weight:800;color:var(--gold)">$'+mv.toFixed(2)+'</td><td style="color:var(--green);font-weight:600">+25%</td></tr>';
    }).join('');
  }

  const c = $('gb-retailers'); if(!c) return;
  c.innerHTML = GB.map((r,i) => '<div class="gb-retailer" id="gbr-'+i+'"><div class="gb-hdr" onclick="gbToggle('+i+')"><span class="gb-name">'+r.name+'</span><span style="font-size:10px;font-weight:700;color:var(--muted);background:var(--bg3);padding:2px 8px;border-radius:8px">'+r.tag+'</span><span class="gb-arrow">&#9660;</span></div><div class="gb-body"><table class="gb-tbl"><thead><tr><th>Denomination</th><th>Gold oz</th><th>Spot Value</th><th>Market Est.</th></tr></thead><tbody>'+denoms.map(d=>{const sv=au*d.oz;const mv=sv*PREMIUM;return '<tr><td>'+d.label+'</td><td>'+d.oz.toFixed(4)+'</td><td style="color:var(--muted)">$'+sv.toFixed(3)+'</td><td style="color:var(--gold);font-weight:700">$'+mv.toFixed(2)+'</td></tr>';}).join('')+'</tbody></table><div style="font-size:11px;color:var(--muted);margin:6px 0 10px">Prices vary by retailer. Click to browse current inventory.</div><a href="'+r.url+'" target="_blank" class="gb-shop">Shop '+r.name+' &#8599;</a></div></div>').join('');
}

function gbToggle(i){const e=$('gbr-'+i);if(e)e.classList.toggle('open');}

// ═══ SILVER DEAL CALC ═══
function calcDeal(){
  if(!$('deal-face'))return;
  const face=parseFloat($('deal-face').value)||100;
  const ag=parseFloat($('deal-spot').value)||spot.XAG||32.45;
  const bp=parseFloat($('deal-buy-pct').value)||20;
  const sp=parseFloat($('deal-sell-pct').value)||5;
  const oz=face*0.7234;const melt=oz*ag;
  $('deal-oz').textContent=oz.toFixed(3)+' oz';
  $('deal-melt').textContent=fmt(melt);
  $('deal-buy').textContent=fmt(melt*(1-bp/100));
  $('deal-sell').textContent=fmt(melt*(1+sp/100));
}
function calcDealBullion(){
  if(!$('deal-bul-oz'))return;
  const oz=parseFloat($('deal-bul-oz').value)||1;
  const ag=parseFloat($('deal-bul-spot').value)||spot.XAG||32.45;
  const bp=parseFloat($('deal-bul-buy-pct').value)||5;
  const sp=parseFloat($('deal-bul-sell-pct').value)||3;
  const melt=oz*ag;
  $('deal-bul-melt').textContent=fmt(melt);
  $('deal-bul-buy').textContent=fmt(melt*(1-bp/100));
  $('deal-bul-sell').textContent=fmt(melt*(1+sp/100));
}
function calcDealRolls(){
  if(!$('deal-roll-type'))return;
  const t=$('deal-roll-type').value||'half';
  const n=parseInt($('deal-roll-count').value)||1;
  const ag=parseFloat($('deal-roll-spot').value)||spot.XAG||32.45;
  const p=parseFloat($('deal-roll-pct').value)||20;
  const oz=ROLL_OZ[t]*n;const melt=oz*ag;
  $('deal-roll-oz').textContent=oz.toFixed(3)+' oz';
  $('deal-roll-melt').textContent=fmt(melt);
  $('deal-roll-buy').textContent=fmt(melt*(1-p/100));
}
function renderSilverMeltTable(){
  const ag=spot.XAG||32.45;
  const coins=[{n:'Dime (pre-1965)',oz:0.07234},{n:'Quarter (pre-1965)',oz:0.18084},{n:'Half (pre-1965)',oz:0.36169},{n:'Morgan Dollar',oz:0.77344},{n:'Peace Dollar',oz:0.77344},{n:'1 oz Silver Eagle',oz:1.0},{n:'10 oz Bar',oz:10},{n:'100 oz Bar',oz:100}];
  const tb=$('silver-melt-tbody');if(!tb)return;
  tb.innerHTML=coins.map(c=>`<tr><td style="font-weight:600">${c.n}</td><td class="p-col">${c.oz.toFixed(5)}</td><td class="rv-gold price-col">${fmt(c.oz*ag)}</td><td class="green-col">${fmt(c.oz*ag*.80)}</td><td class="p-col">${fmt(c.oz*ag*.70)}</td></tr>`).join('');
}

// ═══ PREMIUMS ═══
function renderPremiums(){
  const ag=spot.XAG||32.45;
  // AFFILIATE LINKS: Replace each url with your affiliate tracking URL once approved.
  // APMEX: Apply at cj.com (search APMEX) — replace url with your CJ tracking link
  // JM Bullion: Apply at shareasale.com (merchant #40365) — replace url with your ShareASale link
  // SD Bullion: Apply at shareasale.com (merchant #68436) — replace url with your ShareASale link
  // Money Metals: Apply at moneymetals.com/affiliate — replace url with your tracking link
  // Gainesville Coins: Apply at shareasale.com — replace url with your ShareASale link
  // BGASC: Apply at shareasale.com — replace url with your ShareASale link
  // Golden Eagle Coins: Apply at shareasale.com — replace url with your ShareASale link
  // Scottsdale Bullion & Coin: Apply at cj.com — replace url with your CJ link
  // Hero Bullion: Apply at shareasale.com — replace url with your ShareASale link
  // Bullion Exchanges: Apply at shareasale.com — replace url with your ShareASale link
  // Westminster Mint: Apply at shareasale.com — replace url with your ShareASale link
  const dealers=[
    {name:'APMEX',url:'https://www.apmex.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.99,b:ag+2.49,c:ag+1.99},
    {name:'JM Bullion',url:'https://www.jmbullion.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.49,b:ag+2.29,c:ag+1.89},
    {name:'SD Bullion',url:'https://sdbullion.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+2.99,b:ag+2.19,c:ag+1.79},
    {name:'Money Metals',url:'https://www.moneymetals.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.59,b:ag+2.59,c:ag+2.09},
    {name:'Gainesville',url:'https://www.gainesvillecoins.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.19,b:ag+2.09,c:ag+1.69},
    {name:'BGASC',url:'https://www.bgasc.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+2.89,b:ag+1.99,c:ag+1.59},
    {name:'Golden Eagle',url:'https://www.goldeneaglecoin.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.49,b:ag+2.39,c:ag+1.99},
    {name:'Scottsdale B&C',url:'https://www.scottsdalebullion.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.79,b:ag+2.69,c:ag+2.19},
    {name:'Hero Bullion',url:'https://www.herobullion.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+2.99,b:ag+2.09,c:ag+1.79},
    {name:'Bullion Exch.',url:'https://bullionexchanges.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.29,b:ag+2.29,c:ag+1.89},
    {name:'Westminster',url:'https://www.westminstermint.com/?utm_source=bulliondealerpro&utm_medium=referral&utm_campaign=premiums',a:ag+3.99,b:ag+2.79,c:ag+2.29}
  ];
  const cont=$('premiums-container');if(!cont)return;
  cont.innerHTML=`<div class="card"><div class="card-title">🏪 Dealer Silver Premiums <small style="font-weight:400;color:var(--muted);font-size:11px">vs Spot $${ag.toFixed(2)}</small></div><div class="tbl-wrap"><table class="dtable"><thead><tr><th>Dealer</th><th>1 oz ASE</th><th>10 oz Bar</th><th>100 oz Bar</th><th>1 oz Premium</th><th></th></tr></thead><tbody>${dealers.map(d=>`<tr><td style="font-weight:700">${d.name}</td><td class="rv-gold price-col">${fmt(d.a)}</td><td class="price-col">${fmt(d.b)}</td><td class="price-col">${fmt(d.c)}</td><td class="p-col">+${fmt(d.a-ag)}</td><td><a href="${d.url}" target="_blank" rel="sponsored noopener" style="color:var(--blue);font-size:11px;font-weight:600">Shop ↗</a></td></tr>`).join('')}</tbody></table></div><p style="font-size:11px;color:var(--muted);margin-top:9px">⚠ Premiums are estimates — click dealer links for current pricing.</p></div>`;
}

// ═══ ROLLS ═══
const ROLL_OZ={dime:50*0.07234,quarter:40*0.18084,half:20*0.36169,dollar:20*0.77344};
function calcRolls(){
  const t=$('roll-type').value||'half';const n=parseInt($('roll-count').value)||1;
  const ag=parseFloat($('roll-spot').value)||spot.XAG||32.45;const p=parseFloat($('roll-pct').value)||20;
  const oz=ROLL_OZ[t]*n;const melt=oz*ag;
  $('roll-oz').textContent=oz.toFixed(3)+' oz';$('roll-melt').textContent=fmt(melt);$('roll-buy').textContent=fmt(melt*(1-p/100));
}

// ═══ PLAT/PAL ═══
function calcPlatPal(){
  if(!$('pt-weight'))return;
  const ptW=parseFloat($('pt-weight').value)||5;const ptP=parseFloat($('pt-pct').value)||25;
  const pdW=parseFloat($('pd-weight').value)||5;const pdP=parseFloat($('pd-pct').value)||25;
  const ptSp=spot.XPT||1089;const pdSp=spot.XPD||1012;
  const spgPt=ptSp/31.1035;const spgPd=pdSp/31.1035;
  $('pt-spot-disp').textContent=fmt(ptSp);$('pd-spot-disp').textContent=fmt(pdSp);
  $('pt-offer').textContent=fmt(ptW*spgPt*(1-ptP/100));$('pd-offer').textContent=fmt(pdW*spgPd*(1-pdP/100));
}

// ═══ CONSTITUTIONAL ═══
const CONST_OZ={
  dime_90:0.07234, quarter_90:0.18084, half_90:0.36169,
  dollar_90:0.77344, dollar_seated:0.77344, dollar_trade:0.78737,
  half_40:0.14792, half_40_70d:0.14792,
  nickel_35:0.05626,
  ike_40:0.31570
};
const CONST_ROLL_OZ={
  dime_90_r:{oz:3.617,coins:50,label:'Dimes 90%'},
  quarter_90_r:{oz:7.234,coins:40,label:'Quarters 90%'},
  half_90_r:{oz:7.234,coins:20,label:'Halves 90%'},
  dollar_90_r:{oz:15.469,coins:20,label:'Morgan/Peace 90%'},
  half_40_r:{oz:2.958,coins:20,label:'Kennedy Halves 40%'},
  nickel_35_r:{oz:2.250,coins:40,label:'War Nickels 35%'},
  ike_40_r:{oz:6.314,coins:20,label:'Ike Dollars 40%'}
};
function calcConst(){
  if(!$('const-type'))return;
  const t=$('const-type').value||'half_90';const q=parseFloat($('const-qty').value)||1;
  const ag=parseFloat($('const-spot').value)||spot.XAG||32.45;const p=parseFloat($('const-pct').value)||20;
  var sp=parseFloat($('const-sell-pct').value);if(isNaN(sp))sp=10;
  const oze=CONST_OZ[t]||0.36169;const oz=oze*q;const melt=oz*ag;
  $('const-oz').textContent=oz.toFixed(4)+' oz';$('const-melt').textContent=fmt(melt);
  $('const-buy').textContent=fmt(melt*(1-p/100));$('const-sell').textContent=fmt(melt*(1+sp/100));
  $('const-percoin').textContent=fmt(oze*ag);
}
function calcConstRolls(){
  const t=($('const-roll-type')||{}).value||'half_90_r';
  const rc=parseFloat(($('const-roll-count')||{}).value)||1;
  const ag=parseFloat(($('const-roll-spot')||{}).value)||spot.XAG||32.45;
  const p=parseFloat(($('const-roll-pct')||{}).value)||20;
  const rd=CONST_ROLL_OZ[t]||{oz:7.234,coins:20};
  const totalOz=rd.oz*rc;const melt=totalOz*ag;
  const buy=melt*(1-p/100);const perRoll=melt/rc;
  if($('cr-oz'))$('cr-oz').textContent=totalOz.toFixed(3)+' oz';
  if($('cr-melt'))$('cr-melt').textContent=fmt(melt);
  if($('cr-buy'))$('cr-buy').textContent=fmt(buy);
  if($('cr-perroll'))$('cr-perroll').textContent=fmt(perRoll);
}
function renderConstRef(){
  const ag=spot.XAG||32.45;
  const coins=[
    {n:'Dime — 90%',comp:'90% Ag',oz:0.07234,face:0.10},
    {n:'Quarter — 90%',comp:'90% Ag',oz:0.18084,face:0.25},
    {n:'Half Dollar — 90%',comp:'90% Ag',oz:0.36169,face:0.50},
    {n:'Morgan/Peace Dollar — 90%',comp:'90% Ag',oz:0.77344,face:1.00},
    {n:'Trade Dollar — 90%',comp:'90% Ag',oz:0.78737,face:1.00},
    {n:'Kennedy Half 1965–69 — 40%',comp:'40% Ag',oz:0.14792,face:0.50},
    {n:'Kennedy Half 1970-D — 40%',comp:'40% Ag',oz:0.14792,face:0.50},
    {n:'War Nickel 1942–45 — 35%',comp:'35% Ag',oz:0.05626,face:0.05},
    {n:'Ike Dollar 1971–76 — 40%',comp:'40% Ag',oz:0.31570,face:1.00},
  ];
  const tb=$('const-ref-tbody');if(!tb)return;
  tb.innerHTML=coins.map(c=>`<tr><td style="font-weight:600">${c.n}</td><td style="color:var(--muted)">${c.comp}</td><td class="p-col">${c.oz.toFixed(5)} oz</td><td class="rv-gold price-col">${fmt(c.oz*ag)}</td><td class="green-col">${fmt((100/c.face)*c.oz*ag)}</td></tr>`).join('');
}
function renderConstRefTable(){
  const ag=spot.XAG||32.45;
  const coins=[{n:'Dime',oz:0.07234,face:0.10},{n:'Quarter',oz:0.18084,face:0.25},{n:'Half Dollar',oz:0.36169,face:0.50},{n:'Morgan Dollar',oz:0.77344,face:1.00},{n:'Peace Dollar',oz:0.77344,face:1.00}];
  const tb=$('const-ref-tbody');if(!tb)return;
  tb.innerHTML=coins.map(c=>`<tr><td style="font-weight:600">${c.n}</td><td class="p-col">${c.oz.toFixed(5)} oz</td><td class="rv-gold price-col">${fmt(c.oz*ag)}</td><td class="green-col">${fmt((100/c.face)*c.oz*ag)}</td></tr>`).join('');
}
function renderConstKeyDates(){
  const rows=KD_DATA.filter(k=>['Mercury Dime','SL Quarter','WL Half','Morgan Dollar','Peace Dollar'].includes(k.c));
  const tb=$('const-kd-tbody');if(!tb)return;
  tb.innerHTML=rows.map(k=>`<tr><td style="font-weight:600">${k.c}</td><td>${k.y}</td><td><span class="kd-badge kd-${k.r}">${k.r}</span></td><td class="green-col">${k.v}</td></tr>`).join('');
}

// ═══ PENNIES ═══
let pennyUnitMode='count';
function pennyUnit(u,btn){
  pennyUnitMode=u;
  document.querySelectorAll('#tab-pennies .calc-hdr .seg').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  const labels={count:'Quantity (coins)',g:'Weight (grams)',oz:'Weight (troy oz)',gr:'Weight (grains)',dwt:'Weight (DWT)',lb:'Weight (pounds)'};
  const lbl=$('penny-qty-label');if(lbl)lbl.textContent=labels[u]||'Amount';
  const defaults={count:100,g:311,oz:10,gr:4822,dwt:200,lb:0.686};
  const inp=$('penny-qty');
  if(inp){inp.value=defaults[u];inp.dataset.lastDefault=defaults[u];}
  calcPenny();
}
function calcPenny(){
  if(!$('penny-type'))return;
  const t=$('penny-type').value||'copper';
  const cu=parseFloat($('penny-cu').value)||spot.HG||4.68;
  const zn=parseFloat($('penny-zn').value)||spot.ZN||1.30;
  const wtMap={'copper':3.11,'modern':2.5,'wartime':2.7,'round1oz':31.1035,'round5oz':155.517,'bar1lb':453.592,'bar10oz':283.495};
  const coinWt=wtMap[t]||3.11;
  // purity map: copper content fraction
  const purMap={'copper':0.95,'modern':0.025,'wartime':0.0,'round1oz':0.999,'round5oz':0.999,'bar1lb':0.999,'bar10oz':0.999};
  const znPurMap={'copper':0.05,'modern':0.975,'wartime':0.0,'round1oz':0.001,'round5oz':0.001,'bar1lb':0.001,'bar10oz':0.001};
  const cuPur=purMap[t]||0.95; const znPur=znPurMap[t]||0.05;
  let m=(cu*0.00220462262*coinWt*cuPur)+(zn*0.00220462262*coinWt*znPur);
  if(t==='wartime')m=0.003;
  const raw=parseFloat($('penny-qty').value)||0;
  let q=0;
  if(pennyUnitMode==='count')q=raw;
  else if(pennyUnitMode==='g')q=raw/coinWt;
  else if(pennyUnitMode==='oz')q=(raw*31.1035)/coinWt;
  else if(pennyUnitMode==='gr')q=(raw*0.0647989)/coinWt;
  else if(pennyUnitMode==='dwt')q=(raw*1.55517)/coinWt;
  else if(pennyUnitMode==='lb')q=(raw*453.592)/coinWt;
  q=Math.round(q*100)/100;
  const totalGrams=q*coinWt;
  const total=m*q;const face=q*0.01;const ratio=m/0.01;
  $('penny-each').textContent='$'+m.toFixed(4);
  $('penny-total').textContent=fmt(total);
  const fl=$('penny-count-label');
  const isRound=t.startsWith('round')||t.startsWith('bar');
  if(isRound){if(fl)fl.textContent='Unit Count';$('penny-face').textContent=Math.round(q).toLocaleString()+' pcs';}
  else if(pennyUnitMode==='count'){if(fl)fl.textContent='Face Value';$('penny-face').textContent=fmt(face);}
  else{if(fl)fl.textContent='≈ Coin Count';$('penny-face').textContent=Math.round(q).toLocaleString()+' coins';}
  const re=$('penny-ratio');if(re){re.textContent=(ratio*100).toFixed(1)+'% of face';re.style.color=ratio>1?'var(--green)':'var(--red)';}
  $('penny-cu').value=cu.toFixed(2);$('penny-zn').value=zn.toFixed(2);
  const wg=$('penny-weight-g');const woz=$('penny-weight-oz');const wlb=$('penny-weight-lb');
  if(wg)wg.textContent=totalGrams.toFixed(2)+' g';
  if(woz)woz.textContent=(totalGrams/31.1035).toFixed(4)+' oz';
  if(wlb)wlb.textContent=(totalGrams/453.592).toFixed(4)+' lb';
}
function renderPennyRefTable(){
  const cu=spot.HG||4.68;const zn=spot.ZN||1.30;
  const copper=(cu*0.00220462262*3.11*0.95)+(zn*0.00220462262*3.11*0.05);
  const modern=(cu*0.00220462262*2.5*0.025)+(zn*0.00220462262*2.5*0.975);
  const types=[{n:'Pre-1982 Copper',y:'1909–1982',c:'95% Cu / 5% Zn',m:copper},{n:'Modern Zinc',y:'1982–present',c:'97.5% Zn / 2.5% Cu',m:modern},{n:'1943 Steel',y:'1943',c:'Steel + Zn plate',m:0.01},{n:'1944–46 Shell Case',y:'1944–1946',c:'95% Cu recycled',m:copper}];
  const tb=$('penny-ref-tbody');if(!tb)return;
  tb.innerHTML=types.map(t=>`<tr><td style="font-weight:700">${t.n}</td><td class="p-col">${t.y}</td><td class="p-col">${t.c}</td><td class="rv-gold price-col">$${t.m.toFixed(4)}</td><td style="color:${t.m>0.01?'var(--green)':'var(--muted)'};font-weight:600">${(t.m/0.01*100).toFixed(1)}%</td></tr>`).join('');
}
function renderPennyKeyDates(){
  const kd=[
    {y:'1909-S VDB',n:'Lincoln Cent',d:'Rare S-mint first year with VDB initials',r:'rare',v:'$700–$1,800+'},
    {y:'1909-S',n:'Lincoln Cent',d:'Low mintage San Francisco issue',r:'rare',v:'$100–$430+'},
    {y:'1914-D',n:'Lincoln Cent',d:'Low Denver mintage key date',r:'rare',v:'$150–$1,400+'},
    {y:'1922 Plain',n:'Lincoln Cent',d:'No D mintmark — weak die variety',r:'rare',v:'$500–$4,500+'},
    {y:'1931-S',n:'Lincoln Cent',d:'Depression-era low mintage',r:'scarce',v:'$80–$200'},
    {y:'1955 DDO',n:'Lincoln Cent',d:'Major doubled die obverse',r:'rare',v:'$500–$1,500+'},
    {y:'1969-S DDO',n:'Lincoln Cent',d:'Extremely rare — verify authenticity',r:'rare',v:'$10,000+'},
    {y:'1877',n:'Indian Head Cent',d:'Key date — very low mintage',r:'rare',v:'$250–$5,500+'},
    {y:'1908-S',n:'Indian Head Cent',d:'Only S-mint Indian Head cent',r:'scarce',v:'$75–$620+'},
    {y:'1909-S',n:'Indian Head Cent',d:'Final S-mint Indian Head cent',r:'rare',v:'$380–$2,700+'},
    {y:'1864 L on Ribbon',n:'Indian Head Cent',d:'Added designer initial — scarce variety',r:'semi',v:'$80–$600+'},
  ];
  const tb=$('penny-kd-tbody');if(!tb)return;
  tb.innerHTML=kd.map(k=>`<tr><td style="font-weight:700">${k.y}</td><td>${k.n}</td><td style="font-size:11px;color:var(--muted)">${k.d}</td><td><span class="kd-badge kd-${k.r}">${k.r}</span></td><td class="green-col">${k.v}</td></tr>`).join('');
}
function renderPennyCoinVals(){
  const searchEl=$('penny-cv-search');
  const seriesEl=$('penny-cv-series');
  const q=(searchEl?.value||'').toLowerCase();
  const ser=seriesEl?.value||'';
  let rows=CV.filter(c=>c.s.toLowerCase().includes('cent'));
  if(ser)rows=rows.filter(c=>c.s===ser);
  if(q)rows=rows.filter(c=>c.d.toLowerCase().includes(q));
  const tb=$('penny-cv-tbody');if(!tb)return;
  const grades=['G4','VG8','F12','VF20','EF40','AU50','MS63','MS65'];
  tb.innerHTML=rows.slice(0,150).map(c=>`<tr><td style="font-weight:600">${c.s}</td><td>${c.d}</td>${grades.map(g=>`<td class="price-col">${c[g]?'$'+c[g].toLocaleString():'—'}</td>`).join('')}</tr>`).join('');
}

// ═══ DATA BLOCKS ═══
const CV_KEY_DATES=['1909-S VDB','1914-D','1931-S','1922 Plain','1877','1909-S',
  '1916-D','1921','1921-D','1916','1918/7-S','1923-S','1932-D','1932-S',
  '1889-CC','1893-S','1895 Proof','1885-CC','1921 High Relief','1928','1934-S',
  '1907 High Relief','1927-D','1913 (Specimen)','1885','1886','1912-S',
  '1913-S T2','1916 DDO','1918/7-D','1926-S','1937-D 3-Leg','1870-S',
  '1885 (Proof only)','1894-S','1901-S','1895-O'];

const KD_DATA=[
  {c:'Lincoln Cent',y:'1909-S VDB',r:'rare',v:'$700–$1,800+'},{c:'Lincoln Cent',y:'1914-D',r:'rare',v:'$150–$500+'},{c:'Lincoln Cent',y:'1922 Plain',r:'rare',v:'$500–$2,500+'},{c:'Lincoln Cent',y:'1931-S',r:'scarce',v:'$80–$200'},
  {c:'Buffalo Nickel',y:'1913-S T2',r:'rare',v:'$300–$1,500+'},{c:'Buffalo Nickel',y:'1916 DDO',r:'rare',v:'$500–$3,000+'},{c:'Buffalo Nickel',y:'1918/7-D',r:'rare',v:'$1,000–$5,000+'},
  {c:'Mercury Dime',y:'1916-D',r:'rare',v:'$700–$2,000+'},{c:'Mercury Dime',y:'1921',r:'scarce',v:'$50–$200'},{c:'Mercury Dime',y:'1942/41',r:'rare',v:'$400–$1,500+'},
  {c:'SL Quarter',y:'1916',r:'rare',v:'$1,500–$5,000+'},{c:'SL Quarter',y:'1918/7-S',r:'rare',v:'$500–$3,000+'},
  {c:'WL Half',y:'1921',r:'rare',v:'$200–$800+'},{c:'WL Half',y:'1921-D',r:'rare',v:'$250–$1,000+'},
  {c:'Morgan Dollar',y:'1893-S',r:'rare',v:'$3,000–$30,000+'},{c:'Morgan Dollar',y:'1895',r:'rare',v:'$30,000+'},{c:'Morgan Dollar',y:'1901',r:'scarce',v:'$200–$1,000+'},
  {c:'Peace Dollar',y:'1921',r:'scarce',v:'$120–$600'},{c:'Peace Dollar',y:'1928',r:'scarce',v:'$150–$700'},
  {c:'St. Gaudens $20',y:'1907 High Relief',r:'rare',v:'$10,000–$40,000+'},{c:'St. Gaudens $20',y:'1927-D',r:'rare',v:'$15,000–$60,000+'},
];
function _cvIsKey(d){return CV_KEY_DATES.includes(d);}
function renderKeyDates(){
  const f=($('kd-select')||{}).value||'';
  let rows=KD_DATA;if(f)rows=rows.filter(k=>k.c===f);
  const tb=$('kd-tbody');if(!tb)return;
  tb.innerHTML=rows.map(k=>`<tr><td style="font-weight:600">${k.c}</td><td>${k.y}</td><td><span class="kd-badge kd-${k.r}">${k.r}</span></td><td class="green-col">${k.v}</td></tr>`).join('');
}
const ME=[
  {t:'Double Die Obverse (DDO)',d:'Hub doubled during die creation. Shows doubling on lettering/date. Most valuable Lincoln cent error.'},
  {t:'Off-Center Strike',d:'Planchet misaligned — part of design missing. 50% off-center with full date = most valuable.'},
  {t:'Clipped Planchet',d:'Blank disc incorrectly cut leaving curved or straight clip. Reduces coin weight.'},
  {t:'Die Cap / Brockage',d:'Coin sticks to die and strikes next coin, leaving incuse mirror image. Very dramatic.'},
  {t:'Wrong Planchet',d:'Struck on planchet for different denomination or country. E.g. Cent on a Dime blank.'},
  {t:'Lamination Error',d:'Metal separates into layers due to impurities or improper alloy. Flakes or missing chunks.'},
  {t:'Struck Through',d:'Foreign material caught between die and planchet. Weak or missing design area results.'},
  {t:'Repunched Mintmark',d:'Mintmark punched multiple times at different positions. Visible doubling of mintmark.'},
  {t:'Die Crack / Cud',d:'Cracked die leaves raised jagged lines. Cud = broke-off piece creates blank lump at rim.'},
  {t:'Mule Error',d:'Wrong obverse + reverse die combination. Extremely rare and very valuable.'},
  {t:'Rotated Die',d:'Reverse die rotated from normal orientation. 180° rotation most obvious. Detectable by holding coin vertically.'},
  {t:'Proof in Mint Set',d:'Wrong-finish coin ends up in wrong packaging. A collector curiosity.'},
];

function renderErrors(targetId='errors-grid'){
  const el=$(targetId);if(!el)return;
  el.innerHTML=ME.map(e=>`<div class="err-card"><div class="err-type">${e.t}</div><div class="err-desc">${e.d}</div></div>`).join('');
}
const GR=[
  {g:'P-1',n:'Poor',d:'Barely identifiable. Date may be readable.'},{g:'FR-2',n:'Fair',d:'Heavily worn, all design clear but flat.'},
  {g:'AG-3',n:'About Good',d:'Very heavily worn, design outlined.'},{g:'G-4/6',n:'Good',d:'Major design elements clear, legends worn.'},
  {g:'VG-8/10',n:'Very Good',d:'Design clear, some detail visible.'},{g:'F-12/15',n:'Fine',d:'Moderate wear, all major features sharp.'},
  {g:'VF-20/35',n:'Very Fine',d:'Light wear on high points.'},{g:'EF-40/45',n:'Extremely Fine',d:'Slight wear on high points only.'},
  {g:'AU-50/58',n:'About Uncirculated',d:'Trace wear on highest points.'},{g:'MS-60',n:'Mint State Basal',d:'No wear, many heavy marks.'},
  {g:'MS-63',n:'Choice Uncirculated',d:'No wear, several noticeable marks.'},{g:'MS-65',n:'Gem Uncirculated',d:'No wear, minor marks, strong luster.'},
  {g:'MS-67',n:'Superb Gem',d:'Minimal marks, exceptional luster.'},{g:'MS-69',n:'Near Perfect',d:'Virtually perfect. Extremely rare.'},
  {g:'MS-70',n:'Perfect Uncirculated',d:'Perfect in every way. Top grade.'},{g:'PR-70',n:'Perfect Proof',d:'Perfect proof. Cameo contrast.'},
];

function renderGrading(){
  ['grade-tbody','const-grade-tbody','penny-grade-tbody'].forEach(id=>{
    const tb=$(id);if(!tb)return;
    tb.innerHTML=GR.map(g=>`<tr><td class="p-col">${g.g}</td><td style="font-weight:700">${g.n}</td><td>${g.d}</td></tr>`).join('');
  });
}
const CV=[
  // ── INDIAN HEAD CENT (1859–1909) ──
  {s:'Indian Head Cent',d:'1859',G4:18,VG8:28,F12:45,VF20:80,EF40:160,AU50:280,MS63:500,MS65:1800},
  {s:'Indian Head Cent',d:'1864 Bronze',G4:12,VG8:20,F12:32,VF20:65,EF40:120,AU50:220,MS63:450,MS65:1400},
  {s:'Indian Head Cent',d:'1877',G4:850,VG8:1200,F12:1700,VF20:2400,EF40:3600,AU50:5500,MS63:10000,MS65:32000},
  {s:'Indian Head Cent',d:'1908-S',G4:75,VG8:110,F12:160,VF20:250,EF40:400,AU50:620,MS63:1100,MS65:3800},
  {s:'Indian Head Cent',d:'1909-S',G4:380,VG8:560,F12:800,VF20:1150,EF40:1700,AU50:2700,MS63:4800,MS65:15000},
  {s:'Indian Head Cent',d:'Common Date',G4:3,VG8:5,F12:8,VF20:16,EF40:35,AU50:65,MS63:130,MS65:450},
  // ── LINCOLN CENT WHEAT (1909–1958) ──
  {s:'Lincoln Cent',d:'1909 VDB',G4:18,VG8:24,F12:30,VF20:38,EF40:55,AU50:80,MS63:145,MS65:380},
  {s:'Lincoln Cent',d:'1909-S VDB',G4:850,VG8:1100,F12:1350,VF20:1800,EF40:2400,AU50:3400,MS63:5500,MS65:15000},
  {s:'Lincoln Cent',d:'1909-S',G4:100,VG8:135,F12:170,VF20:220,EF40:300,AU50:430,MS63:750,MS65:2200},
  {s:'Lincoln Cent',d:'1910-S',G4:8,VG8:12,F12:18,VF20:32,EF40:70,AU50:135,MS63:270,MS65:950},
  {s:'Lincoln Cent',d:'1911-D',G4:12,VG8:18,F12:28,VF20:55,EF40:120,AU50:220,MS63:450,MS65:1600},
  {s:'Lincoln Cent',d:'1911-S',G4:28,VG8:42,F12:68,VF20:120,EF40:220,AU50:380,MS63:750,MS65:2500},
  {s:'Lincoln Cent',d:'1914-D',G4:200,VG8:290,F12:390,VF20:580,EF40:900,AU50:1400,MS63:3200,MS65:11000},
  {s:'Lincoln Cent',d:'1914-S',G4:16,VG8:24,F12:40,VF20:75,EF40:160,AU50:290,MS63:580,MS65:2000},
  {s:'Lincoln Cent',d:'1922 Plain',G4:650,VG8:900,F12:1150,VF20:1800,EF40:2800,AU50:4500,MS63:10000,MS65:null},
  {s:'Lincoln Cent',d:'1924-D',G4:28,VG8:42,F12:68,VF20:120,EF40:230,AU50:410,MS63:820,MS65:2800},
  {s:'Lincoln Cent',d:'1926-S',G4:12,VG8:18,F12:28,VF20:55,EF40:120,AU50:230,MS63:500,MS65:1900},
  {s:'Lincoln Cent',d:'1931-S',G4:100,VG8:125,F12:150,VF20:185,EF40:250,AU50:350,MS63:500,MS65:1100},
  {s:'Lincoln Cent',d:'1933-D',G4:7,VG8:11,F12:17,VF20:30,EF40:68,AU50:130,MS63:260,MS65:900},
  {s:'Lincoln Cent',d:'1943 Steel',G4:0.75,VG8:1,F12:1.5,VF20:3,EF40:5,AU50:10,MS63:28,MS65:80},
  {s:'Lincoln Cent',d:'1943-D Steel',G4:0.75,VG8:1,F12:1.5,VF20:3,EF40:6,AU50:12,MS63:32,MS65:100},
  {s:'Lincoln Cent',d:'1943-S Steel',G4:1,VG8:1.5,F12:2,VF20:4,EF40:8,AU50:15,MS63:38,MS65:130},
  {s:'Lincoln Cent',d:'1944 Steel (Error)',G4:40000,VG8:65000,F12:100000,VF20:null,EF40:null,AU50:null,MS63:null,MS65:null},
  {s:'Lincoln Cent',d:'1955 DDO',G4:1200,VG8:1600,F12:2000,VF20:2700,EF40:3800,AU50:5500,MS63:9000,MS65:24000},
  {s:'Lincoln Cent',d:'1969-S DDO',G4:20000,VG8:32000,F12:45000,VF20:null,EF40:null,AU50:null,MS63:null,MS65:null},
  {s:'Lincoln Cent',d:'1972 DDO',G4:140,VG8:200,F12:270,VF20:400,EF40:650,AU50:1050,MS63:2000,MS65:6500},
  {s:'Lincoln Cent',d:'Common Date (wheat)',G4:0.1,VG8:0.2,F12:0.35,VF20:0.75,EF40:1.5,AU50:3,MS63:7,MS65:28},
  // ── LIBERTY HEAD NICKEL (1883–1913) ──
  {s:'Liberty Head Nickel',d:'1885',G4:280,VG8:390,F12:520,VF20:750,EF40:1100,AU50:1600,MS63:3200,MS65:11000},
  {s:'Liberty Head Nickel',d:'1886',G4:210,VG8:300,F12:420,VF20:600,EF40:950,AU50:1450,MS63:2800,MS65:9500},
  {s:'Liberty Head Nickel',d:'1912-S',G4:160,VG8:240,F12:340,VF20:500,EF40:800,AU50:1300,MS63:2600,MS65:8500},
  {s:'Liberty Head Nickel',d:'Common Date',G4:3,VG8:5,F12:8,VF20:16,EF40:38,AU50:80,MS63:170,MS65:580},
  // ── BUFFALO NICKEL (1913–1938) ──
  {s:'Buffalo Nickel',d:'1913-P T1',G4:22,VG8:30,F12:42,VF20:65,EF40:115,AU50:210,MS63:420,MS65:1400},
  {s:'Buffalo Nickel',d:'1913-S T1',G4:55,VG8:85,F12:130,VF20:200,EF40:350,AU50:640,MS63:1250,MS65:4800},
  {s:'Buffalo Nickel',d:'1913-S T2',G4:420,VG8:630,F12:1000,VF20:1400,EF40:2500,AU50:4200,MS63:9500,MS65:34000},
  {s:'Buffalo Nickel',d:'1916 DDO',G4:700,VG8:1100,F12:1700,VF20:2800,EF40:4800,AU50:8500,MS63:17000,MS65:null},
  {s:'Buffalo Nickel',d:'1918/7-D',G4:1400,VG8:2100,F12:3500,VF20:5500,EF40:9500,AU50:17000,MS63:null,MS65:null},
  {s:'Buffalo Nickel',d:'1921-S',G4:28,VG8:42,F12:70,VF20:125,EF40:280,AU50:560,MS63:1250,MS65:4800},
  {s:'Buffalo Nickel',d:'1926-S',G4:55,VG8:90,F12:145,VF20:260,EF40:560,AU50:1250,MS63:3500,MS65:null},
  {s:'Buffalo Nickel',d:'1937-D 3-Leg',G4:560,VG8:840,F12:1250,VF20:1950,EF40:3100,AU50:4800,MS63:8200,MS65:25000},
  {s:'Buffalo Nickel',d:'Common Date',G4:2,VG8:3,F12:5,VF20:8,EF40:18,AU50:38,MS63:85,MS65:290},
  // ── JEFFERSON NICKEL (1938–present) ──
  {s:'Jefferson Nickel',d:'1938-D',G4:1.5,VG8:2,F12:3,VF20:5,EF40:9,AU50:18,MS63:36,MS65:110},
  {s:'Jefferson Nickel',d:'1939-D',G4:5,VG8:8,F12:12,VF20:22,EF40:50,AU50:100,MS63:210,MS65:700},
  {s:'Jefferson Nickel',d:'1942-D',G4:1.5,VG8:2.5,F12:4,VF20:7,EF40:17,AU50:35,MS63:75,MS65:260},
  {s:'Jefferson Nickel',d:'War Nickel (35% Silver)',G4:4,VG8:4.5,F12:5.5,VF20:7,EF40:10,AU50:15,MS63:30,MS65:95},
  {s:'Jefferson Nickel',d:'1950-D',G4:12,VG8:18,F12:26,VF20:40,EF40:65,AU50:115,MS63:220,MS65:720},
  {s:'Jefferson Nickel',d:'Common Date',G4:0.15,VG8:0.25,F12:0.5,VF20:0.75,EF40:1.5,AU50:3,MS63:7,MS65:28},
  // ── BARBER DIME (1892–1916) ──
  {s:'Barber Dime',d:'1895-O',G4:110,VG8:175,F12:300,VF20:540,EF40:1100,AU50:2100,MS63:5500,MS65:null},
  {s:'Barber Dime',d:'1896-S',G4:85,VG8:135,F12:220,VF20:420,EF40:850,AU50:1700,MS63:4200,MS65:null},
  {s:'Barber Dime',d:'1901-S',G4:70,VG8:110,F12:180,VF20:350,EF40:700,AU50:1400,MS63:3500,MS65:null},
  {s:'Barber Dime',d:'1903-S',G4:55,VG8:90,F12:155,VF20:290,EF40:600,AU50:1200,MS63:3100,MS65:null},
  {s:'Barber Dime',d:'1894-S',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:null,MS65:null},
  {s:'Barber Dime',d:'Common Date',G4:6,VG8:8,F12:10,VF20:18,EF40:40,AU50:95,MS63:220,MS65:730},
  // ── MERCURY DIME (1916–1945) ──
  {s:'Mercury Dime',d:'1916-D',G4:950,VG8:1350,F12:2000,VF20:3000,EF40:4800,AU50:7500,MS63:14000,MS65:42000},
  {s:'Mercury Dime',d:'1921',G4:72,VG8:115,F12:168,VF20:280,EF40:490,AU50:840,MS63:2100,MS65:7000},
  {s:'Mercury Dime',d:'1921-D',G4:64,VG8:98,F12:155,VF20:255,EF40:450,AU50:775,MS63:1950,MS65:6200},
  {s:'Mercury Dime',d:'1926-S',G4:18,VG8:30,F12:52,VF20:100,EF40:260,AU50:580,MS63:1700,MS65:null},
  {s:'Mercury Dime',d:'1931-D',G4:10,VG8:16,F12:24,VF20:46,EF40:100,AU50:215,MS63:490,MS65:1700},
  {s:'Mercury Dime',d:'1942/41',G4:560,VG8:840,F12:1250,VF20:1950,EF40:3100,AU50:5300,MS63:11000,MS65:null},
  {s:'Mercury Dime',d:'1942/41-D',G4:490,VG8:760,F12:1100,VF20:1700,EF40:2800,AU50:4800,MS63:9500,MS65:null},
  {s:'Mercury Dime',d:'Common Date',G4:6,VG8:6.5,F12:7,VF20:8,EF40:12,AU50:20,MS63:42,MS65:130},
  // ── ROOSEVELT DIME (1946–1964 silver) ──
  {s:'Roosevelt Dime',d:'1946',G4:5.5,VG8:6,F12:7,VF20:9,EF40:13,AU50:19,MS63:36,MS65:115},
  {s:'Roosevelt Dime',d:'1949-S',G4:7,VG8:9,F12:13,VF20:18,EF40:30,AU50:52,MS63:105,MS65:360},
  {s:'Roosevelt Dime',d:'1950-S',G4:6,VG8:8,F12:11,VF20:16,EF40:27,AU50:46,MS63:95,MS65:320},
  {s:'Roosevelt Dime',d:'1955',G4:5.5,VG8:7,F12:9,VF20:12,EF40:20,AU50:34,MS63:70,MS65:225},
  {s:'Roosevelt Dime',d:'Common (pre-65 silver)',G4:6,VG8:6.5,F12:7.5,VF20:9,EF40:14,AU50:22,MS63:48,MS65:160},
  // ── BARBER QUARTER (1892–1916) ──
  {s:'Barber Quarter',d:'1896-S',G4:700,VG8:1100,F12:2000,VF20:3500,EF40:7000,AU50:13000,MS63:null,MS65:null},
  {s:'Barber Quarter',d:'1901-S',G4:2800,VG8:5000,F12:8500,VF20:15000,EF40:null,AU50:null,MS63:null,MS65:null},
  {s:'Barber Quarter',d:'1913-S',G4:280,VG8:450,F12:780,VF20:1400,EF40:3100,AU50:6500,MS63:null,MS65:null},
  {s:'Barber Quarter',d:'Common Date',G4:15,VG8:22,F12:36,VF20:68,EF40:175,AU50:390,MS63:900,MS65:3100},
  // ── STANDING LIBERTY QUARTER (1916–1930) ──
  {s:'SL Quarter',d:'1916',G4:2200,VG8:3600,F12:5800,VF20:8500,EF40:13000,AU50:20000,MS63:36000,MS65:null},
  {s:'SL Quarter',d:'1917 T1',G4:25,VG8:35,F12:56,VF20:95,EF40:185,AU50:330,MS63:760,MS65:2750},
  {s:'SL Quarter',d:'1918/7-S',G4:700,VG8:1100,F12:2000,VF20:3500,EF40:7000,AU50:13000,MS63:null,MS65:null},
  {s:'SL Quarter',d:'1921',G4:120,VG8:195,F12:330,VF20:600,EF40:1350,AU50:3000,MS63:8800,MS65:null},
  {s:'SL Quarter',d:'1923-S',G4:225,VG8:370,F12:605,VF20:1050,EF40:2100,AU50:4200,MS63:12000,MS65:null},
  {s:'SL Quarter',d:'1927-S',G4:80,VG8:125,F12:215,VF20:425,EF40:1050,AU50:2700,MS63:null,MS65:null},
  {s:'SL Quarter',d:'Common Date',G4:15,VG8:21,F12:30,VF20:50,EF40:95,AU50:190,MS63:390,MS65:1250},
  // ── WASHINGTON QUARTER (1932–1964 silver) ──
  {s:'Washington Quarter',d:'1932-D',G4:145,VG8:215,F12:315,VF20:500,EF40:860,AU50:1700,MS63:4200,MS65:null},
  {s:'Washington Quarter',d:'1932-S',G4:130,VG8:190,F12:285,VF20:460,EF40:790,AU50:1575,MS63:4000,MS65:null},
  {s:'Washington Quarter',d:'1936-D',G4:15,VG8:22,F12:30,VF20:50,EF40:105,AU50:210,MS63:480,MS65:1900},
  {s:'Washington Quarter',d:'1937',G4:14,VG8:20,F12:28,VF20:45,EF40:65,AU50:115,MS63:250,MS65:1000},
  {s:'Washington Quarter',d:'1940-D',G4:14,VG8:20,F12:27,VF20:42,EF40:60,AU50:95,MS63:210,MS65:780},
  {s:'Washington Quarter',d:'Common (pre-65)',G4:14,VG8:15,F12:17,VF20:20,EF40:28,AU50:44,MS63:80,MS65:240},
  // ── BARBER HALF (1892–1915) ──
  {s:'Barber Half',d:'1892-O Micro O',G4:90,VG8:150,F12:240,VF20:450,EF40:1050,AU50:2300,MS63:6000,MS65:null},
  {s:'Barber Half',d:'1904-S',G4:65,VG8:105,F12:180,VF20:380,EF40:900,AU50:2000,MS63:5200,MS65:null},
  {s:'Barber Half',d:'1914',G4:40,VG8:64,F12:110,VF20:215,EF40:530,AU50:1200,MS63:3100,MS65:null},
  {s:'Barber Half',d:'Common Date',G4:28,VG8:38,F12:60,VF20:115,EF40:280,AU50:620,MS63:1400,MS65:4600},
  // ── WALKING LIBERTY HALF (1916–1947) ──
  {s:'WL Half',d:'1916',G4:65,VG8:95,F12:140,VF20:220,EF40:385,AU50:680,MS63:1400,MS65:4800},
  {s:'WL Half',d:'1916-D Obv',G4:80,VG8:125,F12:190,VF20:310,EF40:580,AU50:1050,MS63:2400,MS65:8500},
  {s:'WL Half',d:'1917-D Obv',G4:34,VG8:52,F12:80,VF20:145,EF40:310,AU50:620,MS63:1400,MS65:5400},
  {s:'WL Half',d:'1919-D',G4:40,VG8:64,F12:110,VF20:205,EF40:440,AU50:940,MS63:2400,MS65:null},
  {s:'WL Half',d:'1921',G4:310,VG8:465,F12:770,VF20:1200,EF40:2300,AU50:4600,MS63:10500,MS65:null},
  {s:'WL Half',d:'1921-D',G4:390,VG8:580,F12:920,VF20:1450,EF40:2750,AU50:5500,MS63:12000,MS65:null},
  {s:'WL Half',d:'1938-D',G4:185,VG8:280,F12:400,VF20:580,EF40:920,AU50:1450,MS63:2800,MS65:7800},
  {s:'WL Half',d:'Common Date',G4:28,VG8:30,F12:33,VF20:40,EF40:55,AU50:90,MS63:170,MS65:560},
  // ── FRANKLIN HALF (1948–1963) ──
  {s:'Franklin Half',d:'1948',G4:27,VG8:28,F12:30,VF20:34,EF40:44,AU50:60,MS63:115,MS65:580},
  {s:'Franklin Half',d:'1949',G4:28,VG8:30,F12:34,VF20:42,EF40:62,AU50:95,MS63:195,MS65:1000},
  {s:'Franklin Half',d:'1949-S',G4:27,VG8:29,F12:32,VF20:38,EF40:52,AU50:78,MS63:155,MS65:780},
  {s:'Franklin Half',d:'1955',G4:42,VG8:52,F12:64,VF20:82,EF40:115,AU50:185,MS63:370,MS65:1450},
  {s:'Franklin Half',d:'1962 FBL',G4:27,VG8:28,F12:30,VF20:34,EF40:44,AU50:60,MS63:130,MS65:1100},
  {s:'Franklin Half',d:'Common Date',G4:27,VG8:28,F12:29,VF20:32,EF40:40,AU50:55,MS63:95,MS65:480},
  // ── KENNEDY HALF (1964–present) ──
  {s:'Kennedy Half',d:'1964 (90% Silver)',G4:27,VG8:28,F12:30,VF20:34,EF40:42,AU50:58,MS63:95,MS65:290},
  {s:'Kennedy Half',d:'1965-69 (40% Silver)',G4:12,VG8:13,F12:14,VF20:16,EF40:20,AU50:28,MS63:52,MS65:165},
  {s:'Kennedy Half',d:'1970-D (40% Silver)',G4:22,VG8:26,F12:30,VF20:38,EF40:52,AU50:72,MS63:130,MS65:420},
  {s:'Kennedy Half',d:'Common Clad',G4:0.5,VG8:0.5,F12:0.75,VF20:1,EF40:1.5,AU50:2.5,MS63:6,MS65:22},
  // ── MORGAN DOLLAR (1878–1921) ──
  {s:'Morgan Dollar',d:'1878 8TF',G4:75,VG8:88,F12:105,VF20:150,EF40:230,AU50:420,MS63:920,MS65:4600},
  {s:'Morgan Dollar',d:'1878 7TF Rev 78',G4:65,VG8:78,F12:95,VF20:132,EF40:205,AU50:370,MS63:780,MS65:3900},
  {s:'Morgan Dollar',d:'1879-S Rev 78',G4:70,VG8:90,F12:125,VF20:200,EF40:340,AU50:610,MS63:1350,MS65:7500},
  {s:'Morgan Dollar',d:'1880-S',G4:62,VG8:66,F12:72,VF20:90,EF40:135,AU50:220,MS63:430,MS65:1900},
  {s:'Morgan Dollar',d:'1881-S',G4:62,VG8:66,F12:72,VF20:88,EF40:130,AU50:215,MS63:410,MS65:1600},
  {s:'Morgan Dollar',d:'1884-O',G4:60,VG8:64,F12:70,VF20:86,EF40:125,AU50:200,MS63:380,MS65:1450},
  {s:'Morgan Dollar',d:'1885-O',G4:60,VG8:64,F12:70,VF20:86,EF40:125,AU50:200,MS63:380,MS65:1450},
  {s:'Morgan Dollar',d:'1879-CC',G4:175,VG8:350,F12:800,VF20:2000,EF40:5500,AU50:12000,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1880-CC',G4:185,VG8:230,F12:290,VF20:510,EF40:950,AU50:1800,MS63:3500,MS65:null},
  {s:'Morgan Dollar',d:'1881-CC',G4:360,VG8:375,F12:500,VF20:700,EF40:1100,AU50:1800,MS63:3600,MS65:null},
  {s:'Morgan Dollar',d:'1885-CC',G4:530,VG8:545,F12:580,VF20:625,EF40:690,AU50:790,MS63:950,MS65:null},
  {s:'Morgan Dollar',d:'1889-CC',G4:1050,VG8:1800,F12:3100,VF20:5800,EF40:12000,AU50:28000,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1893-S',G4:4400,VG8:6800,F12:12500,VF20:21000,EF40:40000,AU50:75000,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1894',G4:730,VG8:1150,F12:2000,VF20:3400,EF40:6300,AU50:11500,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1895 Proof',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:58000,MS65:115000},
  {s:'Morgan Dollar',d:'1895-O',G4:320,VG8:530,F12:920,VF20:1850,EF40:4600,AU50:15000,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1895-S',G4:440,VG8:690,F12:1150,VF20:2150,EF40:4600,AU50:11000,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1901',G4:90,VG8:155,F12:275,VF20:615,EF40:1850,AU50:6200,MS63:null,MS65:null},
  {s:'Morgan Dollar',d:'1903-O',G4:62,VG8:68,F12:80,VF20:128,EF40:215,AU50:430,MS63:920,MS65:3800},
  {s:'Morgan Dollar',d:'1921',G4:60,VG8:64,F12:70,VF20:78,EF40:108,AU50:160,MS63:290,MS65:900},
  {s:'Morgan Dollar',d:'Common Date',G4:60,VG8:64,F12:70,VF20:80,EF40:115,AU50:175,MS63:280,MS65:880},
  // ── PEACE DOLLAR (1921–1935) ──
  {s:'Peace Dollar',d:'1921',G4:195,VG8:250,F12:345,VF20:540,EF40:925,AU50:1700,MS63:3400,MS65:13000},
  {s:'Peace Dollar',d:'1924-S',G4:62,VG8:78,F12:110,VF20:175,EF40:420,AU50:980,MS63:3200,MS65:null},
  {s:'Peace Dollar',d:'1925-S',G4:60,VG8:72,F12:100,VF20:165,EF40:375,AU50:900,MS63:2900,MS65:null},
  {s:'Peace Dollar',d:'1927-D',G4:65,VG8:82,F12:125,VF20:215,EF40:510,AU50:1300,MS63:4800,MS65:null},
  {s:'Peace Dollar',d:'1927-S',G4:65,VG8:82,F12:125,VF20:215,EF40:510,AU50:1300,MS63:4800,MS65:null},
  {s:'Peace Dollar',d:'1928',G4:235,VG8:315,F12:440,VF20:650,EF40:1100,AU50:1900,MS63:4000,MS65:14500},
  {s:'Peace Dollar',d:'1934-D',G4:62,VG8:78,F12:110,VF20:175,EF40:420,AU50:980,MS63:3200,MS65:null},
  {s:'Peace Dollar',d:'1934-S',G4:78,VG8:115,F12:185,VF20:360,EF40:850,AU50:2600,MS63:10000,MS65:null},
  {s:'Peace Dollar',d:'1935-S',G4:62,VG8:78,F12:110,VF20:175,EF40:420,AU50:980,MS63:3500,MS65:null},
  {s:'Peace Dollar',d:'Common Date',G4:60,VG8:64,F12:68,VF20:78,EF40:105,AU50:160,MS63:265,MS65:800},
  // ── EISENHOWER DOLLAR (1971–1978) ──
  {s:'Eisenhower Dollar',d:'1971',G4:2,VG8:2.5,F12:3,VF20:4,EF40:6,AU50:9,MS63:18,MS65:58},
  {s:'Eisenhower Dollar',d:'1971-S Silver',G4:22,VG8:24,F12:27,VF20:32,EF40:40,AU50:55,MS63:90,MS65:300},
  {s:'Eisenhower Dollar',d:'1972 T3',G4:4,VG8:6,F12:8,VF20:11,EF40:18,AU50:30,MS63:65,MS65:290},
  {s:'Eisenhower Dollar',d:'Common Clad',G4:2,VG8:2.5,F12:3,VF20:4,EF40:6,AU50:9,MS63:15,MS65:52},
  // ── SUSAN B. ANTHONY DOLLAR ──
  {s:'SBA Dollar',d:'1979-P Wide Rim',G4:14,VG8:20,F12:26,VF20:36,EF40:58,AU50:95,MS63:190,MS65:580},
  {s:'SBA Dollar',d:'1981-S Type 2',G4:72,VG8:100,F12:130,VF20:175,EF40:230,AU50:320,MS63:580,MS65:null},
  {s:'SBA Dollar',d:'Common Date',G4:1,VG8:1,F12:1.5,VF20:2,EF40:3,AU50:4,MS63:9,MS65:30},
  // ── GOLD COINAGE ──
  {s:'Gold $1 (Type 1)',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:265,AU50:315,MS63:530,MS65:1400},
  {s:'Gold $1 (Type 3)',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:280,AU50:330,MS63:570,MS65:1550},
  {s:'Gold $2.50 Liberty',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:430,AU50:485,MS63:770,MS65:1850},
  {s:'Gold $2.50 Indian',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:460,AU50:520,MS63:840,MS65:2150},
  {s:'Gold $3 Princess',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:2750,AU50:3350,MS63:5300,MS65:14500},
  {s:'Gold $5 Liberty',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:780,AU50:850,MS63:1100,MS65:2200},
  {s:'Gold $5 Indian',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:810,AU50:900,MS63:1175,MS65:2500},
  {s:'Gold $10 Liberty',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:1650,AU50:1760,MS63:2100,MS65:3800},
  {s:'Gold $10 Indian',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:1725,AU50:1850,MS63:2200,MS65:4100},
  {s:'Gold $20 Liberty',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:3250,AU50:3400,MS63:3900,MS65:6200},
  {s:'Gold $20 St. Gaudens',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:3400,AU50:3550,MS63:4050,MS65:7000},
  {s:'Gold $20 St. Gaudens',d:'1907 High Relief',G4:null,VG8:null,F12:null,VF20:null,EF40:18500,AU50:28000,MS63:47000,MS65:null},
  {s:'Gold $20 St. Gaudens',d:'1927-D',G4:null,VG8:null,F12:null,VF20:null,EF40:23000,AU50:40000,MS63:95000,MS65:null},
  // ── SILVER AMERICAN EAGLE (1986–present) ──
  {s:'Silver Eagle',d:'1986 (First Year)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:115,MS65:180},
  {s:'Silver Eagle',d:'1994',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:100,MS65:160},
  {s:'Silver Eagle',d:'1995-W Proof',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:5800,MS65:9500},
  {s:'Silver Eagle',d:'1996',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:130,MS65:210},
  {s:'Silver Eagle',d:'2011-S Burnished',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:165,MS65:320},
  {s:'Silver Eagle',d:'Common Date (BU)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:93,MS65:115},
  // ── GOLD AMERICAN EAGLE ──
  {s:'Gold Eagle 1oz',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:3700,MS65:4000},
  {s:'Gold Eagle 1/2oz',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:1925,MS65:2075},
  {s:'Gold Eagle 1/4oz',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:1000,MS65:1110},
  {s:'Gold Eagle 1/10oz',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:430,MS65:495},
  // ── GOLD BUFFALO ──
  {s:'Gold Buffalo 1oz',d:'Common Date',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:3775,MS65:4075},
  // ── COMMEMORATIVE SILVER ──
  {s:'Commemorative Half',d:'1892 Columbian',G4:28,VG8:38,F12:50,VF20:72,EF40:115,AU50:185,MS63:370,MS65:1200},
  {s:'Commemorative Half',d:'1893 Isabella Quarter',G4:95,VG8:140,F12:220,VF20:345,EF40:620,AU50:1075,MS63:2350,MS65:7600},
  {s:'Commemorative Half',d:'1921 Alabama',G4:95,VG8:140,F12:220,VF20:345,EF40:590,AU50:1025,MS63:2200,MS65:6900},
  {s:'Commemorative Half',d:'1921 Missouri',G4:125,VG8:190,F12:285,VF20:440,EF40:780,AU50:1400,MS63:3100,MS65:null},
  {s:'Commemorative Half',d:'1936 Albany',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:380,MS65:1225},
  {s:'Commemorative Half',d:'1936 Cleveland',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:310,MS65:1000},
  {s:'Commemorative Half',d:'Common Classic',G4:40,VG8:56,F12:80,VF20:120,EF40:185,AU50:300,MS63:570,MS65:1900},
  // ── PROOF & MINT SETS ──
  {s:'Proof Set',d:'1936 (6-coin)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:5400,MS65:null},
  {s:'Proof Set',d:'1950 (5-coin)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:600,MS65:null},
  {s:'Proof Set',d:'1955 (5-coin)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:280,MS65:null},
  {s:'Proof Set',d:'Common (1960s)',G4:null,VG8:null,F12:null,VF20:null,EF40:null,AU50:null,MS63:25,MS65:null},
  // ── SEATED LIBERTY SERIES ──
  {s:'Seated Liberty Dime',d:'1871-CC',G4:300,VG8:480,F12:840,VF20:1525,EF40:3400,AU50:6800,MS63:null,MS65:null},
  {s:'Seated Liberty Dime',d:'Common Date',G4:28,VG8:44,F12:70,VF20:132,EF40:320,AU50:720,MS63:1600,MS65:6200},
  {s:'Seated Liberty Quarter',d:'1871-CC',G4:610,VG8:1050,F12:1825,VF20:3800,EF40:8400,AU50:null,MS63:null,MS65:null},
  {s:'Seated Liberty Quarter',d:'Common Date',G4:36,VG8:58,F12:100,VF20:195,EF40:440,AU50:940,MS63:2200,MS65:7800},
  {s:'Seated Liberty Half',d:'Common Date',G4:42,VG8:68,F12:115,VF20:225,EF40:520,AU50:1100,MS63:2550,MS65:9500},
  {s:'Seated Liberty Dollar',d:'Common Date',G4:195,VG8:285,F12:440,VF20:780,EF40:1700,AU50:3400,MS63:7800,MS65:null},
  // ── TRADE DOLLAR (1873–1885) ──
  {s:'Trade Dollar',d:'1878-CC',G4:195,VG8:285,F12:440,VF20:780,EF40:1700,AU50:3400,MS63:7800,MS65:null},
  {s:'Trade Dollar',d:'Common Date',G4:125,VG8:190,F12:285,VF20:510,EF40:1100,AU50:2350,MS63:6200,MS65:null},
  // ── DRAPED BUST / CAPPED BUST ──
  {s:'Capped Bust Half',d:'1807–1836 Common',G4:78,VG8:125,F12:205,VF20:345,EF40:700,AU50:1400,MS63:3900,MS65:null},
  {s:'Capped Bust Dime',d:'Common Date',G4:50,VG8:80,F12:128,VF20:245,EF40:560,AU50:1200,MS63:2800,MS65:null},
  {s:'Draped Bust Dollar',d:'1798 Common',G4:2300,VG8:3800,F12:6100,VF20:10500,EF40:21000,AU50:null,MS63:null,MS65:null},
];

function initCVDropdowns(){
  const s=$('cv-series');if(!s||s.options.length>1)return;
  [...new Set(CV.map(c=>c.s))].forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o);});
}
function renderCoinVals(){
  initCVDropdowns();
  const cvSearch=$('cv-search');const cvSeries=$('cv-series');const cvMax=$('cv-max');
  const q=(cvSearch?cvSearch.value:'').toLowerCase();
  const ser=cvSeries?cvSeries.value:'';
  const max=cvMax?parseFloat(cvMax.value)||Infinity:Infinity;
  let rows=CV;
  if(ser)rows=rows.filter(c=>c.s===ser);
  if(q)rows=rows.filter(c=>c.d.toLowerCase().includes(q)||c.s.toLowerCase().includes(q));
  const grades=['G4','VG8','F12','VF20','EF40','AU50','MS63','MS65'];
  const tb=$('cv-tbody');if(!tb)return;
  tb.innerHTML=rows.slice(0,200).map(c=>{
    const key=_cvIsKey(c.d);
    return`<tr ${key?'style="background:rgba(220,38,38,.03)"':''}>
      <td style="font-weight:600${key?';color:var(--red)':''}">${c.s}${key?' 🔑':''}</td>
      <td>${c.d}</td>
      ${grades.map(g=>`<td class="price-col">${c[g]?'$'+c[g].toLocaleString():'—'}</td>`).join('')}
      <td><button onclick="window.open('https://www.pcgs.com/coinfacts','_blank')" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:2px 6px;border-radius:4px;cursor:pointer;font-size:10px">📖</button></td>
    </tr>`;
  }).join('');
  $('cv-status').textContent=rows.length>200?`Showing 200 of ${rows.length} — refine search`:'';
}
function openGradingLookup(source) {
  const typeEl = document.getElementById('nm-grade-type') || document.getElementById('gs-grade-type');
  const gradeEl = document.getElementById('nm-grade-val') || document.getElementById('gs-grade-val');
  const infoEl = document.getElementById('nm-grading-info') || document.getElementById('grading-info');
  const coinType = typeEl ? typeEl.value : 'cent';
  const grade = gradeEl ? gradeEl.value : 'AU-58';
  const label = `${coinType} in ${grade}`;
  if(source==='pcgs'){
    window.open('https://www.pcgs.com/photograde','_blank');
    if(infoEl) infoEl.textContent = '↗ Opened PCGS Photograde — browse to ' + label;
  } else if(source==='ngc'){
    window.open('https://www.ngccoin.com/resources/grading-standards/','_blank');
    if(infoEl) infoEl.textContent = '↗ Opened NGC Grading Standards page';
  } else if(source==='coinfacts'){
    window.open('https://www.pcgs.com/coinfacts','_blank');
    if(infoEl) infoEl.textContent = '↗ Opened PCGS CoinFacts — search for ' + label;
  }
}
// ═══ CURRENCY EXCHANGE DATA ═══
let fxRates={};
let fxSortCol='country';
let fxSortDir=1;
const FX_CURRENCIES=[
  {flag:'🇦🇺',country:'Australia',code:'AUD'},
  {flag:'🇧🇷',country:'Brazil',code:'BRL'},
  {flag:'🇨🇦',country:'Canada',code:'CAD'},
  {flag:'🇨🇳',country:'China',code:'CNY'},
  {flag:'🇨🇿',country:'Czech Republic',code:'CZK'},
  {flag:'🇩🇰',country:'Denmark',code:'DKK'},
  {flag:'🇪🇺',country:'Euro Zone',code:'EUR'},
  {flag:'🇬🇧',country:'United Kingdom',code:'GBP'},
  {flag:'🇭🇰',country:'Hong Kong',code:'HKD'},
  {flag:'🇭🇺',country:'Hungary',code:'HUF'},
  {flag:'🇮🇳',country:'India',code:'INR'},
  {flag:'🇮🇩',country:'Indonesia',code:'IDR'},
  {flag:'🇮🇱',country:'Israel',code:'ILS'},
  {flag:'🇯🇵',country:'Japan',code:'JPY'},
  {flag:'🇲🇽',country:'Mexico',code:'MXN'},
  {flag:'🇳🇿',country:'New Zealand',code:'NZD'},
  {flag:'🇳🇴',country:'Norway',code:'NOK'},
  {flag:'🇵🇭',country:'Philippines',code:'PHP'},
  {flag:'🇵🇱',country:'Poland',code:'PLN'},
  {flag:'🇷🇴',country:'Romania',code:'RON'},
  {flag:'🇷🇺',country:'Russia',code:'RUB'},
  {flag:'🇸🇬',country:'Singapore',code:'SGD'},
  {flag:'🇿🇦',country:'South Africa',code:'ZAR'},
  {flag:'🇰🇷',country:'South Korea',code:'KRW'},
  {flag:'🇸🇪',country:'Sweden',code:'SEK'},
  {flag:'🇨🇭',country:'Switzerland',code:'CHF'},
  {flag:'🇹🇼',country:'Taiwan',code:'TWD'},
  {flag:'🇹🇭',country:'Thailand',code:'THB'},
  {flag:'🇹🇷',country:'Turkey',code:'TRY'},
  {flag:'🇦🇪',country:'UAE',code:'AED'},
  {flag:'🇺🇦',country:'Ukraine',code:'UAH'},
  {flag:'🇻🇳',country:'Vietnam',code:'VND'},
  {flag:'🇦🇷',country:'Argentina',code:'ARS'},
  {flag:'🇨🇱',country:'Chile',code:'CLP'},
  {flag:'🇨🇴',country:'Colombia',code:'COP'},
  {flag:'🇵🇰',country:'Pakistan',code:'PKR'},
  {flag:'🇧🇩',country:'Bangladesh',code:'BDT'},
  {flag:'🇪🇬',country:'Egypt',code:'EGP'},
  {flag:'🇰🇪',country:'Kenya',code:'KES'},
  {flag:'🇳🇬',country:'Nigeria',code:'NGN'},
  {flag:'🇬🇭',country:'Ghana',code:'GHS'},
  {flag:'🇲🇦',country:'Morocco',code:'MAD'},
  {flag:'🇮🇶',country:'Iraq',code:'IQD'},
  {flag:'🇸🇦',country:'Saudi Arabia',code:'SAR'},
  {flag:'🇯🇴',country:'Jordan',code:'JOD'},
  {flag:'🇰🇼',country:'Kuwait',code:'KWD'},
  {flag:'🇶🇦',country:'Qatar',code:'QAR'},
  {flag:'🇧🇭',country:'Bahrain',code:'BHD'},
  {flag:'🇴🇲',country:'Oman',code:'OMR'},
  {flag:'🇮🇷',country:'Iran',code:'IRR'},
  {flag:'🇲🇾',country:'Malaysia',code:'MYR'},
  {flag:'🇳🇵',country:'Nepal',code:'NPR'},
  {flag:'🇱🇰',country:'Sri Lanka',code:'LKR'},
  {flag:'🇲🇲',country:'Myanmar',code:'MMK'},
  {flag:'🇰🇭',country:'Cambodia',code:'KHR'},
  {flag:'🇺🇿',country:'Uzbekistan',code:'UZS'},
  {flag:'🇰🇿',country:'Kazakhstan',code:'KZT'},
  {flag:'🇦🇲',country:'Armenia',code:'AMD'},
  {flag:'🇬🇪',country:'Georgia',code:'GEL'},
  {flag:'🇦🇿',country:'Azerbaijan',code:'AZN'},
  {flag:'🇧🇾',country:'Belarus',code:'BYN'},
  {flag:'🇷🇸',country:'Serbia',code:'RSD'},
  {flag:'🇭🇷',country:'Croatia',code:'HRK'},
  {flag:'🇧🇬',country:'Bulgaria',code:'BGN'},
  {flag:'🇮🇸',country:'Iceland',code:'ISK'},
];
// Top 10 featured countries shown on load
const FX_TOP10=['EUR','GBP','JPY','CAD','AUD','CHF','CNY','MXN','INR','BRL'];

async function loadFX(force=false){
  // Free usage limit check
  if(!window_isPro){
    let fxUsed=parseInt(localStorage.getItem('bdp-fx-used')||'0');
    if(!window_isPro && fxUsed>=5){
      const banner=$('fx-limit-banner');if(banner)banner.style.display='block';
      const ctrl=$('fx-controls');if(ctrl)ctrl.style.display='none';
      const top=$('fx-top10');if(top)top.style.display='none';
      const tbl=$('fx-table');if(tbl)tbl.style.display='none';
      return;
    }
    if(!window_isPro){ fxUsed++; localStorage.setItem('bdp-fx-used',fxUsed); }
    const banner=$('fx-limit-banner');
    if(banner){
      if(!window_isPro && fxUsed>=5){banner.style.display='block';const ctrl=$('fx-controls');if(ctrl)ctrl.style.pointerEvents='none';}
      else{banner.style.display='none';}
    }
    // Show remaining uses hint
    if(!window_isPro && fxUsed<5){const s=$('fx-status');if(s)s.textContent='ℹ Free: '+(5-fxUsed)+' lookups remaining. Upgrade for unlimited.';}
  }
  if(!force && Object.keys(fxRates).length>0) return;
  $('fx-status').textContent='Loading exchange rates…';
  try{
    const r=await fetch('/api/fx');
    if(!r.ok)throw new Error('API error');
    const d=await r.json();
    fxRates=d.rates||{};
    $('fx-updated').textContent='Updated: '+new Date(d.updated||(d.timestamp*1000)||Date.now()).toLocaleString()+' · Source: Open Exchange Rates';
  } catch(e) {
    // Fallback: use static approximate rates
    fxRates={AUD:1.54,BRL:5.10,CAD:1.36,CNY:7.24,CZK:22.8,DKK:6.90,EUR:0.92,GBP:0.79,HKD:7.82,HUF:360,INR:83.1,IDR:15800,ILS:3.72,JPY:149.5,MXN:17.2,NZD:1.65,NOK:10.5,PHP:55.8,PLN:3.98,RON:4.57,RUB:89.5,SGD:1.34,ZAR:18.8,KRW:1330,SEK:10.4,CHF:0.88,TWD:31.8,THB:35.2,TRY:32.1,AED:3.67,UAH:38.2,VND:24500,ARS:900,CLP:950,COP:4000,PKR:279,BDT:110,EGP:47.5,KES:130,NGN:1500,GHS:12.5,MAD:10.1,IQD:1310,SAR:3.75,JOD:0.71,KWD:0.31,QAR:3.64,BHD:0.377,OMR:0.385,IRR:42000,MYR:4.68,NPR:133,LKR:315,MMK:2100,KHR:4100,UZS:12600,KZT:450,AMD:387,GEL:2.66,AZN:1.70,BYN:3.27,RSD:108,HRK:7.05,BGN:1.80,ISK:137};
    $('fx-updated').textContent='⚠ Using estimated rates — live data unavailable';
  }
  buildFXDropdown();
  renderFXTop10();
  filterFX();
  $('fx-status').textContent='';
}
function renderFXTop10(){
  const amt=parseFloat($('fx-amount').value)||1;
  const container=$('fx-top10');if(!container)return;
  container.innerHTML=FX_TOP10.map(code=>{
    const c=FX_CURRENCIES.find(x=>x.code===code);if(!c||!fxRates[code])return'';
    const rate=fxRates[code];const converted=(rate*amt);
    return`<div class="fx-top-card" onclick="document.getElementById('fx-search').value='${code}';filterFX()">
      <div style="font-size:26px">${c.flag}</div>
      <div><div style="font-weight:700;font-size:13px">${c.country}</div><div style="color:var(--gold);font-size:11px;font-weight:600">${c.code}</div></div>
      <div style="text-align:right"><div style="font-weight:800;font-size:14px;color:var(--gold)">${converted>=100?converted.toLocaleString(undefined,{maximumFractionDigits:0}):converted.toFixed(2)}</div><div style="color:var(--muted);font-size:10px">per $${amt}</div></div>
    </div>`;
  }).join('');
}

function sortFX(col){
  if(fxSortCol===col)fxSortDir*=-1;else{fxSortCol=col;fxSortDir=1;}
  filterFX();
}
function filterFX(){
  const q=($('fx-search').value||'').toLowerCase();
  const amt=parseFloat($('fx-amount').value)||1;
  let rows=FX_CURRENCIES.filter((c,i,arr)=>arr.findIndex(x=>x.code===c.code)===i); // dedupe
  if(q) rows=rows.filter(c=>c.country.toLowerCase().includes(q)||c.code.toLowerCase().includes(q));
  rows=rows.filter(c=>fxRates[c.code]);
  rows.sort((a,b)=>{
    let av,bv;
    if(fxSortCol==='rate'){av=fxRates[a.code]||0;bv=fxRates[b.code]||0;}
    else if(fxSortCol==='usd'){av=1/(fxRates[a.code]||1);bv=1/(fxRates[b.code]||1);}
    else if(fxSortCol==='code'){av=a.code;bv=b.code;}
    else{av=a.country;bv=b.country;}
    if(typeof av==='string')return av.localeCompare(bv)*fxSortDir;
    return(av-bv)*fxSortDir;
  });
  $('fx-tbody').innerHTML=rows.map(c=>{
    const rate=fxRates[c.code];
    if(!rate)return'';
    const usdVal=(amt/rate);
    const converted=(rate*amt);
    return`<tr>
      <td style="font-size:22px;text-align:center">${c.flag}</td>
      <td style="font-weight:600">${c.country}</td>
      <td style="font-family:var(--mono);color:var(--gold)">${c.code}</td>
      <td style="font-family:var(--mono)">${rate>=1?rate.toLocaleString(undefined,{maximumFractionDigits:4}):rate.toFixed(6)}</td>
      <td style="font-family:var(--mono);color:#aaa">$${usdVal.toFixed(4)}</td>
      <td style="font-family:var(--mono);color:var(--gold);font-weight:700">${converted>=1?converted.toLocaleString(undefined,{maximumFractionDigits:2}):converted.toFixed(4)} ${c.code}</td>
    </tr>`;
  }).join('');
  if(!rows.length&&q)$('fx-status').textContent='No currencies match your search.';
  else $('fx-status').textContent='';
  renderFXTop10();
}



function buildFXDropdown(){
  const sel=$('fx-dropdown');if(!sel)return;
  FX_CURRENCIES.forEach(c=>{const o=document.createElement('option');o.value=c.code;o.textContent=c.flag+' '+c.country+' ('+c.code+')';sel.appendChild(o);});
}
function fxDropdownChange(){
  const v=$('fx-dropdown').value;
  $('fx-search').value=v||'';filterFX();
}
// ══════════════════════════════════════════════════════════════
// TRADING SHEET
// ══════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════
// TYPE SET TRACKER
// ════════════════════════════════════════════════════════════════
const TS_SETS = {
  '20th': {
    title: '20th Century Type Set',
    desc: 'One example of each major US coin design issued 1900–2000',
    sections: [
      { heading: 'Cents', coins: [
        {id:'ihc',name:'Indian Head Cent',years:'1859–1909',note:'Final year 1909 most common'},
        {id:'linc_wheat',name:'Lincoln Wheat Cent',years:'1909–1958',note:'Wheat reverse'},
        {id:'linc_mem',name:'Lincoln Memorial Cent',years:'1959–2008',note:'Memorial reverse'},
      ]},
      { heading: 'Nickels', coins: [
        {id:'lib_nickel',name:'Liberty V Nickel',years:'1883–1912',note:''},
        {id:'buffalo',name:'Buffalo Nickel',years:'1913–1938',note:'Indian Head / Bison'},
        {id:'jefferson_war',name:'Jefferson Nickel (War)',years:'1942–1945',note:'35% silver'},
        {id:'jefferson',name:'Jefferson Nickel',years:'1938–2003',note:''},
      ]},
      { heading: 'Dimes', coins: [
        {id:'barber_dime',name:'Barber Dime',years:'1892–1916',note:''},
        {id:'mercury_dime',name:'Mercury Dime',years:'1916–1945',note:'90% silver'},
        {id:'roose_dime',name:'Roosevelt Dime',years:'1946–present',note:'90% silver pre-1965'},
      ]},
      { heading: 'Quarters', coins: [
        {id:'barber_q',name:'Barber Quarter',years:'1892–1916',note:''},
        {id:'slq',name:'Standing Liberty Quarter',years:'1916–1930',note:'90% silver'},
        {id:'wash_q',name:'Washington Quarter',years:'1932–present',note:'90% silver pre-1965'},
      ]},
      { heading: 'Half Dollars', coins: [
        {id:'barber_h',name:'Barber Half Dollar',years:'1892–1915',note:''},
        {id:'walking_lib',name:'Walking Liberty Half',years:'1916–1947',note:'90% silver'},
        {id:'franklin',name:'Franklin Half Dollar',years:'1948–1963',note:'90% silver'},
        {id:'kennedy_90',name:'Kennedy Half — 90%',years:'1964',note:'Key — first year'},
        {id:'kennedy_40',name:'Kennedy Half — 40%',years:'1965–1970',note:'40% silver'},
        {id:'kennedy_clad',name:'Kennedy Half — Clad',years:'1971–present',note:''},
      ]},
      { heading: 'Dollars', coins: [
        {id:'morgan',name:'Morgan Dollar',years:'1878–1921',note:'90% silver'},
        {id:'peace',name:'Peace Dollar',years:'1921–1935',note:'90% silver'},
        {id:'ike',name:'Eisenhower Dollar',years:'1971–1978',note:'40% silver proofs'},
        {id:'sba',name:'Susan B. Anthony Dollar',years:'1979–1981, 1999',note:''},
        {id:'sacagawea',name:'Sacagawea Dollar',years:'2000–present',note:''},
      ]},
    ]
  },
  'lincoln': {
    title: 'Lincoln Cent Set',
    desc: 'Major date/mintmark combinations of the Lincoln cent series',
    sections: [
      { heading: 'Wheat Cents — Philadelphia', coins: [
        {id:'lc_1909',name:'1909 VDB',years:'1909',note:'Key date — first year'},
        {id:'lc_1914',name:'1914',years:'1914-P',note:'Scarce P-mint'},
        {id:'lc_1922',name:'1922 Plain',years:'1922',note:'No D — weak die'},
        {id:'lc_1931',name:'1931',years:'1931-P',note:'Low mintage'},
        {id:'lc_1943_steel',name:'1943 Steel',years:'1943',note:'Wartime steel planchet'},
        {id:'lc_1944',name:'1944',years:'1944-P',note:'Shell case bronze'},
        {id:'lc_1955_dbl',name:'1955 Doubled Die',years:'1955',note:'Famous error'},
        {id:'lc_1958',name:'1958',years:'1958-P',note:'Last wheat cent'},
      ]},
      { heading: 'Wheat Cents — Denver', coins: [
        {id:'lc_1909d',name:'1909-D',years:'1909-D',note:''},
        {id:'lc_1914d',name:'1914-D',years:'1914-D',note:'Key date'},
        {id:'lc_1922d',name:'1922-D',years:'1922-D',note:'Normal D-mint'},
        {id:'lc_1931d',name:'1931-D',years:'1931-D',note:''},
        {id:'lc_1943d',name:'1943-D Steel',years:'1943-D',note:''},
      ]},
      { heading: 'Wheat Cents — San Francisco', coins: [
        {id:'lc_1909s_vdb',name:'1909-S VDB',years:'1909-S',note:'Rarest wheat cent'},
        {id:'lc_1909s',name:'1909-S',years:'1909-S',note:'Key date'},
        {id:'lc_1914s',name:'1914-S',years:'1914-S',note:''},
        {id:'lc_1924s',name:'1924-S',years:'1924-S',note:'Scarce'},
        {id:'lc_1931s',name:'1931-S',years:'1931-S',note:'Key date'},
      ]},
      { heading: 'Memorial Cents — Key Dates', coins: [
        {id:'lc_1960s',name:'1960-D Small Date',years:'1960-D',note:'Variety'},
        {id:'lc_1969s_dbl',name:'1969-S Doubled Die',years:'1969-S',note:'Rare error'},
        {id:'lc_1972_dbl',name:'1972 Doubled Die',years:'1972',note:'Notable error'},
        {id:'lc_1983_dbl',name:'1983 Doubled Die Reverse',years:'1983',note:''},
        {id:'lc_1995_dbl',name:'1995 Doubled Die',years:'1995',note:'Last notable DDO'},
      ]},
    ]
  },
  'morgan': {
    title: 'Morgan Dollar Set',
    desc: 'Complete date/mintmark set 1878–1921',
    sections: [
      { heading: 'Philadelphia Mint', coins: [
        {id:'mo_1878_8tf',name:'1878 8 Tail Feathers',years:'1878',note:'First year, variety'},
        {id:'mo_1878_7tf',name:'1878 7 Tail Feathers',years:'1878',note:'Variety'},
        {id:'mo_1879',name:'1879',years:'1879-P',note:''},
        {id:'mo_1880',name:'1880',years:'1880-P',note:''},
        {id:'mo_1881',name:'1881',years:'1881-P',note:''},
        {id:'mo_1882',name:'1882',years:'1882-P',note:''},
        {id:'mo_1883',name:'1883',years:'1883-P',note:''},
        {id:'mo_1884',name:'1884',years:'1884-P',note:''},
        {id:'mo_1885',name:'1885',years:'1885-P',note:''},
        {id:'mo_1886',name:'1886',years:'1886-P',note:''},
        {id:'mo_1887',name:'1887',years:'1887-P',note:''},
        {id:'mo_1888',name:'1888',years:'1888-P',note:''},
        {id:'mo_1889',name:'1889',years:'1889-P',note:''},
        {id:'mo_1890',name:'1890',years:'1890-P',note:''},
        {id:'mo_1891',name:'1891',years:'1891-P',note:''},
        {id:'mo_1892',name:'1892',years:'1892-P',note:''},
        {id:'mo_1893',name:'1893',years:'1893-P',note:'Key date'},
        {id:'mo_1894',name:'1894',years:'1894-P',note:'Key date — rare'},
        {id:'mo_1895_proof',name:'1895 Proof',years:'1895',note:'Rarest Morgan'},
        {id:'mo_1896',name:'1896',years:'1896-P',note:''},
        {id:'mo_1897',name:'1897',years:'1897-P',note:''},
        {id:'mo_1898',name:'1898',years:'1898-P',note:''},
        {id:'mo_1899',name:'1899',years:'1899-P',note:'Semi-key'},
        {id:'mo_1900',name:'1900',years:'1900-P',note:''},
        {id:'mo_1901',name:'1901',years:'1901-P',note:'Key date'},
        {id:'mo_1902',name:'1902',years:'1902-P',note:''},
        {id:'mo_1903',name:'1903',years:'1903-P',note:''},
        {id:'mo_1904',name:'1904',years:'1904-P',note:''},
        {id:'mo_1921',name:'1921',years:'1921-P',note:'Last year'},
      ]},
      { heading: 'New Orleans Mint', coins: [
        {id:'mo_1879o',name:'1879-O',years:'1879-O',note:''},
        {id:'mo_1882o',name:'1882-O',years:'1882-O',note:''},
        {id:'mo_1884o',name:'1884-O',years:'1884-O',note:'Common date'},
        {id:'mo_1885o',name:'1885-O',years:'1885-O',note:'Common date'},
        {id:'mo_1893o',name:'1893-O',years:'1893-O',note:'Key date'},
        {id:'mo_1894o',name:'1894-O',years:'1894-O',note:'Key date'},
        {id:'mo_1895o',name:'1895-O',years:'1895-O',note:'Key date'},
        {id:'mo_1897o',name:'1897-O',years:'1897-O',note:''},
        {id:'mo_1898o',name:'1898-O',years:'1898-O',note:'Common'},
        {id:'mo_1900o',name:'1900-O',years:'1900-O',note:''},
        {id:'mo_1904o',name:'1904-O',years:'1904-O',note:'Common date'},
      ]},
      { heading: 'San Francisco Mint', coins: [
        {id:'mo_1879s',name:'1879-S',years:'1879-S',note:''},
        {id:'mo_1881s',name:'1881-S',years:'1881-S',note:'Common date'},
        {id:'mo_1883s',name:'1883-S',years:'1883-S',note:'Key date'},
        {id:'mo_1884s',name:'1884-S',years:'1884-S',note:'Key date'},
        {id:'mo_1892s',name:'1892-S',years:'1892-S',note:'Key date'},
        {id:'mo_1893s',name:'1893-S',years:'1893-S',note:'King of Morgans'},
        {id:'mo_1894s',name:'1894-S',years:'1894-S',note:''},
        {id:'mo_1895s',name:'1895-S',years:'1895-S',note:'Key date'},
        {id:'mo_1901s',name:'1901-S',years:'1901-S',note:''},
        {id:'mo_1903s',name:'1903-S',years:'1903-S',note:'Key date'},
        {id:'mo_1904s',name:'1904-S',years:'1904-S',note:''},
      ]},
      { heading: 'Carson City Mint', coins: [
        {id:'mo_1878cc',name:'1878-CC',years:'1878-CC',note:''},
        {id:'mo_1879cc',name:'1879-CC',years:'1879-CC',note:'Key date'},
        {id:'mo_1882cc',name:'1882-CC',years:'1882-CC',note:''},
        {id:'mo_1883cc',name:'1883-CC',years:'1883-CC',note:''},
        {id:'mo_1884cc',name:'1884-CC',years:'1884-CC',note:''},
        {id:'mo_1885cc',name:'1885-CC',years:'1885-CC',note:''},
        {id:'mo_1889cc',name:'1889-CC',years:'1889-CC',note:'Key date'},
        {id:'mo_1890cc',name:'1890-CC',years:'1890-CC',note:''},
        {id:'mo_1891cc',name:'1891-CC',years:'1891-CC',note:''},
        {id:'mo_1892cc',name:'1892-CC',years:'1892-CC',note:''},
        {id:'mo_1893cc',name:'1893-CC',years:'1893-CC',note:'Key date'},
      ]},
    ]
  },
  'peace': {
    title: 'Peace Dollar Set',
    desc: 'Complete date/mintmark set 1921–1935',
    sections: [
      { heading: 'Philadelphia Mint', coins: [
        {id:'pd_1921',name:'1921',years:'1921-P',note:'Key date — first year'},
        {id:'pd_1922',name:'1922',years:'1922-P',note:'High relief variety'},
        {id:'pd_1923',name:'1923',years:'1923-P',note:'Common'},
        {id:'pd_1924',name:'1924',years:'1924-P',note:''},
        {id:'pd_1925',name:'1925',years:'1925-P',note:''},
        {id:'pd_1926',name:'1926',years:'1926-P',note:''},
        {id:'pd_1927',name:'1927',years:'1927-P',note:'Semi-key'},
        {id:'pd_1928',name:'1928',years:'1928-P',note:'Key date'},
        {id:'pd_1934',name:'1934',years:'1934-P',note:''},
        {id:'pd_1935',name:'1935',years:'1935-P',note:'Last year'},
      ]},
      { heading: 'San Francisco Mint', coins: [
        {id:'pd_1922s',name:'1922-S',years:'1922-S',note:''},
        {id:'pd_1923s',name:'1923-S',years:'1923-S',note:''},
        {id:'pd_1924s',name:'1924-S',years:'1924-S',note:''},
        {id:'pd_1925s',name:'1925-S',years:'1925-S',note:''},
        {id:'pd_1926s',name:'1926-S',years:'1926-S',note:''},
        {id:'pd_1927s',name:'1927-S',years:'1927-S',note:''},
        {id:'pd_1928s',name:'1928-S',years:'1928-S',note:''},
        {id:'pd_1934s',name:'1934-S',years:'1934-S',note:'Key date'},
        {id:'pd_1935s',name:'1935-S',years:'1935-S',note:''},
      ]},
      { heading: 'Denver Mint', coins: [
        {id:'pd_1922d',name:'1922-D',years:'1922-D',note:''},
        {id:'pd_1923d',name:'1923-D',years:'1923-D',note:'Semi-key'},
        {id:'pd_1925d',name:'1925-D',years:'1925-D',note:''},
        {id:'pd_1926d',name:'1926-D',years:'1926-D',note:''},
        {id:'pd_1927d',name:'1927-D',years:'1927-D',note:'Key date'},
        {id:'pd_1928d',name:'1928-D',years:'1928-D',note:''},
        {id:'pd_1934d',name:'1934-D',years:'1934-D',note:''},
        {id:'pd_1935d',name:'1935-D',years:'1935-D',note:''},
      ]},
    ]
  },
  'mercury': {
    title: 'Mercury Dime Set',
    desc: 'Complete date/mintmark set 1916–1945 — all 90% silver',
    sections: [
      { heading: 'Key Dates & Semi-Keys', coins: [
        {id:'md_1916d',name:'1916-D',years:'1916-D',note:'King of Mercury Dimes'},
        {id:'md_1921',name:'1921',years:'1921-P',note:'Key date'},
        {id:'md_1921d',name:'1921-D',years:'1921-D',note:'Key date'},
        {id:'md_1926s',name:'1926-S',years:'1926-S',note:'Key date'},
        {id:'md_1931d',name:'1931-D',years:'1931-D',note:'Semi-key'},
        {id:'md_1931s',name:'1931-S',years:'1931-S',note:'Semi-key'},
        {id:'md_1942_41',name:'1942/41 DDO',years:'1942/41',note:'Famous overdate error'},
      ]},
      { heading: 'Philadelphia Mint', coins: [
        {id:'md_1916',name:'1916-P',years:'1916-P',note:'First year'},
        {id:'md_1917',name:'1917-P',years:'1917-P',note:''},
        {id:'md_1918',name:'1918-P',years:'1918-P',note:''},
        {id:'md_1919',name:'1919-P',years:'1919-P',note:''},
        {id:'md_1920',name:'1920-P',years:'1920-P',note:''},
        {id:'md_1923',name:'1923-P',years:'1923-P',note:''},
        {id:'md_1924',name:'1924-P',years:'1924-P',note:''},
        {id:'md_1925',name:'1925-P',years:'1925-P',note:''},
        {id:'md_1930',name:'1930-P',years:'1930-P',note:''},
        {id:'md_1935',name:'1935-P',years:'1935-P',note:''},
        {id:'md_1940',name:'1940-P',years:'1940-P',note:''},
        {id:'md_1945',name:'1945-P',years:'1945-P',note:'Last year'},
      ]},
      { heading: 'Denver & San Francisco', coins: [
        {id:'md_1917d',name:'1917-D',years:'1917-D',note:''},
        {id:'md_1920d',name:'1920-D',years:'1920-D',note:''},
        {id:'md_1925d',name:'1925-D',years:'1925-D',note:''},
        {id:'md_1935d',name:'1935-D',years:'1935-D',note:''},
        {id:'md_1942d',name:'1942-D',years:'1942-D',note:''},
        {id:'md_1917s',name:'1917-S',years:'1917-S',note:''},
        {id:'md_1920s',name:'1920-S',years:'1920-S',note:''},
        {id:'md_1923s',name:'1923-S',years:'1923-S',note:''},
        {id:'md_1927s',name:'1927-S',years:'1927-S',note:''},
        {id:'md_1934s',name:'1934-S',years:'1934-S',note:''},
        {id:'md_1945s',name:'1945-S',years:'1945-S',note:'Micro-S variety'},
      ]},
    ]
  },
  'walkliberty': {
    title: 'Walking Liberty Half Dollar Set',
    desc: 'Complete date/mintmark set 1916–1947 — all 90% silver',
    sections: [
      { heading: 'Key & Semi-Key Dates', coins: [
        {id:'wlh_1916',name:'1916-P',years:'1916',note:'First year — key date'},
        {id:'wlh_1916d_obv',name:'1916-D Obverse',years:'1916-D',note:'D on obverse — key'},
        {id:'wlh_1916s',name:'1916-S',years:'1916-S',note:'Key date'},
        {id:'wlh_1917d_obv',name:'1917-D Obverse',years:'1917-D',note:'D on obverse'},
        {id:'wlh_1917s_obv',name:'1917-S Obverse',years:'1917-S',note:'S on obverse'},
        {id:'wlh_1919',name:'1919-P',years:'1919',note:'Semi-key'},
        {id:'wlh_1919d',name:'1919-D',years:'1919-D',note:'Key date'},
        {id:'wlh_1919s',name:'1919-S',years:'1919-S',note:'Key date'},
        {id:'wlh_1921',name:'1921-P',years:'1921',note:'Key date'},
        {id:'wlh_1921d',name:'1921-D',years:'1921-D',note:'Key date'},
        {id:'wlh_1921s',name:'1921-S',years:'1921-S',note:'Key date'},
        {id:'wlh_1938d',name:'1938-D',years:'1938-D',note:'Key date — lowest mintage'},
      ]},
      { heading: 'Philadelphia — Common Dates', coins: [
        {id:'wlh_1917',name:'1917-P',years:'1917',note:''},
        {id:'wlh_1918',name:'1918-P',years:'1918',note:''},
        {id:'wlh_1920',name:'1920-P',years:'1920',note:''},
        {id:'wlh_1941',name:'1941-P',years:'1941',note:''},
        {id:'wlh_1942',name:'1942-P',years:'1942',note:''},
        {id:'wlh_1943',name:'1943-P',years:'1943',note:''},
        {id:'wlh_1945',name:'1945-P',years:'1945',note:''},
        {id:'wlh_1946',name:'1946-P',years:'1946',note:''},
        {id:'wlh_1947',name:'1947-P',years:'1947',note:'Last year'},
      ]},
      { heading: 'Denver & San Francisco', coins: [
        {id:'wlh_1917d_rev',name:'1917-D Reverse',years:'1917-D',note:'D on reverse'},
        {id:'wlh_1918d',name:'1918-D',years:'1918-D',note:''},
        {id:'wlh_1920d',name:'1920-D',years:'1920-D',note:''},
        {id:'wlh_1941d',name:'1941-D',years:'1941-D',note:''},
        {id:'wlh_1942d',name:'1942-D',years:'1942-D',note:''},
        {id:'wlh_1917s_rev',name:'1917-S Reverse',years:'1917-S',note:'S on reverse'},
        {id:'wlh_1918s',name:'1918-S',years:'1918-S',note:''},
        {id:'wlh_1923s',name:'1923-S',years:'1923-S',note:'Semi-key'},
        {id:'wlh_1927s',name:'1927-S',years:'1927-S',note:'Semi-key'},
        {id:'wlh_1941s',name:'1941-S',years:'1941-S',note:''},
        {id:'wlh_1942s',name:'1942-S',years:'1942-S',note:''},
        {id:'wlh_1943s',name:'1943-S',years:'1943-S',note:''},
        {id:'wlh_1945d',name:'1945-D',years:'1945-D',note:''},
        {id:'wlh_1946d',name:'1946-D',years:'1946-D',note:''},
        {id:'wlh_1947d',name:'1947-D',years:'1947-D',note:'Last Denver'},
      ]},
    ]
  },
  'slq': {
    title: 'Standing Liberty Quarter Set',
    desc: 'Complete date/mintmark set 1916–1930 — all 90% silver',
    sections: [
      { heading: 'Key Dates', coins: [
        {id:'slq_1916',name:'1916',years:'1916',note:'Rarest SLQ — key date'},
        {id:'slq_1918_7',name:'1918/17-D',years:'1918/17-D',note:'Famous overdate'},
        {id:'slq_1918_7s',name:'1918/17-S',years:'1918/17-S',note:'Overdate S-mint'},
        {id:'slq_1919d',name:'1919-D',years:'1919-D',note:'Key date'},
        {id:'slq_1919s',name:'1919-S',years:'1919-S',note:'Key date'},
        {id:'slq_1921',name:'1921',years:'1921',note:'Key date'},
        {id:'slq_1923s',name:'1923-S',years:'1923-S',note:'Key date'},
        {id:'slq_1926s',name:'1926-S',years:'1926-S',note:'Semi-key'},
        {id:'slq_1927s',name:'1927-S',years:'1927-S',note:'Key date'},
      ]},
      { heading: 'Philadelphia Mint', coins: [
        {id:'slq_1917_t1',name:'1917 Type 1',years:'1917',note:'Bare breast design'},
        {id:'slq_1917_t2',name:'1917 Type 2',years:'1917',note:'Mail coat design'},
        {id:'slq_1918',name:'1918',years:'1918-P',note:''},
        {id:'slq_1919',name:'1919',years:'1919-P',note:''},
        {id:'slq_1920',name:'1920',years:'1920-P',note:''},
        {id:'slq_1924',name:'1924',years:'1924-P',note:''},
        {id:'slq_1925',name:'1925',years:'1925-P',note:''},
        {id:'slq_1926',name:'1926',years:'1926-P',note:''},
        {id:'slq_1927',name:'1927',years:'1927-P',note:''},
        {id:'slq_1928',name:'1928',years:'1928-P',note:''},
        {id:'slq_1929',name:'1929',years:'1929-P',note:''},
        {id:'slq_1930',name:'1930',years:'1930-P',note:'Last year'},
      ]},
      { heading: 'Denver & San Francisco', coins: [
        {id:'slq_1917d_t1',name:'1917-D Type 1',years:'1917-D',note:''},
        {id:'slq_1917d_t2',name:'1917-D Type 2',years:'1917-D',note:''},
        {id:'slq_1918d',name:'1918-D',years:'1918-D',note:''},
        {id:'slq_1920d',name:'1920-D',years:'1920-D',note:''},
        {id:'slq_1917s_t1',name:'1917-S Type 1',years:'1917-S',note:''},
        {id:'slq_1917s_t2',name:'1917-S Type 2',years:'1917-S',note:''},
        {id:'slq_1918s',name:'1918-S',years:'1918-S',note:''},
        {id:'slq_1920s',name:'1920-S',years:'1920-S',note:'Semi-key'},
        {id:'slq_1924d',name:'1924-D',years:'1924-D',note:''},
        {id:'slq_1924s',name:'1924-S',years:'1924-S',note:''},
        {id:'slq_1925d',name:'1925-D',years:'1925-D',note:''},
        {id:'slq_1930d',name:'1930-D',years:'1930-D',note:''},
        {id:'slq_1930s',name:'1930-S',years:'1930-S',note:''},
      ]},
    ]
  },
  'buffalo': {
    title: 'Buffalo Nickel Set',
    desc: 'Complete date/mintmark set 1913–1938',
    sections: [
      { heading: 'Key & Semi-Key Dates', coins: [
        {id:'bn_1913_t1',name:'1913 Type 1',years:'1913',note:'Mound reverse'},
        {id:'bn_1913_t2',name:'1913 Type 2',years:'1913',note:'Plain ground reverse'},
        {id:'bn_1913s_t2',name:'1913-S Type 2',years:'1913-S',note:'Key date'},
        {id:'bn_1913d_t2',name:'1913-D Type 2',years:'1913-D',note:'Key date'},
        {id:'bn_1914',name:'1914',years:'1914-P',note:'Semi-key'},
        {id:'bn_1916_dbl',name:'1916 Doubled Die',years:'1916',note:'Famous DDO error'},
        {id:'bn_1918_7d',name:'1918/17-D',years:'1918/17-D',note:'Overdate key'},
        {id:'bn_1921s',name:'1921-S',years:'1921-S',note:'Semi-key'},
        {id:'bn_1924s',name:'1924-S',years:'1924-S',note:'Semi-key'},
        {id:'bn_1926s',name:'1926-S',years:'1926-S',note:'Key date'},
        {id:'bn_1937d_3leg',name:'1937-D 3-Legged',years:'1937-D',note:'Famous die error'},
      ]},
      { heading: 'Philadelphia Mint', coins: [
        {id:'bn_1914p',name:'1914-P',years:'1914',note:''},
        {id:'bn_1915',name:'1915-P',years:'1915',note:''},
        {id:'bn_1918',name:'1918-P',years:'1918',note:''},
        {id:'bn_1920',name:'1920-P',years:'1920',note:''},
        {id:'bn_1923',name:'1923-P',years:'1923',note:''},
        {id:'bn_1925',name:'1925-P',years:'1925',note:''},
        {id:'bn_1928',name:'1928-P',years:'1928',note:''},
        {id:'bn_1934',name:'1934-P',years:'1934',note:''},
        {id:'bn_1936',name:'1936-P',years:'1936',note:''},
        {id:'bn_1938',name:'1938-P',years:'1938',note:'Last year P-mint'},
      ]},
      { heading: 'Denver & San Francisco', coins: [
        {id:'bn_1913d_t1',name:'1913-D Type 1',years:'1913-D',note:''},
        {id:'bn_1914d',name:'1914-D',years:'1914-D',note:'Key date'},
        {id:'bn_1918d',name:'1918-D',years:'1918-D',note:''},
        {id:'bn_1920d',name:'1920-D',years:'1920-D',note:''},
        {id:'bn_1936d',name:'1936-D',years:'1936-D',note:''},
        {id:'bn_1938d',name:'1938-D',years:'1938-D',note:'Last year Denver'},
        {id:'bn_1917s',name:'1917-S',years:'1917-S',note:''},
        {id:'bn_1919s',name:'1919-S',years:'1919-S',note:''},
        {id:'bn_1920s',name:'1920-S',years:'1920-S',note:''},
        {id:'bn_1923s',name:'1923-S',years:'1923-S',note:''},
        {id:'bn_1925s',name:'1925-S',years:'1925-S',note:''},
        {id:'bn_1927s',name:'1927-S',years:'1927-S',note:''},
      ]},
    ]
  },
  'barber': {
    title: 'Barber Series Set',
    desc: 'Barber Dimes, Quarters, and Half Dollars 1892–1916',
    sections: [
      { heading: 'Barber Dimes — Key Dates', coins: [
        {id:'bd_1895o',name:'1895-O Dime',years:'1895-O',note:'Key date'},
        {id:'bd_1896s',name:'1896-S Dime',years:'1896-S',note:'Key date'},
        {id:'bd_1901s',name:'1901-S Dime',years:'1901-S',note:'Key date'},
        {id:'bd_1903s',name:'1903-S Dime',years:'1903-S',note:'Key date'},
        {id:'bd_1913s',name:'1913-S Dime',years:'1913-S',note:'Key date'},
        {id:'bd_1916s_d',name:'1916-S Dime',years:'1916-S',note:'Last Barber dime'},
      ]},
      { heading: 'Barber Quarters — Key Dates', coins: [
        {id:'bq_1896s',name:'1896-S Quarter',years:'1896-S',note:'Key date'},
        {id:'bq_1901s',name:'1901-S Quarter',years:'1901-S',note:'Rarest Barber quarter'},
        {id:'bq_1913s',name:'1913-S Quarter',years:'1913-S',note:'Key date'},
        {id:'bq_1914s',name:'1914-S Quarter',years:'1914-S',note:'Key date'},
        {id:'bq_1896o',name:'1896-O Quarter',years:'1896-O',note:'Semi-key'},
      ]},
      { heading: 'Barber Half Dollars — Key Dates', coins: [
        {id:'bh_1892o',name:'1892-O Half',years:'1892-O',note:'Key date — first year O-mint'},
        {id:'bh_1892s',name:'1892-S Half',years:'1892-S',note:'Key date'},
        {id:'bh_1893s',name:'1893-S Half',years:'1893-S',note:'Semi-key'},
        {id:'bh_1897o',name:'1897-O Half',years:'1897-O',note:'Key date'},
        {id:'bh_1897s',name:'1897-S Half',years:'1897-S',note:'Key date'},
        {id:'bh_1914',name:'1914 Half',years:'1914-P',note:'Key date — low mintage'},
        {id:'bh_1915',name:'1915 Half',years:'1915-P',note:'Last Barber half'},
      ]},
      { heading: 'Barber Type Coins (one each)', coins: [
        {id:'bt_dime',name:'Barber Dime — Type',years:'1892–1916',note:'Any date/mint'},
        {id:'bt_quarter',name:'Barber Quarter — Type',years:'1892–1916',note:'Any date/mint'},
        {id:'bt_half',name:'Barber Half — Type',years:'1892–1915',note:'Any date/mint'},
      ]},
    ]
  },
  'silver90': {
    title: '90% Silver Type Set',
    desc: 'One example of each 90% silver US coin type — excellent starter set',
    sections: [
      { heading: 'Dimes', coins: [
        {id:'s90_seated_d',name:'Seated Liberty Dime',years:'1837–1891',note:'90% silver'},
        {id:'s90_barber_d',name:'Barber Dime',years:'1892–1916',note:'90% silver'},
        {id:'s90_mercury_d',name:'Mercury Dime',years:'1916–1945',note:'90% silver'},
        {id:'s90_roose_d',name:'Roosevelt Dime',years:'1946–1964',note:'90% silver pre-1965'},
      ]},
      { heading: 'Quarters', coins: [
        {id:'s90_seated_q',name:'Seated Liberty Quarter',years:'1838–1891',note:'90% silver'},
        {id:'s90_barber_q',name:'Barber Quarter',years:'1892–1916',note:'90% silver'},
        {id:'s90_slq',name:'Standing Liberty Quarter',years:'1916–1930',note:'90% silver'},
        {id:'s90_wash_q',name:'Washington Quarter',years:'1932–1964',note:'90% silver'},
      ]},
      { heading: 'Half Dollars', coins: [
        {id:'s90_seated_h',name:'Seated Liberty Half',years:'1839–1891',note:'90% silver'},
        {id:'s90_barber_h',name:'Barber Half Dollar',years:'1892–1915',note:'90% silver'},
        {id:'s90_walking_h',name:'Walking Liberty Half',years:'1916–1947',note:'90% silver'},
        {id:'s90_franklin',name:'Franklin Half Dollar',years:'1948–1963',note:'90% silver'},
        {id:'s90_kennedy_64',name:'Kennedy Half 1964',years:'1964',note:'90% silver — first year'},
      ]},
      { heading: 'Dollars', coins: [
        {id:'s90_seated_dol',name:'Seated Liberty Dollar',years:'1840–1873',note:'90% silver'},
        {id:'s90_trade',name:'Trade Dollar',years:'1873–1885',note:'90% silver'},
        {id:'s90_morgan',name:'Morgan Dollar',years:'1878–1921',note:'90% silver'},
        {id:'s90_peace',name:'Peace Dollar',years:'1921–1935',note:'90% silver'},
      ]},
      { heading: 'Other Silver Types', coins: [
        {id:'s90_3cent',name:'3-Cent Silver',years:'1851–1873',note:'75% silver'},
        {id:'s90_halfime',name:'Half Dime',years:'1794–1873',note:'90% silver'},
        {id:'s90_20cent',name:'20-Cent Piece',years:'1875–1878',note:'90% silver'},
        {id:'s90_capped_bust',name:'Capped Bust Half',years:'1807–1839',note:'89.25% silver'},
        {id:'s90_draped_bust',name:'Draped Bust Dollar',years:'1795–1804',note:'Early silver dollar'},
      ]},
    ]
  },
  'statequarters': {
    title: 'State Quarters Set',
    desc: 'All 50 State Quarters 1999–2008',
    sections: [
      { heading: '1999', coins: [
        {id:'sq_de',name:'Delaware',years:'1999',note:'First State'},
        {id:'sq_pa',name:'Pennsylvania',years:'1999',note:''},
        {id:'sq_nj',name:'New Jersey',years:'1999',note:''},
        {id:'sq_ga',name:'Georgia',years:'1999',note:''},
        {id:'sq_ct',name:'Connecticut',years:'1999',note:''},
      ]},
      { heading: '2000', coins: [
        {id:'sq_ma',name:'Massachusetts',years:'2000',note:''},
        {id:'sq_md',name:'Maryland',years:'2000',note:''},
        {id:'sq_sc',name:'South Carolina',years:'2000',note:''},
        {id:'sq_nh',name:'New Hampshire',years:'2000',note:''},
        {id:'sq_va',name:'Virginia',years:'2000',note:''},
      ]},
      { heading: '2001', coins: [
        {id:'sq_ny',name:'New York',years:'2001',note:''},
        {id:'sq_nc',name:'North Carolina',years:'2001',note:''},
        {id:'sq_ri',name:'Rhode Island',years:'2001',note:''},
        {id:'sq_vt',name:'Vermont',years:'2001',note:''},
        {id:'sq_ky',name:'Kentucky',years:'2001',note:''},
      ]},
      { heading: '2002', coins: [
        {id:'sq_tn',name:'Tennessee',years:'2002',note:''},
        {id:'sq_oh',name:'Ohio',years:'2002',note:''},
        {id:'sq_la',name:'Louisiana',years:'2002',note:''},
        {id:'sq_in',name:'Indiana',years:'2002',note:''},
        {id:'sq_ms',name:'Mississippi',years:'2002',note:''},
      ]},
      { heading: '2003', coins: [
        {id:'sq_il',name:'Illinois',years:'2003',note:''},
        {id:'sq_al',name:'Alabama',years:'2003',note:''},
        {id:'sq_me',name:'Maine',years:'2003',note:''},
        {id:'sq_mo_q',name:'Missouri',years:'2003',note:''},
        {id:'sq_ar',name:'Arkansas',years:'2003',note:''},
      ]},
      { heading: '2004', coins: [
        {id:'sq_mi',name:'Michigan',years:'2004',note:''},
        {id:'sq_fl',name:'Florida',years:'2004',note:''},
        {id:'sq_tx',name:'Texas',years:'2004',note:''},
        {id:'sq_ia',name:'Iowa',years:'2004',note:''},
        {id:'sq_wi',name:'Wisconsin',years:'2004',note:'Extra leaf error'},
      ]},
      { heading: '2005', coins: [
        {id:'sq_ca',name:'California',years:'2005',note:''},
        {id:'sq_mn',name:'Minnesota',years:'2005',note:''},
        {id:'sq_or',name:'Oregon',years:'2005',note:''},
        {id:'sq_ks',name:'Kansas',years:'2005',note:''},
        {id:'sq_wv',name:'West Virginia',years:'2005',note:''},
      ]},
      { heading: '2006', coins: [
        {id:'sq_nv',name:'Nevada',years:'2006',note:''},
        {id:'sq_ne',name:'Nebraska',years:'2006',note:''},
        {id:'sq_co',name:'Colorado',years:'2006',note:''},
        {id:'sq_nd',name:'North Dakota',years:'2006',note:''},
        {id:'sq_sd',name:'South Dakota',years:'2006',note:''},
      ]},
      { heading: '2007', coins: [
        {id:'sq_mt',name:'Montana',years:'2007',note:''},
        {id:'sq_wa',name:'Washington',years:'2007',note:''},
        {id:'sq_id',name:'Idaho',years:'2007',note:''},
        {id:'sq_wy',name:'Wyoming',years:'2007',note:''},
        {id:'sq_ut',name:'Utah',years:'2007',note:''},
      ]},
      { heading: '2008', coins: [
        {id:'sq_ok',name:'Oklahoma',years:'2008',note:''},
        {id:'sq_nm',name:'New Mexico',years:'2008',note:''},
        {id:'sq_az',name:'Arizona',years:'2008',note:''},
        {id:'sq_ak',name:'Alaska',years:'2008',note:''},
        {id:'sq_hi',name:'Hawaii',years:'2008',note:'Last state quarter'},
      ]},
    ]
  },
  'ase': {
    title: 'American Silver Eagle Set',
    desc: 'Annual issues 1986–present — 1 oz .999 fine silver',
    sections: [
      { heading: '1986–1995', coins: [
        {id:'ase_1986',name:'1986',years:'1986',note:'First year — key'},
        {id:'ase_1987',name:'1987',years:'1987',note:''},
        {id:'ase_1988',name:'1988',years:'1988',note:''},
        {id:'ase_1989',name:'1989',years:'1989',note:''},
        {id:'ase_1990',name:'1990',years:'1990',note:''},
        {id:'ase_1991',name:'1991',years:'1991',note:''},
        {id:'ase_1992',name:'1992',years:'1992',note:''},
        {id:'ase_1993',name:'1993',years:'1993',note:'Low mintage'},
        {id:'ase_1994',name:'1994',years:'1994',note:'Key date — low mintage'},
        {id:'ase_1995',name:'1995',years:'1995',note:''},
      ]},
      { heading: '1996–2005', coins: [
        {id:'ase_1996',name:'1996',years:'1996',note:'Key date — lowest bullion mintage'},
        {id:'ase_1997',name:'1997',years:'1997',note:''},
        {id:'ase_1998',name:'1998',years:'1998',note:''},
        {id:'ase_1999',name:'1999',years:'1999',note:''},
        {id:'ase_2000',name:'2000',years:'2000',note:''},
        {id:'ase_2001',name:'2001',years:'2001',note:''},
        {id:'ase_2002',name:'2002',years:'2002',note:''},
        {id:'ase_2003',name:'2003',years:'2003',note:''},
        {id:'ase_2004',name:'2004',years:'2004',note:''},
        {id:'ase_2005',name:'2005',years:'2005',note:''},
      ]},
      { heading: '2006–2015', coins: [
        {id:'ase_2006',name:'2006',years:'2006',note:'20th anniversary'},
        {id:'ase_2007',name:'2007',years:'2007',note:''},
        {id:'ase_2008',name:'2008',years:'2008',note:''},
        {id:'ase_2009',name:'2009',years:'2009',note:'High mintage year'},
        {id:'ase_2010',name:'2010',years:'2010',note:''},
        {id:'ase_2011',name:'2011',years:'2011',note:'25th anniversary'},
        {id:'ase_2012',name:'2012',years:'2012',note:''},
        {id:'ase_2013',name:'2013',years:'2013',note:''},
        {id:'ase_2014',name:'2014',years:'2014',note:''},
        {id:'ase_2015',name:'2015',years:'2015',note:''},
      ]},
      { heading: '2016–2026', coins: [
        {id:'ase_2016',name:'2016',years:'2016',note:'30th anniversary'},
        {id:'ase_2017',name:'2017',years:'2017',note:''},
        {id:'ase_2018',name:'2018',years:'2018',note:''},
        {id:'ase_2019',name:'2019',years:'2019',note:''},
        {id:'ase_2020',name:'2020',years:'2020',note:''},
        {id:'ase_2021_t1',name:'2021 Type 1',years:'2021',note:'Last Adolph Weinman design'},
        {id:'ase_2021_t2',name:'2021 Type 2',years:'2021',note:'New reverse design'},
        {id:'ase_2022',name:'2022',years:'2022',note:'New design'},
        {id:'ase_2023',name:'2023',years:'2023',note:''},
        {id:'ase_2024',name:'2024',years:'2024',note:''},
        {id:'ase_2025',name:'2025',years:'2025',note:''},
        {id:'ase_2026',name:'2026',years:'2026',note:'40th anniversary'},
      ]},
    ]
  },
  'gae': {
    title: 'American Gold Eagle Set',
    desc: 'Annual US Mint Gold Eagles 1986–present — 91.67% gold (22k)',
    sections: [
      { heading: '1986–1995 (First Decade)', coins: [
        {id:'gae_1986_1oz',name:'1986 $50 Gold Eagle (1 oz)',years:'1986',note:'First year — key'},
        {id:'gae_1986_half',name:'1986 $25 Gold Eagle (½ oz)',years:'1986',note:'First year'},
        {id:'gae_1986_qtr',name:'1986 $10 Gold Eagle (¼ oz)',years:'1986',note:'First year'},
        {id:'gae_1986_tenth',name:'1986 $5 Gold Eagle (1/10 oz)',years:'1986',note:'First year'},
        {id:'gae_1987_1oz',name:'1987 $50 Gold Eagle (1 oz)',years:'1987',note:''},
        {id:'gae_1988_1oz',name:'1988 $50 Gold Eagle (1 oz)',years:'1988',note:''},
        {id:'gae_1989_1oz',name:'1989 $50 Gold Eagle (1 oz)',years:'1989',note:''},
        {id:'gae_1990_1oz',name:'1990 $50 Gold Eagle (1 oz)',years:'1990',note:''},
        {id:'gae_1991_1oz',name:'1991 $50 Gold Eagle (1 oz)',years:'1991',note:''},
        {id:'gae_1992_1oz',name:'1992 $50 Gold Eagle (1 oz)',years:'1992',note:''},
        {id:'gae_1993_1oz',name:'1993 $50 Gold Eagle (1 oz)',years:'1993',note:'Low mintage'},
        {id:'gae_1994_1oz',name:'1994 $50 Gold Eagle (1 oz)',years:'1994',note:'Key date — low mintage'},
        {id:'gae_1995_1oz',name:'1995 $50 Gold Eagle (1 oz)',years:'1995',note:''},
        {id:'gae_1995w_pr',name:'1995-W Proof Gold Eagle Set',years:'1995',note:'10th anniversary — key'},
      ]},
      { heading: '1996–2005', coins: [
        {id:'gae_1996_1oz',name:'1996 $50 Gold Eagle (1 oz)',years:'1996',note:''},
        {id:'gae_1997_1oz',name:'1997 $50 Gold Eagle (1 oz)',years:'1997',note:''},
        {id:'gae_1998_1oz',name:'1998 $50 Gold Eagle (1 oz)',years:'1998',note:''},
        {id:'gae_1999_1oz',name:'1999 $50 Gold Eagle (1 oz)',years:'1999',note:''},
        {id:'gae_1999w_unf',name:'1999-W $50 Unfinished Proof Dies',years:'1999',note:'Error — scarce variety'},
        {id:'gae_2000_1oz',name:'2000 $50 Gold Eagle (1 oz)',years:'2000',note:''},
        {id:'gae_2001_1oz',name:'2001 $50 Gold Eagle (1 oz)',years:'2001',note:''},
        {id:'gae_2002_1oz',name:'2002 $50 Gold Eagle (1 oz)',years:'2002',note:''},
        {id:'gae_2003_1oz',name:'2003 $50 Gold Eagle (1 oz)',years:'2003',note:''},
        {id:'gae_2004_1oz',name:'2004 $50 Gold Eagle (1 oz)',years:'2004',note:''},
        {id:'gae_2005_1oz',name:'2005 $50 Gold Eagle (1 oz)',years:'2005',note:''},
      ]},
      { heading: '2006–2015', coins: [
        {id:'gae_2006_1oz',name:'2006 $50 Gold Eagle (1 oz)',years:'2006',note:'20th anniversary'},
        {id:'gae_2006w_buf',name:'2006-W $50 Gold Buffalo (24k)',years:'2006',note:'First 24k US gold coin'},
        {id:'gae_2007_1oz',name:'2007 $50 Gold Eagle (1 oz)',years:'2007',note:''},
        {id:'gae_2008_1oz',name:'2008 $50 Gold Eagle (1 oz)',years:'2008',note:''},
        {id:'gae_2009_1oz',name:'2009 $50 Gold Eagle (1 oz)',years:'2009',note:'High demand year'},
        {id:'gae_2010_1oz',name:'2010 $50 Gold Eagle (1 oz)',years:'2010',note:''},
        {id:'gae_2011_1oz',name:'2011 $50 Gold Eagle (1 oz)',years:'2011',note:'25th anniversary'},
        {id:'gae_2012_1oz',name:'2012 $50 Gold Eagle (1 oz)',years:'2012',note:''},
        {id:'gae_2013_1oz',name:'2013 $50 Gold Eagle (1 oz)',years:'2013',note:''},
        {id:'gae_2014_1oz',name:'2014 $50 Gold Eagle (1 oz)',years:'2014',note:''},
        {id:'gae_2015_1oz',name:'2015 $50 Gold Eagle (1 oz)',years:'2015',note:''},
        {id:'gae_2015w_75th',name:'2015-W 75th Anniv. Gold Eagle',years:'2015',note:'High relief — key'},
      ]},
      { heading: '2016–2026', coins: [
        {id:'gae_2016_1oz',name:'2016 $50 Gold Eagle (1 oz)',years:'2016',note:'30th anniversary'},
        {id:'gae_2017_1oz',name:'2017 $50 Gold Eagle (1 oz)',years:'2017',note:''},
        {id:'gae_2018_1oz',name:'2018 $50 Gold Eagle (1 oz)',years:'2018',note:''},
        {id:'gae_2019_1oz',name:'2019 $50 Gold Eagle (1 oz)',years:'2019',note:''},
        {id:'gae_2020_1oz',name:'2020 $50 Gold Eagle (1 oz)',years:'2020',note:''},
        {id:'gae_2021_t1',name:'2021 Type 1 Gold Eagle (1 oz)',years:'2021',note:'Last original reverse'},
        {id:'gae_2021_t2',name:'2021 Type 2 Gold Eagle (1 oz)',years:'2021',note:'New reverse design'},
        {id:'gae_2022_1oz',name:'2022 $50 Gold Eagle (1 oz)',years:'2022',note:''},
        {id:'gae_2023_1oz',name:'2023 $50 Gold Eagle (1 oz)',years:'2023',note:''},
        {id:'gae_2024_1oz',name:'2024 $50 Gold Eagle (1 oz)',years:'2024',note:''},
        {id:'gae_2025_1oz',name:'2025 $50 Gold Eagle (1 oz)',years:'2025',note:''},
        {id:'gae_2026_1oz',name:'2026 $50 Gold Eagle (1 oz)',years:'2026',note:'40th anniversary'},
      ]},
      { heading: 'Gold Buffalo (24k .9999)', coins: [
        {id:'gbuf_2006',name:'2006 $50 Gold Buffalo',years:'2006',note:'First 24k — key'},
        {id:'gbuf_2007',name:'2007 $50 Gold Buffalo',years:'2007',note:''},
        {id:'gbuf_2008',name:'2008 $50 Gold Buffalo',years:'2008',note:'Low mintage — key'},
        {id:'gbuf_2009',name:'2009 $50 Gold Buffalo',years:'2009',note:''},
        {id:'gbuf_2010',name:'2010 $50 Gold Buffalo',years:'2010',note:''},
        {id:'gbuf_2011',name:'2011 $50 Gold Buffalo',years:'2011',note:''},
        {id:'gbuf_2012',name:'2012 $50 Gold Buffalo',years:'2012',note:''},
        {id:'gbuf_2013',name:'2013 $50 Gold Buffalo',years:'2013',note:''},
        {id:'gbuf_2014',name:'2014 $50 Gold Buffalo',years:'2014',note:''},
        {id:'gbuf_2015',name:'2015 $50 Gold Buffalo',years:'2015',note:''},
        {id:'gbuf_2016',name:'2016 $50 Gold Buffalo',years:'2016',note:''},
        {id:'gbuf_2017',name:'2017 $50 Gold Buffalo',years:'2017',note:''},
        {id:'gbuf_2018',name:'2018 $50 Gold Buffalo',years:'2018',note:'Low mintage — key'},
        {id:'gbuf_2019',name:'2019 $50 Gold Buffalo',years:'2019',note:''},
        {id:'gbuf_2020',name:'2020 $50 Gold Buffalo',years:'2020',note:''},
        {id:'gbuf_2021',name:'2021 $50 Gold Buffalo',years:'2021',note:''},
        {id:'gbuf_2022',name:'2022 $50 Gold Buffalo',years:'2022',note:''},
        {id:'gbuf_2023',name:'2023 $50 Gold Buffalo',years:'2023',note:''},
        {id:'gbuf_2024',name:'2024 $50 Gold Buffalo',years:'2024',note:''},
        {id:'gbuf_2025',name:'2025 $50 Gold Buffalo',years:'2025',note:''},
        {id:'gbuf_2026',name:'2026 $50 Gold Buffalo',years:'2026',note:'20th anniversary'},
      ]},
    ]
  },
  'commem': {
    title: 'US Commemorative Coins (Classic)',
    desc: 'Classic US commemoratives 1892–1954 — 90% silver and gold issues',
    sections: [
      { heading: '1892–1900 Early Issues', coins: [
        {id:'com_columbian',name:'1892–93 Columbian Half Dollar',years:'1892–1893',note:'First US commemorative'},
        {id:'com_isabella',name:'1893 Isabella Quarter',years:'1893',note:'Only commem quarter'},
        {id:'com_lafayette',name:'1900 Lafayette Dollar',years:'1900',note:'First US commem dollar'},
      ]},
      { heading: '1915–1925', coins: [
        {id:'com_panama',name:'1915 Panama-Pacific Half',years:'1915',note:''},
        {id:'com_illinois',name:'1918 Illinois Centennial Half',years:'1918',note:''},
        {id:'com_maine',name:'1920 Maine Centennial Half',years:'1920',note:''},
        {id:'com_pilgrim',name:'1920–21 Pilgrim Tercentenary Half',years:'1920–1921',note:''},
        {id:'com_missouri',name:'1921 Missouri Centennial Half',years:'1921',note:'2★4 variety key'},
        {id:'com_monroe',name:'1923 Monroe Doctrine Half',years:'1923',note:''},
        {id:'com_huguenot',name:'1924 Huguenot-Walloon Half',years:'1924',note:''},
        {id:'com_lexington',name:'1925 Lexington-Concord Half',years:'1925',note:''},
        {id:'com_stonewall',name:'1925 Stone Mountain Half',years:'1925',note:'High mintage'},
      ]},
      { heading: '1926–1939', coins: [
        {id:'com_oregon',name:'1926–39 Oregon Trail Half',years:'1926–1939',note:'Long series — 14 dates'},
        {id:'com_vermont',name:'1927 Vermont Sesquicentennial Half',years:'1927',note:''},
        {id:'com_hawaii',name:'1928 Hawaiian Sesquicentennial Half',years:'1928',note:'Rare — key date'},
        {id:'com_maryland',name:'1934 Maryland Tercentenary Half',years:'1934',note:''},
        {id:'com_texas',name:'1934–38 Texas Centennial Half',years:'1934–1938',note:'Multiple dates'},
        {id:'com_daniel_boone',name:'1934–38 Daniel Boone Bicentennial Half',years:'1934–1938',note:'Many varieties'},
        {id:'com_connecticut',name:'1935 Connecticut Tercentenary Half',years:'1935',note:''},
        {id:'com_hudson',name:'1935 Hudson Sesquicentennial Half',years:'1935',note:'Low mintage — key'},
        {id:'com_old_spanish',name:'1935 Old Spanish Trail Half',years:'1935',note:'Low mintage'},
        {id:'com_arkansas',name:'1935–39 Arkansas Centennial Half',years:'1935–1939',note:''},
        {id:'com_rhode_island',name:'1936 Rhode Island Half',years:'1936',note:'3 mints'},
        {id:'com_york',name:'1936 York County Half',years:'1936',note:''},
        {id:'com_wisconsin',name:'1936 Wisconsin Territorial Centennial Half',years:'1936',note:''},
        {id:'com_elgin',name:'1936 Elgin Centennial Half',years:'1936',note:''},
        {id:'com_roanoke',name:'1937 Roanoke Island Half',years:'1937',note:''},
        {id:'com_antietam',name:'1937 Battle of Antietam Half',years:'1937',note:'Low mintage'},
        {id:'com_new_rochelle',name:'1938 New Rochelle Half',years:'1938',note:''},
        {id:'com_iowa',name:'1946 Iowa Centennial Half',years:'1946',note:''},
        {id:'com_booker_t',name:'1946–51 Booker T. Washington Half',years:'1946–1951',note:''},
        {id:'com_btw_carver',name:'1951–54 Washington-Carver Half',years:'1951–1954',note:'Last classic commem'},
      ]},
      { heading: 'Gold Commemoratives', coins: [
        {id:'com_gold_dollar_la',name:'1903 Louisiana Purchase Gold Dollar',years:'1903',note:'2 varieties'},
        {id:'com_gold_dollar_lewis',name:'1904–05 Lewis & Clark Gold Dollar',years:'1904–1905',note:''},
        {id:'com_gold_dollar_mc',name:'1916–17 McKinley Memorial Gold Dollar',years:'1916–1917',note:''},
        {id:'com_gold_dollar_grant',name:'1922 Grant Memorial Gold Dollar',years:'1922',note:'Star variety key'},
        {id:'com_pan_pac_gold',name:'1915 Panama-Pacific Gold $2.50',years:'1915',note:'Rare'},
        {id:'com_pan_pac_50',name:'1915 Panama-Pacific Gold $50',years:'1915',note:'Round & octagonal — extremely rare'},
      ]},
    ]
  },
  'proofsets': {
    title: 'US Proof Sets by Year',
    desc: 'Annual US Mint proof sets — mirror finish coins in original packaging',
    sections: [
      { heading: '1950s–1960s', coins: [
        {id:'ps_1950',name:'1950 Proof Set',years:'1950',note:'5 coins — first modern proof set'},
        {id:'ps_1951',name:'1951 Proof Set',years:'1951',note:''},
        {id:'ps_1952',name:'1952 Proof Set',years:'1952',note:''},
        {id:'ps_1953',name:'1953 Proof Set',years:'1953',note:''},
        {id:'ps_1954',name:'1954 Proof Set',years:'1954',note:''},
        {id:'ps_1955',name:'1955 Proof Set',years:'1955',note:'Low mintage'},
        {id:'ps_1956',name:'1956 Proof Set',years:'1956',note:''},
        {id:'ps_1957',name:'1957 Proof Set',years:'1957',note:''},
        {id:'ps_1958',name:'1958 Proof Set',years:'1958',note:''},
        {id:'ps_1959',name:'1959 Proof Set',years:'1959',note:''},
        {id:'ps_1960',name:'1960 Proof Set',years:'1960',note:'Small/large date varieties'},
        {id:'ps_1961',name:'1961 Proof Set',years:'1961',note:''},
        {id:'ps_1962',name:'1962 Proof Set',years:'1962',note:''},
        {id:'ps_1963',name:'1963 Proof Set',years:'1963',note:''},
        {id:'ps_1964',name:'1964 Proof Set',years:'1964',note:'Last 90% silver proof set'},
      ]},
      { heading: '1968–1980', coins: [
        {id:'ps_1968',name:'1968-S Proof Set',years:'1968',note:'Proof production resumed'},
        {id:'ps_1969',name:'1969-S Proof Set',years:'1969',note:''},
        {id:'ps_1970',name:'1970-S Proof Set',years:'1970',note:'Small date variety — key'},
        {id:'ps_1971',name:'1971-S Proof Set',years:'1971',note:''},
        {id:'ps_1972',name:'1972-S Proof Set',years:'1972',note:''},
        {id:'ps_1973',name:'1973-S Proof Set',years:'1973',note:''},
        {id:'ps_1974',name:'1974-S Proof Set',years:'1974',note:''},
        {id:'ps_1976',name:'1976-S Bicentennial Proof Set',years:'1976',note:'Bicentennial designs'},
        {id:'ps_1977',name:'1977-S Proof Set',years:'1977',note:''},
        {id:'ps_1978',name:'1978-S Proof Set',years:'1978',note:''},
        {id:'ps_1979',name:'1979-S Proof Set',years:'1979',note:'Type 1 & 2 varieties'},
        {id:'ps_1980',name:'1980-S Proof Set',years:'1980',note:''},
      ]},
      { heading: '1981–2000', coins: [
        {id:'ps_1981',name:'1981-S Proof Set',years:'1981',note:'Type 1 & 2 varieties'},
        {id:'ps_1982',name:'1982-S Proof Set',years:'1982',note:''},
        {id:'ps_1983',name:'1983-S Proof Set',years:'1983',note:'Prestige set available'},
        {id:'ps_1984',name:'1984-S Proof Set',years:'1984',note:''},
        {id:'ps_1985',name:'1985-S Proof Set',years:'1985',note:''},
        {id:'ps_1986',name:'1986-S Proof Set',years:'1986',note:''},
        {id:'ps_1987',name:'1987-S Proof Set',years:'1987',note:''},
        {id:'ps_1988',name:'1988-S Proof Set',years:'1988',note:''},
        {id:'ps_1989',name:'1989-S Proof Set',years:'1989',note:''},
        {id:'ps_1990',name:'1990-S Proof Set',years:'1990',note:'No-S Lincoln variety key'},
        {id:'ps_1991',name:'1991-S Proof Set',years:'1991',note:''},
        {id:'ps_1992',name:'1992-S Proof Set',years:'1992',note:''},
        {id:'ps_1993',name:'1993-S Proof Set',years:'1993',note:''},
        {id:'ps_1994',name:'1994-S Proof Set',years:'1994',note:''},
        {id:'ps_1995',name:'1995-S Proof Set',years:'1995',note:'Double die Lincoln — key'},
        {id:'ps_1996',name:'1996-S Proof Set',years:'1996',note:''},
        {id:'ps_1997',name:'1997-S Proof Set',years:'1997',note:''},
        {id:'ps_1998',name:'1998-S Proof Set',years:'1998',note:''},
        {id:'ps_1999',name:'1999-S Proof Set',years:'1999',note:'9-coin set (state quarters begin)'},
        {id:'ps_2000',name:'2000-S Proof Set',years:'2000',note:''},
      ]},
      { heading: '2001–2026', coins: [
        {id:'ps_2001',name:'2001-S Proof Set',years:'2001',note:''},
        {id:'ps_2002',name:'2002-S Proof Set',years:'2002',note:''},
        {id:'ps_2003',name:'2003-S Proof Set',years:'2003',note:''},
        {id:'ps_2004',name:'2004-S Proof Set',years:'2004',note:''},
        {id:'ps_2005',name:'2005-S Proof Set',years:'2005',note:''},
        {id:'ps_2006',name:'2006-S Proof Set',years:'2006',note:''},
        {id:'ps_2007',name:'2007-S Proof Set',years:'2007',note:''},
        {id:'ps_2008',name:'2008-S Proof Set',years:'2008',note:''},
        {id:'ps_2009',name:'2009-S Proof Set',years:'2009',note:'18-coin set'},
        {id:'ps_2010',name:'2010-S Proof Set',years:'2010',note:''},
        {id:'ps_2011',name:'2011-S Proof Set',years:'2011',note:''},
        {id:'ps_2012',name:'2012-S Proof Set',years:'2012',note:''},
        {id:'ps_2013',name:'2013-S Proof Set',years:'2013',note:''},
        {id:'ps_2014',name:'2014-S Proof Set',years:'2014',note:''},
        {id:'ps_2015',name:'2015-S Proof Set',years:'2015',note:''},
        {id:'ps_2016',name:'2016-S Proof Set',years:'2016',note:''},
        {id:'ps_2017',name:'2017-S Proof Set',years:'2017',note:''},
        {id:'ps_2018',name:'2018-S Proof Set',years:'2018',note:''},
        {id:'ps_2019',name:'2019-S Proof Set',years:'2019',note:''},
        {id:'ps_2020',name:'2020-S Proof Set',years:'2020',note:''},
        {id:'ps_2021',name:'2021-S Proof Set',years:'2021',note:''},
        {id:'ps_2022',name:'2022-S Proof Set',years:'2022',note:''},
        {id:'ps_2023',name:'2023-S Proof Set',years:'2023',note:''},
        {id:'ps_2024',name:'2024-S Proof Set',years:'2024',note:''},
        {id:'ps_2025',name:'2025-S Proof Set',years:'2025',note:''},
        {id:'ps_2026',name:'2026-S Proof Set',years:'2026',note:'250th anniversary'},
      ]},
    ]
  },
  'mintsets': {
    title: 'US Mint Sets by Year',
    desc: 'Annual US Mint uncirculated sets — one coin per denomination per mint mark',
    sections: [
      { heading: '1947–1964', coins: [
        {id:'ms_1947',name:'1947 Mint Set',years:'1947',note:'First modern mint set — 2 sets P&D'},
        {id:'ms_1948',name:'1948 Mint Set',years:'1948',note:''},
        {id:'ms_1949',name:'1949 Mint Set',years:'1949',note:''},
        {id:'ms_1951',name:'1951 Mint Set',years:'1951',note:''},
        {id:'ms_1952',name:'1952 Mint Set',years:'1952',note:''},
        {id:'ms_1953',name:'1953 Mint Set',years:'1953',note:''},
        {id:'ms_1954',name:'1954 Mint Set',years:'1954',note:''},
        {id:'ms_1955',name:'1955 Mint Set',years:'1955',note:'Low mintage'},
        {id:'ms_1956',name:'1956 Mint Set',years:'1956',note:''},
        {id:'ms_1957',name:'1957 Mint Set',years:'1957',note:''},
        {id:'ms_1958',name:'1958 Mint Set',years:'1958',note:''},
        {id:'ms_1959',name:'1959 Mint Set',years:'1959',note:''},
        {id:'ms_1960',name:'1960 Mint Set',years:'1960',note:''},
        {id:'ms_1961',name:'1961 Mint Set',years:'1961',note:''},
        {id:'ms_1962',name:'1962 Mint Set',years:'1962',note:''},
        {id:'ms_1963',name:'1963 Mint Set',years:'1963',note:''},
        {id:'ms_1964',name:'1964 Mint Set',years:'1964',note:'Last 90% silver mint set'},
      ]},
      { heading: '1968–2000', coins: [
        {id:'ms_1968',name:'1968 Mint Set',years:'1968',note:'Production resumed'},
        {id:'ms_1969',name:'1969 Mint Set',years:'1969',note:''},
        {id:'ms_1970',name:'1970 Mint Set',years:'1970',note:'Small date variety — key'},
        {id:'ms_1971',name:'1971 Mint Set',years:'1971',note:''},
        {id:'ms_1972',name:'1972 Mint Set',years:'1972',note:''},
        {id:'ms_1973',name:'1973 Mint Set',years:'1973',note:''},
        {id:'ms_1974',name:'1974 Mint Set',years:'1974',note:''},
        {id:'ms_1976',name:'1976 Bicentennial Mint Set',years:'1976',note:''},
        {id:'ms_1977',name:'1977 Mint Set',years:'1977',note:''},
        {id:'ms_1978',name:'1978 Mint Set',years:'1978',note:''},
        {id:'ms_1979',name:'1979 Mint Set',years:'1979',note:''},
        {id:'ms_1980',name:'1980 Mint Set',years:'1980',note:''},
        {id:'ms_1984',name:'1984 Mint Set',years:'1984',note:''},
        {id:'ms_1985',name:'1985 Mint Set',years:'1985',note:''},
        {id:'ms_1986',name:'1986 Mint Set',years:'1986',note:''},
        {id:'ms_1990',name:'1990 Mint Set',years:'1990',note:''},
        {id:'ms_1995',name:'1995 Mint Set',years:'1995',note:''},
        {id:'ms_1999',name:'1999 Mint Set',years:'1999',note:'State quarters begin'},
        {id:'ms_2000',name:'2000 Mint Set',years:'2000',note:''},
      ]},
      { heading: '2001–2026', coins: [
        {id:'ms_2001',name:'2001 Mint Set',years:'2001',note:''},
        {id:'ms_2002',name:'2002 Mint Set',years:'2002',note:''},
        {id:'ms_2003',name:'2003 Mint Set',years:'2003',note:''},
        {id:'ms_2004',name:'2004 Mint Set',years:'2004',note:''},
        {id:'ms_2005',name:'2005 Mint Set',years:'2005',note:''},
        {id:'ms_2006',name:'2006 Mint Set',years:'2006',note:''},
        {id:'ms_2007',name:'2007 Mint Set',years:'2007',note:''},
        {id:'ms_2008',name:'2008 Mint Set',years:'2008',note:''},
        {id:'ms_2009',name:'2009 Mint Set',years:'2009',note:'18-coin set — Lincoln bicentennial'},
        {id:'ms_2010',name:'2010 Mint Set',years:'2010',note:''},
        {id:'ms_2011',name:'2011 Mint Set',years:'2011',note:''},
        {id:'ms_2012',name:'2012 Mint Set',years:'2012',note:''},
        {id:'ms_2013',name:'2013 Mint Set',years:'2013',note:''},
        {id:'ms_2014',name:'2014 Mint Set',years:'2014',note:''},
        {id:'ms_2015',name:'2015 Mint Set',years:'2015',note:''},
        {id:'ms_2016',name:'2016 Mint Set',years:'2016',note:''},
        {id:'ms_2017',name:'2017 Mint Set',years:'2017',note:''},
        {id:'ms_2018',name:'2018 Mint Set',years:'2018',note:''},
        {id:'ms_2019',name:'2019 Mint Set',years:'2019',note:''},
        {id:'ms_2020',name:'2020 Mint Set',years:'2020',note:''},
        {id:'ms_2021',name:'2021 Mint Set',years:'2021',note:''},
        {id:'ms_2022',name:'2022 Mint Set',years:'2022',note:''},
        {id:'ms_2023',name:'2023 Mint Set',years:'2023',note:''},
        {id:'ms_2024',name:'2024 Mint Set',years:'2024',note:''},
        {id:'ms_2025',name:'2025 Mint Set',years:'2025',note:''},
        {id:'ms_2026',name:'2026 Mint Set',years:'2026',note:'250th anniversary'},
      ]},
    ]
  },
  'carsoncity': {
    title: 'Carson City Mint Set',
    desc: 'Chase the CC mint mark across all series — minted 1870–1893',
    sections: [
      { heading: 'Seated Liberty Series', coins: [
        {id:'cc_sl_dime',name:'CC Seated Liberty Dime',years:'1871–1878',note:'Multiple dates available'},
        {id:'cc_sl_20c',name:'CC Seated Liberty 20 Cents',years:'1875',note:'Only year — scarce'},
        {id:'cc_sl_quarter',name:'CC Seated Liberty Quarter',years:'1870–1878',note:''},
        {id:'cc_sl_half',name:'CC Seated Liberty Half Dollar',years:'1870–1878',note:''},
        {id:'cc_sl_dollar',name:'CC Seated Liberty Dollar',years:'1870–1873',note:'Low mintages'},
      ]},
      { heading: 'Trade & Morgan Dollars', coins: [
        {id:'cc_trade',name:'CC Trade Dollar',years:'1873–1878',note:'Key series for CC'},
        {id:'cc_morgan_1878',name:'1878-CC Morgan Dollar',years:'1878',note:'First CC Morgan'},
        {id:'cc_morgan_1879',name:'1879-CC Morgan Dollar',years:'1879',note:''},
        {id:'cc_morgan_1880',name:'1880-CC Morgan Dollar',years:'1880',note:''},
        {id:'cc_morgan_1881',name:'1881-CC Morgan Dollar',years:'1881',note:''},
        {id:'cc_morgan_1882',name:'1882-CC Morgan Dollar',years:'1882',note:''},
        {id:'cc_morgan_1883',name:'1883-CC Morgan Dollar',years:'1883',note:''},
        {id:'cc_morgan_1884',name:'1884-CC Morgan Dollar',years:'1884',note:''},
        {id:'cc_morgan_1885',name:'1885-CC Morgan Dollar',years:'1885',note:'Rare — key date'},
        {id:'cc_morgan_1889',name:'1889-CC Morgan Dollar',years:'1889',note:'Key date — low mintage'},
        {id:'cc_morgan_1890',name:'1890-CC Morgan Dollar',years:'1890',note:''},
        {id:'cc_morgan_1891',name:'1891-CC Morgan Dollar',years:'1891',note:''},
        {id:'cc_morgan_1892',name:'1892-CC Morgan Dollar',years:'1892',note:''},
        {id:'cc_morgan_1893',name:'1893-CC Morgan Dollar',years:'1893',note:'Last CC Morgan — key'},
      ]},
      { heading: 'Half Eagles & Eagles (Gold)', coins: [
        {id:'cc_gold_half_eagle',name:'CC Liberty Half Eagle ($5)',years:'1870–1884',note:'Multiple dates'},
        {id:'cc_gold_eagle',name:'CC Liberty Eagle ($10)',years:'1870–1893',note:'Multiple dates'},
        {id:'cc_gold_double_eagle',name:'CC Liberty Double Eagle ($20)',years:'1870–1893',note:'Multiple dates — popular series'},
      ]},
    ]
  },
  'silvercert': {
    title: 'Silver Certificate Collection',
    desc: 'US Silver Certificates — redeemable for silver, issued 1878–1964',
    sections: [
      { heading: 'Large Size (1878–1923)', coins: [
        {id:'sc_1878',name:'Series 1878 $1',years:'1878',note:'First silver certificate — rare'},
        {id:'sc_1880_1',name:'Series 1880 $1',years:'1880',note:''},
        {id:'sc_1886_1',name:'Series 1886 $1 (Martha Washington)',years:'1886',note:'First woman on US currency'},
        {id:'sc_1891_1',name:'Series 1891 $1',years:'1891',note:''},
        {id:'sc_1896_1',name:'Series 1896 $1 (Educational)',years:'1896',note:'Most beautiful US note — key'},
        {id:'sc_1896_2',name:'Series 1896 $2 (Educational)',years:'1896',note:''},
        {id:'sc_1896_5',name:'Series 1896 $5 (Educational)',years:'1896',note:''},
        {id:'sc_1899_1',name:'Series 1899 $1 (Black Eagle)',years:'1899',note:'Popular design'},
        {id:'sc_1899_2',name:'Series 1899 $2 (Porthole)',years:'1899',note:''},
        {id:'sc_1899_5',name:'Series 1899 $5 (Indian Chief)',years:'1899',note:''},
        {id:'sc_1923_1',name:'Series 1923 $1',years:'1923',note:'Last large size — common'},
        {id:'sc_1923_5',name:'Series 1923 $5 (Porthole)',years:'1923',note:''},
      ]},
      { heading: 'Small Size (1928–1957)', coins: [
        {id:'sc_1928_1',name:'Series 1928 $1',years:'1928',note:'First small size silver cert'},
        {id:'sc_1928a_1',name:'Series 1928-A $1',years:'1928',note:''},
        {id:'sc_1928b_1',name:'Series 1928-B $1',years:'1928',note:''},
        {id:'sc_1928c_1',name:'Series 1928-C $1',years:'1928',note:'Scarce'},
        {id:'sc_1928d_1',name:'Series 1928-D $1',years:'1928',note:'Scarce'},
        {id:'sc_1928e_1',name:'Series 1928-E $1',years:'1928',note:'Very scarce — key'},
        {id:'sc_1934_1',name:'Series 1934 $1',years:'1934',note:''},
        {id:'sc_1934_5',name:'Series 1934 $5',years:'1934',note:''},
        {id:'sc_1934_10',name:'Series 1934 $10',years:'1934',note:''},
        {id:'sc_1935_1',name:'Series 1935 $1',years:'1935',note:'Many varieties — A through H'},
        {id:'sc_1935a_r',name:'Series 1935-A $1 (R — experimental)',years:'1935',note:'R & S experimental notes — rare'},
        {id:'sc_1935a_s',name:'Series 1935-A $1 (S — experimental)',years:'1935',note:''},
        {id:'sc_1957_1',name:'Series 1957 $1',years:'1957',note:'Last common silver cert'},
        {id:'sc_1957a_1',name:'Series 1957-A $1',years:'1957',note:''},
        {id:'sc_1957b_1',name:'Series 1957-B $1',years:'1957',note:'Last silver certificate issued'},
      ]},
    ]
  },
  'smallsize': {
    title: 'Small Size US Currency by Type',
    desc: 'Collect one of each major small size note type — 1928 to present',
    sections: [
      { heading: 'Gold Certificates', coins: [
        {id:'ss_gc_1928_10',name:'Series 1928 $10 Gold Certificate',years:'1928',note:'Last gold cert issued — yellow seal'},
        {id:'ss_gc_1928_20',name:'Series 1928 $20 Gold Certificate',years:'1928',note:''},
        {id:'ss_gc_1928_50',name:'Series 1928 $50 Gold Certificate',years:'1928',note:'Scarce'},
        {id:'ss_gc_1928_100',name:'Series 1928 $100 Gold Certificate',years:'1928',note:'Scarce'},
      ]},
      { heading: 'Federal Reserve Notes — Pre-WWII', coins: [
        {id:'ss_frn_1928_1',name:'Series 1928 $1 FRN',years:'1928',note:'Green seal'},
        {id:'ss_frn_1928_5',name:'Series 1928 $5 FRN',years:'1928',note:''},
        {id:'ss_frn_1928_10',name:'Series 1928 $10 FRN',years:'1928',note:''},
        {id:'ss_frn_1928_20',name:'Series 1928 $20 FRN',years:'1928',note:''},
        {id:'ss_frn_1928_50',name:'Series 1928 $50 FRN',years:'1928',note:''},
        {id:'ss_frn_1928_100',name:'Series 1928 $100 FRN',years:'1928',note:''},
        {id:'ss_frn_1934_500',name:'Series 1934 $500 FRN',years:'1934',note:'McKinley portrait — rare'},
        {id:'ss_frn_1934_1000',name:'Series 1934 $1,000 FRN',years:'1934',note:'Cleveland portrait — rare'},
      ]},
      { heading: 'WWII Emergency Issues', coins: [
        {id:'ss_hawaii_1',name:'Hawaii Overprint $1',years:'1942',note:'Brown seal — WWII emergency'},
        {id:'ss_hawaii_5',name:'Hawaii Overprint $5',years:'1942',note:''},
        {id:'ss_hawaii_10',name:'Hawaii Overprint $10',years:'1942',note:''},
        {id:'ss_hawaii_20',name:'Hawaii Overprint $20',years:'1942',note:''},
        {id:'ss_na_1',name:'North Africa Yellow Seal $1',years:'1942',note:'Rare WWII issue'},
        {id:'ss_na_5',name:'North Africa Yellow Seal $5',years:'1942',note:''},
        {id:'ss_na_10',name:'North Africa Yellow Seal $10',years:'1942',note:''},
      ]},
      { heading: 'Modern FRN Type Set', coins: [
        {id:'ss_mod_1',name:'$1 Federal Reserve Note',years:'1963–present',note:'One from each series'},
        {id:'ss_mod_2',name:'$2 Federal Reserve Note',years:'1976–present',note:'Series 1976 especially popular'},
        {id:'ss_mod_5',name:'$5 Federal Reserve Note',years:'1963–present',note:''},
        {id:'ss_mod_10',name:'$10 Federal Reserve Note',years:'1963–present',note:''},
        {id:'ss_mod_20',name:'$20 Federal Reserve Note',years:'1963–present',note:''},
        {id:'ss_mod_50',name:'$50 Federal Reserve Note',years:'1963–present',note:''},
        {id:'ss_mod_100',name:'$100 Federal Reserve Note',years:'1963–present',note:'Ben Franklin — most collected'},
        {id:'ss_star_1',name:'Star Note $1',years:'various',note:'Replacement notes — low print runs'},
        {id:'ss_star_100',name:'Star Note $100',years:'various',note:''},
        {id:'ss_low_serial',name:'Low Serial Number Note',years:'various',note:'#00000001–#00000100 — premium collector pieces'},
        {id:'ss_radar',name:'Radar Serial Number Note',years:'various',note:'Reads same forwards & backwards'},
        {id:'ss_repeater',name:'Repeater Serial Number Note',years:'various',note:'e.g. 12341234'},
      ]},
    ]
  },
};

// ── TypeSet state ──
let tsCurrentSet = '20th';
const TS_STORAGE_KEY = 'bdp_typesets';

function tsLoadChecks(){
  try{return JSON.parse(localStorage.getItem(TS_STORAGE_KEY)||'{}');}catch{return{};}
}
function tsSaveChecks(data){
  localStorage.setItem(TS_STORAGE_KEY, JSON.stringify(data));
}
function tsToggleCoin(setKey, coinId){
  const data=tsLoadChecks();
  if(!data[setKey])data[setKey]={};
  data[setKey][coinId]=!data[setKey][coinId];
  tsSaveChecks(data);
  tsRenderSet(setKey);
  tsUpdateOverall();
  cloudPush();
}
function tsShowSet(key, btn){
  tsCurrentSet=key;
  document.querySelectorAll('#ts-set-nav .seg').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  tsRenderSet(key);
}
function tsRenderSet(key){
  const set=TS_SETS[key];if(!set)return;
  const data=tsLoadChecks();
  const owned=data[key]||{};
  $('ts-set-title').textContent=set.title;
  // Count
  let total=0,have=0;
  set.sections.forEach(sec=>sec.coins.forEach(c=>{total++;if(owned[c.id])have++;}));
  $('ts-set-progress').textContent=`${have} / ${total}`;
  const pct=total?Math.round(have/total*100):0;
  $('ts-progress-bar').style.width=pct+'%';
  // Render grid
  const grid=$('ts-coin-grid');if(!grid)return;
  grid.innerHTML=set.sections.map(sec=>`
    <div class="ts-section-head">${sec.heading}</div>
    <div class="ts-grid">
      ${sec.coins.map(c=>`
        <div class="ts-coin-card ${owned[c.id]?'owned':''}" onclick="tsToggleCoin('${key}','${c.id}')">
          <div class="ts-chk">${owned[c.id]?'✓':''}</div>
          <div style="flex:1;min-width:0">
            <div class="ts-coin-name">${c.name}</div>
            <div class="ts-coin-years">${c.years}</div>
            ${c.note?`<div class="ts-coin-note">${c.note}</div>`:''}
          </div>
        </div>
      `).join('')}
    </div>
  `).join('');
}
function tsUpdateOverall(){
  const data=tsLoadChecks();
  let total=0,have=0;
  Object.keys(TS_SETS).forEach(k=>{
    const owned=data[k]||{};
    TS_SETS[k].sections.forEach(sec=>sec.coins.forEach(c=>{total++;if(owned[c.id])have++;}));
  });
  const pct=total?Math.round(have/total*100):0;
  $('ts-overall-pct').textContent=pct+'%';
  $('ts-overall-count').textContent=`${have} / ${total} coins`;
}
function tsCheckAll(){
  const data=tsLoadChecks();if(!data[tsCurrentSet])data[tsCurrentSet]={};
  TS_SETS[tsCurrentSet].sections.forEach(sec=>sec.coins.forEach(c=>data[tsCurrentSet][c.id]=true));
  tsSaveChecks(data);tsRenderSet(tsCurrentSet);tsUpdateOverall();
}
function tsClearAll(){
  const data=tsLoadChecks();data[tsCurrentSet]={};
  tsSaveChecks(data);tsRenderSet(tsCurrentSet);tsUpdateOverall();
}
function tsResetAll(){
  if(!confirm('Reset ALL type sets? This cannot be undone.'))return;
  localStorage.removeItem(TS_STORAGE_KEY);
  tsRenderSet(tsCurrentSet);tsUpdateOverall();
}

let tsRows = [];
let tsTVWindow = null;
const TS_KEY = 'bdp_trading_sheet';

function tsInit() {
  tsLoadFromStorage();
  tsSyncSpot();
  tsRenderRef();
}

function tsSyncSpot() {
  // Pull from existing spot prices already loaded on the page
  const g = document.getElementById('ts-spot-gold');
  const s = document.getElementById('ts-spot-silver');
  if (g && spot.XAU) g.textContent = '$' + spot.XAU.toFixed(2);
  if (s && spot.XAG) s.textContent = '$' + spot.XAG.toFixed(2);
  tsRenderRef();
}

/* ── Silver Reference Table (fixed items, live melt) ── */
const TS_REF_ITEMS = [
  { name: 'Silver Bullion (.999 fine)', ozt: 1.000, key: 'bullion' },
  { name: 'Pre-1965 Dime (90%)', ozt: 0.07234, key: 'dime' },
  { name: 'Pre-1965 Quarter (90%)', ozt: 0.18084, key: 'quarter' },
  { name: 'Silver Dollar (Morgan/Peace)', ozt: 0.77344, key: 'dollar' },
  { name: '40% Kennedy Half', ozt: 0.1479, key: 'half40' },
  { name: '35% War Nickel', ozt: 0.05626, key: 'nickel35' }
];
const TS_REF_KEY = 'bdp_silver_ref_prices';

function tsLoadRefPrices() {
  try { return JSON.parse(localStorage.getItem(TS_REF_KEY) || '{}'); } catch(e) { return {}; }
}
function tsSaveRefPrices(data) {
  try { localStorage.setItem(TS_REF_KEY, JSON.stringify(data)); } catch(e) {}
}
function tsRenderRef() {
  const tbody = document.getElementById('ts-ref-tbody');
  const agEl = document.getElementById('ts-ref-ag');
  if (!tbody) return;
  const ag = spot.XAG || 0;
  if (agEl) agEl.textContent = ag.toFixed(2);
  const saved = tsLoadRefPrices();
  tbody.innerHTML = TS_REF_ITEMS.map(item => {
    const melt = (ag * item.ozt);
    const bp = saved[item.key+'_buy'] || '';
    const sp = saved[item.key+'_sell'] || '';
    return `<tr>
      <td style="font-weight:700">${item.name}</td>
      <td style="font-family:monospace;color:var(--muted)">${item.ozt.toFixed(5)}</td>
      <td style="font-family:monospace;font-weight:700;color:var(--gold)">$${melt.toFixed(2)}</td>
      <td class="ts-buy"><span class="ts-dollar">$</span><input class="ts-input" value="${bp}" placeholder="0.00" onchange="tsRefUpdate('${item.key}_buy',this.value)" style="width:85px"></td>
      <td class="ts-sell"><span class="ts-dollar">$</span><input class="ts-input" value="${sp}" placeholder="0.00" onchange="tsRefUpdate('${item.key}_sell',this.value)" style="width:85px"></td>
      <td style="font-size:10px;color:var(--muted)">${item.key==='bullion'?'1 oz .999 fine':item.key==='dime'?'$1 face = $'+ (ag*0.7234).toFixed(2):item.key==='quarter'?'$1 face = $'+ (ag*0.7234).toFixed(2):item.key==='dollar'?'$1 face ≈ $'+ (ag*0.77344).toFixed(2):''}</td>
    </tr>`;
  }).join('');
}
function tsRefUpdate(key, val) {
  const data = tsLoadRefPrices();
  data[key] = val;
  tsSaveRefPrices(data);
}

/* ── Original Trading Sheet ── */
function tsRender() {
  const tbody = document.getElementById('ts-tbody');
  if (!tbody) return;
  if (tsRows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:32px;font-style:italic">No items yet — click + ADD ITEM to get started</td></tr>';
    return;
  }
  tbody.innerHTML = tsRows.map((r, i) => `
    <tr>
      <td><input class="ts-input" value="${r.name||''}" placeholder="Item name" onchange="tsUpdate(${i},'name',this.value)"></td>
      <td><input class="ts-input" value="${r.weight||''}" placeholder="e.g. 1.0" onchange="tsUpdate(${i},'weight',this.value)" style="width:70px"></td>
      <td>
        <select class="ts-input" onchange="tsUpdate(${i},'unit',this.value)" style="width:70px;background:var(--bg2);border:none;border-bottom:1px solid #333;color:var(--text)">
          ${['oz','g','troy oz','lb','kg'].map(u=>`<option value="${u}" ${r.unit===u?'selected':''}>${u}</option>`).join('')}
        </select>
      </td>
      <td><span class="ts-dollar">$</span><input class="ts-input" value="${r.spot||''}" placeholder="—" onchange="tsUpdate(${i},'spot',this.value)" style="width:80px"></td>
      <td class="ts-buy"><span class="ts-dollar">$</span><input class="ts-input" value="${r.buy||''}" placeholder="0.00" onchange="tsUpdate(${i},'buy',this.value)" style="width:85px"></td>
      <td class="ts-sell"><span class="ts-dollar">$</span><input class="ts-input" value="${r.sell||''}" placeholder="0.00" onchange="tsUpdate(${i},'sell',this.value)" style="width:85px"></td>
      <td><input class="ts-input" value="${r.notes||''}" placeholder="Notes…" onchange="tsUpdate(${i},'notes',this.value)"></td>
      <td><button class="ts-del" onclick="tsDeleteRow(${i})">✕</button></td>
    </tr>
  `).join('');
  tsSyncSpot();
}

function tsAddRow() {
  tsRows.push({ name:'', weight:'', unit:'oz', spot:'', buy:'', sell:'', notes:'' });
  tsRender();
  tsAutoSave();
}

function tsUpdate(i, field, val) {
  tsRows[i][field] = val;
  tsAutoSave();
  if (tsTVWindow && !tsTVWindow.closed) tsBroadcast();
}

function tsDeleteRow(i) {
  tsRows.splice(i, 1);
  tsRender();
  tsAutoSave();
  if (tsTVWindow && !tsTVWindow.closed) tsBroadcast();
}

function tsAutoSave() {
  try {
    localStorage.setItem(TS_KEY, JSON.stringify(tsRows));
    const el = document.getElementById('ts-save-status');
    if (el) { el.textContent = '✓ Auto-saved'; setTimeout(() => el.textContent='', 2000); }
  } catch(e) {}
}

function tsSave() {
  try {
    localStorage.setItem(TS_KEY, JSON.stringify(tsRows));
    const el = document.getElementById('ts-save-status');
    if (el) el.textContent = '✓ Saved!';
    setTimeout(() => { if(el) el.textContent=''; }, 2500);
  } catch(e) { alert('Could not save — storage full?'); }
}

function tsLoad() {
  tsLoadFromStorage();
  tsRender();
}

function tsLoadFromStorage() {
  try {
    const raw = localStorage.getItem(TS_KEY);
    if (raw) tsRows = JSON.parse(raw);
    else tsRows = [];
  } catch(e) { tsRows = []; }
  tsRender();
}

function tsClear() {
  if (!confirm('Clear all trading sheet rows?')) return;
  tsRows = [];
  localStorage.removeItem(TS_KEY);
  tsRender();
  if (tsTVWindow && !tsTVWindow.closed) tsBroadcast();
}

function tsPrint() {
  showTab('trading');
  setTimeout(() => window.print(), 200);
}

// ── TV MODE ─────────────────────────────────────────────────────
function tsTVMode() {
  if (tsTVWindow && !tsTVWindow.closed) { tsTVWindow.focus(); return; }

  // Build TV page on the fly as a data URL
 const gold = spot.XAU ? '$' + spot.XAU.toFixed(2) : '—';
  const silver = spot.XAG ? '$' + spot.XAG.toFixed(2) : '—';
  const rows = tsRows;

  // Build reference rows for TV
  const agTV = spot.XAG || 0;
  const savedTV = tsLoadRefPrices();
  const refRowsHTML = TS_REF_ITEMS.map(item => {
    const melt = (agTV * item.ozt);
    const bp = savedTV[item.key+'_buy'] || '';
    const sp = savedTV[item.key+'_sell'] || '';
    return '<tr style="background:#1a1408"><td style="font-weight:700">'+item.name+'</td><td style="font-family:monospace">'+item.ozt.toFixed(5)+' ozt</td><td style="font-family:monospace;color:#c9a84c">$'+melt.toFixed(2)+'</td><td class="buy">'+(bp?'$'+bp:'—')+'</td><td class="sell">'+(sp?'$'+sp:'—')+'</td><td style="font-size:12px;color:#888">'+(item.key==='bullion'?'1 oz .999 fine':'')+'</td></tr>';
  }).join('');

  const rowsHTML = rows.length === 0
    ? '<tr><td colspan="6" style="text-align:center;color:#555;padding:40px;font-style:italic">No items on sheet yet</td></tr>'
    : rows.map(r => `
      <tr>
        <td>${r.name||'—'}</td>
        <td>${r.weight||'—'} ${r.unit||'oz'}</td>
        <td>${r.spot ? '$'+r.spot : '—'}</td>
        <td class="buy">${r.buy ? '$'+r.buy : '—'}</td>
        <td class="sell">${r.sell ? '$'+r.sell : '—'}</td>
        <td>${r.notes||''}</td>
      </tr>`).join('');

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  const timeStr = now.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});

  const tvHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Trading Sheet — TV Display</title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700;900&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  :root{--gold:#c9a84c;--lightgold:#e8c97e;--dark:#0a0a0a;--panel:#111;--border:#222;--silver:#b0b8c1;}
  *{box-sizing:border-box;margin:0;padding:0;}
  html,body{height:100%;background:var(--dark);color:#fff;font-family:'Rajdhani',sans-serif;overflow:hidden;}
  body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.06) 2px,rgba(0,0,0,.06) 4px);pointer-events:none;z-index:9999;}
  .header{padding:18px 48px 14px;border-bottom:3px solid var(--gold);background:linear-gradient(180deg,#0a0a00,#111);display:flex;align-items:center;justify-content:space-between;}
  .header-title{font-family:'Cinzel',serif;font-size:28px;color:var(--gold);letter-spacing:3px;}
  .header-sub{font-family:'Rajdhani',sans-serif;font-size:14px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-top:4px;}
  .spot-bar{display:flex;gap:48px;align-items:center;}
  .spot-item{text-align:center;}
  .spot-label{font-size:11px;letter-spacing:3px;color:#888;font-family:'Rajdhani',sans-serif;text-transform:uppercase;}
  .spot-val{font-family:'Share Tech Mono',monospace;font-size:28px;letter-spacing:1px;}
  .spot-gold{color:var(--lightgold);text-shadow:0 0 20px rgba(232,201,126,.5);}
  .spot-silver{color:var(--silver);text-shadow:0 0 16px rgba(176,184,193,.4);}
  .datetime{text-align:right;}
  .live-date{font-family:'Share Tech Mono',monospace;font-size:16px;color:#aaa;letter-spacing:1px;}
  .live-time{font-family:'Orbitron',monospace;font-size:26px;color:#fff;letter-spacing:2px;margin-top:4px;}
  .content{padding:24px 48px;}
  table{width:100%;border-collapse:collapse;}
  thead tr{background:linear-gradient(135deg,#1a1508,#111);}
  thead th{padding:14px 20px;text-align:left;font-family:'Cinzel',serif;font-size:13px;letter-spacing:3px;color:var(--gold);border-bottom:2px solid var(--gold);}
  tbody tr{border-bottom:1px solid #1e1e1e;transition:background .2s;}
  tbody tr:nth-child(even){background:#0d0d0d;}
  tbody td{padding:16px 20px;font-size:22px;font-family:'Rajdhani',sans-serif;color:#ddd;}
  tbody td.buy{color:#4ddb7a;font-family:'Share Tech Mono',monospace;font-size:24px;font-weight:700;}
  tbody td.sell{color:#e07070;font-family:'Share Tech Mono',monospace;font-size:24px;font-weight:700;}
  tbody td:first-child{font-size:24px;font-weight:700;color:#fff;}
  .footer{position:fixed;bottom:0;left:0;right:0;background:#0a0a0a;border-top:1px solid #222;padding:8px 48px;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#555;font-family:'Share Tech Mono',monospace;}
  @keyframes pulse-gold{0%,100%{text-shadow:0 0 20px rgba(232,201,126,.3);}50%{text-shadow:0 0 40px rgba(232,201,126,.7);}}
  .spot-gold{animation:pulse-gold 3s ease-in-out infinite;}
</style>
</head><body>
<div class="header">
  <div>
    <div class="header-title">BULLION DEALER PRO</div>
    <div class="header-sub">Live Trading Sheet</div>
  </div>
  <div class="spot-bar">
    <div class="spot-item"><div class="spot-label">Gold / oz</div><div class="spot-val spot-gold">${gold}</div></div>
    <div class="spot-item"><div class="spot-label">Silver / oz</div><div class="spot-val spot-silver">${silver}</div></div>
  </div>
  <div class="datetime">
    <div class="live-date">${dateStr}</div>
    <div class="live-time" id="tv-time">${timeStr}</div>
  </div>
</div>
<div class="content">
  <table><thead><tr><th>ITEM</th><th>WEIGHT</th><th>SPOT</th><th>WE BUY</th><th>WE SELL</th><th>NOTES</th></tr></thead>
  <tbody>${refRowsHTML}${rowsHTML}</tbody></table>
</div>
<div class="footer">
  <span>Spot Prices & Dealer Tools · bulliondealerpro.com</span>
  <span id="tv-updated">Last updated: ${timeStr}</span>
</div>
<script>
  // Live clock
  function tick(){
    const n=new Date();
    document.getElementById('tv-time').textContent=n.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
  }
  setInterval(tick,1000);
  // Fullscreen
  try{document.documentElement.requestFullscreen();}catch(e){}
  // Listen for updates from parent window
  window.addEventListener('message',function(e){
    if(e.data&&e.data.type==='ts-update'){
      document.querySelector('tbody').innerHTML=e.data.html;
      document.getElementById('tv-updated').textContent='Last updated: '+new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
    }
  });
<\/script>
</body></html>`;

  const blob = new Blob([tvHTML], {type:'text/html'});
  const url = URL.createObjectURL(blob);
  tsTVWindow = window.open(url, '_blank', 'noopener');

  const btn = document.getElementById('ts-tv-btn');
  if (btn) { btn.textContent = '📺 TV OPEN ↗'; btn.style.color='#4ddb7a'; btn.style.borderColor='#4ddb7a'; }

  const checker = setInterval(() => {
    if (!tsTVWindow || tsTVWindow.closed) {
      clearInterval(checker);
      tsTVWindow = null;
      if (btn) { btn.textContent='📺 TV MODE'; btn.style.color=''; btn.style.borderColor=''; }
    }
  }, 1000);
}

function tsBroadcast() {
  if (!tsTVWindow || tsTVWindow.closed) return;
  const rows = tsRows;
  const rowsHTML = rows.length === 0
    ? '<tr><td colspan="6" style="text-align:center;color:#555;padding:40px;font-style:italic">No items on sheet yet</td></tr>'
    : rows.map(r => `<tr><td>${r.name||'—'}</td><td>${r.weight||'—'} ${r.unit||'oz'}</td><td>${r.spot?'$'+r.spot:'—'}</td><td class="buy">${r.buy?'$'+r.buy:'—'}</td><td class="sell">${r.sell?'$'+r.sell:'—'}</td><td>${r.notes||''}</td></tr>`).join('');
  try { tsTVWindow.postMessage({type:'ts-update', html:rowsHTML}, '*'); } catch(e){}
}

// Auto-load on tab open
document.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem(TS_KEY)) tsLoadFromStorage();
});



// ═══ NEWS ═══
async function loadNews(){
  try{
    const r=await fetch('/api/news');
    const items=await r.json();
    if(!items||!items.length)return;
    const dots=' &nbsp;·&nbsp; ';
    const h=items.map(i=>'<a href="'+i.link+'" target="_blank">'+i.title+'</a>').join(dots);
    const el=$('news-inner');
    if(!el)return;
    // kill animation, swap content, reflow, restart
    el.style.animation='none';
    el.innerHTML=h+' &emsp;&emsp;&emsp; '+h;
    void el.offsetWidth;
    el.style.animation='scrollL 60s linear infinite';
  }catch(e){console.warn('[loadNews]',e);}
}

// ═══ ACCOUNT ═══
async function loadAccount(){
  try{
    const r = await fetch('/api/me');
    if(!r.ok){
      // Not logged in — guest mode. Prices still load, pro tabs get locks, no full-screen block
      window_isPro = false;
      window_authReady = true;
      applyGuestUI();
      return;
    }
    const u = await r.json();
    const paid = ['admin','monthly','annual','trial'];
    window_isPro = paid.includes(u.plan);
    if(window_isPro){
      localStorage.removeItem('bdp-karat-used');
      localStorage.removeItem('bdp-fx-used');
      const knudge=$('karat-limit-nudge');if(knudge)knudge.style.display='none';
      const fxbanner=$('fx-limit-banner');if(fxbanner)fxbanner.style.display='none';
      const fxctrl=$('fx-controls');if(fxctrl)fxctrl.style.pointerEvents='auto';
    }
    window_authReady = true;

    // ALWAYS remove the paywall for any logged-in user
    $('paywall').classList.remove('show');

    // Header buttons
    if(u.plan==='admin'){const sec=document.getElementById('admin-access-section');if(sec)sec.style.display='block';}
    $('logout-btn').style.display='inline-flex';

    // Account card
    const pl = u.plan==='free'?'FREE':u.plan.toUpperCase();
    $('acct-card').innerHTML=`
      <div style="font-size:9px;font-weight:700;letter-spacing:2px;color:var(--muted);margin-bottom:9px">ACCOUNT</div>
      <div style="font-size:15px;font-weight:700;color:var(--text);margin-bottom:11px">${u.email}</div>
      <span class="premium-badge" style="font-size:12px;padding:4px 14px">${pl}</span>
      ${u.plan==='trial'?`<div style="margin-top:7px;font-size:12px;color:var(--muted)">Trial ends: ${new Date(u.trialEnd).toLocaleDateString()}</div>`:''}
      ${(!window_isPro)?`<div style="margin-top:18px"><a href="/pricing" style="display:inline-block;background:var(--blue);color:#fff;padding:9px 22px;border-radius:7px;font-size:13px;font-weight:700;text-decoration:none">Upgrade to PRO →</a></div>`:''}`;

    if(window_isPro){
      // Remove locks from pro tabs
      document.querySelectorAll('.tab[data-pro="1"]').forEach(t=>{
        t.style.opacity='';
        const lock = t.querySelector('.pro-lock');
        if(lock) lock.remove();
      });
      setTimeout(cloudPull, 800);
    } else {
      applyGuestUI();
    }

    // If a pro tab was queued before auth resolved, open it now
    if(window_pendingTab){
      const pt = window_pendingTab; window_pendingTab = null;
      showTab(pt);
    }

  }catch(e){
    console.error('loadAccount error:', e);
    window_isPro = false;
    window_authReady = true;
    applyGuestUI();
  }
}

function applyGuestUI(){
  // Add lock badges to pro tabs — but no full-screen paywall takeover
  document.querySelectorAll('.tab[data-pro="1"]').forEach(t=>{
    t.style.opacity='0.6';
    const ic = t.querySelector('.ticon');
    if(ic && !ic.querySelector('.pro-lock')){
      const lock = document.createElement('span');
      lock.className = 'pro-lock';
      lock.textContent = '🔒';
      lock.style.cssText = 'position:absolute;top:-4px;right:-4px;font-size:9px;line-height:1';
      ic.style.position = 'relative';
      ic.style.display = 'inline-block';
      ic.appendChild(lock);
    }
  });
}
async function redeemPromo(){
  const code=$('promo-input').value.trim().toUpperCase();
  const r=await fetch('/api/promo/redeem',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
  const d=await r.json();
  $('promo-msg').innerHTML=r.ok?`<span class="ok">✓ Applied! Plan: ${d.plan}</span>`:`<span class="err">${d.error}</span>`;
  if(r.ok)loadAccount();
}

// ═══════════════════════════════════════════════════
// SCRAP GOLD BUYER
// ═══════════════════════════════════════════════════
const SCRAP_KARATS=[
  {id:'10',label:'10k Gold',purity:0.4167},
  {id:'14',label:'14k Gold',purity:0.5833},
  {id:'18',label:'18k Gold',purity:0.7500},
  {id:'22',label:'22k Gold',purity:0.9167},
  {id:'24',label:'24k Gold',purity:0.9999},
  {id:'sterling',label:'Sterling Silver (.925)',purity:0.925,isSilver:true}
];
const SCRAP_BG={'10':'rgba(212,175,55,0.12)','14':'rgba(212,175,55,0.18)','18':'rgba(212,175,55,0.25)','22':'rgba(212,175,55,0.32)','24':'rgba(212,175,55,0.40)','sterling':'rgba(148,163,184,0.15)'};
const SCRAP_BD={'10':'rgba(212,175,55,0.35)','14':'rgba(212,175,55,0.45)','18':'rgba(212,175,55,0.55)','22':'rgba(212,175,55,0.65)','24':'rgba(212,175,55,0.80)','sterling':'rgba(148,163,184,0.45)'};
function calcScrapGold(){
  const gs=spot.XAU||0, ss=spot.XAG||0;
  const disp=document.getElementById('scrap-spot-display');
  const tm=document.getElementById('scrap-spot-time');
  if(disp) disp.textContent=gs?'$'+gs.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})+'/oz':'—';
  if(tm) tm.textContent=new Date().toLocaleTimeString();
  const board=document.getElementById('scrap-board');
  if(!board) return;
  board.innerHTML='';
  SCRAP_KARATS.forEach(k=>{
    const pctEl=document.getElementById('scrap-pct-'+k.id);
    const pct=pctEl?(parseFloat(pctEl.value)||50):50;
    const sp=k.isSilver?ss:gs;
    const mpg=(sp*k.purity)/31.1035;
    const bpg=mpg*(pct/100);
    const bpd=bpg*1.55517;
    const card=document.createElement('div');
    card.style.cssText='background:'+SCRAP_BG[k.id]+';border:1px solid '+SCRAP_BD[k.id]+';border-radius:12px;padding:14px;text-align:center';
    card.innerHTML='<div style="font-size:13px;font-weight:800;color:var(--gold);margin-bottom:6px">'+k.label+'</div>'
      +'<div style="font-size:11px;color:var(--muted);margin-bottom:8px">Buy @ '+pct+'% of melt</div>'
      +'<div style="font-size:20px;font-weight:900;color:var(--green);margin-bottom:4px">$'+bpg.toFixed(2)+'<span style="font-size:11px;color:var(--muted)">/g</span></div>'
      +'<div style="font-size:14px;font-weight:700;color:var(--text2)">$'+bpd.toFixed(2)+'<span style="font-size:10px;color:var(--muted)">/dwt</span></div>'
      +'<div style="font-size:10px;color:var(--muted);margin-top:6px">Melt: $'+mpg.toFixed(2)+'/g</div>';
    board.appendChild(card);
  });
  calcScrapQuote();
}
function calcScrapQuote(){
  const wt=parseFloat(document.getElementById('sq-weight')?.value)||0;
  const unit=document.getElementById('sq-unit')?.value||'g';
  const kid=document.getElementById('sq-karat')?.value||'14';
  const k=SCRAP_KARATS.find(x=>x.id===kid)||SCRAP_KARATS[1];
  let g=wt;
  if(unit==='dwt') g=wt*1.55517;
  else if(unit==='oz') g=wt*31.1035;
  else if(unit==='gr') g=wt*0.0648;
  const sp=k.isSilver?(spot.XAG||0):(spot.XAU||0);
  const mpg=(sp*k.purity)/31.1035;
  const melt=mpg*g;
  const pctEl=document.getElementById('scrap-pct-'+kid);
  const pct=pctEl?(parseFloat(pctEl.value)||50):50;
  const offer=melt*(pct/100);
  const profit=melt-offer;
  const me=document.getElementById('sq-melt'), oe=document.getElementById('sq-offer'), pe=document.getElementById('sq-profit');
  if(me) me.textContent=fmt(melt);
  if(oe) oe.textContent=fmt(offer);
  if(pe) pe.textContent=fmt(profit);
}
function saveScrapPresets(){
  const p={};
  SCRAP_KARATS.forEach(k=>{const el=document.getElementById('scrap-pct-'+k.id);if(el) p['scrap_pct_'+k.id]=el.value;});
  localStorage.setItem('bdp-scrap-presets',JSON.stringify(p));
  const msg=document.getElementById('scrap-save-msg');
  if(msg){msg.textContent='✅ Presets saved!';setTimeout(()=>msg.textContent='',2500);}
}
function loadScrapPresets(){
  try{
    const p=JSON.parse(localStorage.getItem('bdp-scrap-presets')||'{}');
    Object.keys(p).forEach(k=>{const el=document.getElementById(k.replace('scrap_pct_','scrap-pct-'));if(el) el.value=p[k];});
  }catch(e){}
}

// ═══════════════════════════════════════════════════
// GOLD COIN LIBRARY (AGW)
// ═══════════════════════════════════════════════════
const GOLD_COINS=[
  {name:'American Gold Eagle 1 oz',country:'🇺🇸 USA',agw:1.0000,series:'American Eagle'},
  {name:'American Gold Eagle 1/2 oz',country:'🇺🇸 USA',agw:0.5000,series:'American Eagle'},
  {name:'American Gold Eagle 1/4 oz',country:'🇺🇸 USA',agw:0.2500,series:'American Eagle'},
  {name:'American Gold Eagle 1/10 oz',country:'🇺🇸 USA',agw:0.1000,series:'American Eagle'},
  {name:'American Gold Buffalo 1 oz',country:'🇺🇸 USA',agw:1.0000,series:'Buffalo'},
  {name:'US $20 Saint-Gaudens',country:'🇺🇸 USA',agw:0.9675,series:'Pre-1933'},
  {name:'US $20 Liberty (Double Eagle)',country:'🇺🇸 USA',agw:0.9675,series:'Pre-1933'},
  {name:'US $10 Liberty Eagle',country:'🇺🇸 USA',agw:0.4838,series:'Pre-1933'},
  {name:'US $10 Indian Eagle',country:'🇺🇸 USA',agw:0.4838,series:'Pre-1933'},
  {name:'US $5 Liberty Half Eagle',country:'🇺🇸 USA',agw:0.2419,series:'Pre-1933'},
  {name:'US $5 Indian Half Eagle',country:'🇺🇸 USA',agw:0.2419,series:'Pre-1933'},
  {name:'US $2.5 Liberty Quarter Eagle',country:'🇺🇸 USA',agw:0.1209,series:'Pre-1933'},
  {name:'US $1 Gold (Type 1-3)',country:'🇺🇸 USA',agw:0.0484,series:'Pre-1933'},
  {name:'Canadian Maple Leaf 1 oz',country:'🇨🇦 Canada',agw:1.0000,series:'Maple Leaf'},
  {name:'Canadian Maple Leaf 1/2 oz',country:'🇨🇦 Canada',agw:0.5000,series:'Maple Leaf'},
  {name:'Canadian Maple Leaf 1/4 oz',country:'🇨🇦 Canada',agw:0.2500,series:'Maple Leaf'},
  {name:'Canadian Maple Leaf 1/10 oz',country:'🇨🇦 Canada',agw:0.1000,series:'Maple Leaf'},
  {name:'Krugerrand 1 oz',country:'🇿🇦 S. Africa',agw:1.0000,series:'Krugerrand'},
  {name:'Krugerrand 1/2 oz',country:'🇿🇦 S. Africa',agw:0.5000,series:'Krugerrand'},
  {name:'Krugerrand 1/4 oz',country:'🇿🇦 S. Africa',agw:0.2500,series:'Krugerrand'},
  {name:'Krugerrand 1/10 oz',country:'🇿🇦 S. Africa',agw:0.1000,series:'Krugerrand'},
  {name:'Austrian Philharmonic 1 oz',country:'🇦🇹 Austria',agw:1.0000,series:'Philharmonic'},
  {name:'Austrian 100 Corona',country:'🇦🇹 Austria',agw:0.9802,series:'Restrikes'},
  {name:'Austrian 4 Ducat',country:'🇦🇹 Austria',agw:0.4426,series:'Restrikes'},
  {name:'Austrian 1 Ducat',country:'🇦🇹 Austria',agw:0.1106,series:'Restrikes'},
  {name:'Mexican 50 Peso (Centenario)',country:'🇲🇽 Mexico',agw:1.2057,series:'Mexican'},
  {name:'Mexican 20 Peso',country:'🇲🇽 Mexico',agw:0.4823,series:'Mexican'},
  {name:'Mexican 10 Peso',country:'🇲🇽 Mexico',agw:0.2411,series:'Mexican'},
  {name:'Mexican 5 Peso',country:'🇲🇽 Mexico',agw:0.1205,series:'Mexican'},
  {name:'British Gold Sovereign',country:'🇬🇧 UK',agw:0.2354,series:'Sovereign'},
  {name:'British Britannia 1 oz',country:'🇬🇧 UK',agw:1.0000,series:'Britannia'},
  {name:'Australian Kangaroo 1 oz',country:'🇦🇺 Australia',agw:1.0000,series:'Kangaroo'},
  {name:'Chinese Gold Panda 1 oz',country:'🇨🇳 China',agw:1.0000,series:'Panda'},
  {name:'Chinese Gold Panda 1/2 oz',country:'🇨🇳 China',agw:0.5000,series:'Panda'}
];
const COIN_IMG={
  'American Eagle':'https://www.herobullion.com/wp-content/uploads/2020/04/2020-American-Gold-Eagle-1-oz-Coin-Obverse.jpg',
  'Buffalo':'https://www.herobullion.com/wp-content/uploads/2020/03/2020-American-Gold-Buffalo-1-oz-Coin-Obverse.jpg',
  'Pre-1933':'https://www.herobullion.com/wp-content/uploads/2021/05/20-Saint-Gaudens-Double-Eagle-Gold-Coin-BU-4.jpg',
  'Krugerrand':'https://www.herobullion.com/wp-content/uploads/2020/03/South-African-Gold-Krugerrand-1-oz-Coin-Obverse.jpg',
  'Philharmonic':'https://www.herobullion.com/wp-content/uploads/2020/12/2021-1-oz-Austria-Gold-Philharmonic-Coin.jpg',
  'Restrikes':'https://www.herobullion.com/wp-content/uploads/2020/12/2021-1-oz-Austria-Gold-Philharmonic-Coin.jpg',
  'Sovereign':'https://www.herobullion.com/wp-content/uploads/2020/07/Great-Britain-Gold-Sovereign-Coin-Any-Type.jpg',
  'Britannia':'https://www.herobullion.com/wp-content/uploads/2020/11/2021-1-oz-British-Gold-Britannia-Coin-Obverse.jpg',
  'Mexican':'https://www.herobullion.com/wp-content/uploads/2021/03/2020-1-oz-Mexican-Gold-Libertad-Coin-1.jpg',
  'Panda':'https://www.herobullion.com/wp-content/uploads/2021/05/1-oz-Chinese-Gold-Panda-Coin-Random-Year-Sealed.jpg',
  'Maple Leaf':'https://www.herobullion.com/wp-content/uploads/2020/03/2020-Canadian-Gold-Maple-1-oz-Coin.jpg',
  'Kangaroo':'https://www.herobullion.com/wp-content/uploads/2024/02/2024-1-oz-Australian-Gold-Kangaroo-Coin.jpg'
};
const COIN_IMG_FALLBACK='data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80"><circle cx="40" cy="40" r="38" fill="%23d4af37" stroke="%23f59e0b" stroke-width="2"/><circle cx="40" cy="40" r="30" fill="none" stroke="%23b8860b" stroke-width="1.5"/><text x="40" y="47" text-anchor="middle" font-size="26" fill="%23b8860b" font-family="serif">🪙</text></svg>';
function renderGoldCoins(){
  const gs=spot.XAU||0;
  const pctEl=document.getElementById('gcl-buy-pct');
  const buyPct=pctEl?(parseFloat(pctEl.value)||90):90;
  const spotEl=document.getElementById('gcl-spot');
  if(spotEl) spotEl.textContent=gs?'$'+gs.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})+'/oz':'—';
  const grid=document.getElementById('gcl-grid');
  if(!grid) return;
  grid.innerHTML='';
  GOLD_COINS.forEach(coin=>{
    const melt=gs*coin.agw;
    const buy=melt*(buyPct/100);
    const imgSrc=COIN_IMG[coin.series]||'';
    const imgHtml=imgSrc
      ?'<img src="'+imgSrc+'" alt="'+coin.name+'" style="width:72px;height:72px;object-fit:contain;border-radius:50%;border:2px solid rgba(212,175,55,0.4);background:#111;flex-shrink:0" onerror="this.src=COIN_IMG_FALLBACK">'
      :'<div style="width:72px;height:72px;border-radius:50%;border:2px solid rgba(212,175,55,0.4);background:rgba(212,175,55,0.12);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:28px">🪙</div>';
    const card=document.createElement('div');
    card.style.cssText='background:#0d1117;border:1px solid rgba(212,175,55,0.35);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    card.innerHTML=
      '<div style="display:flex;gap:12px;align-items:center">'
        +imgHtml
        +'<div style="flex:1;min-width:0">'
          +'<div style="font-size:13px;font-weight:700;color:var(--gold);line-height:1.3;margin-bottom:2px">'+coin.name+'</div>'
          +'<div style="font-size:10px;color:var(--muted)">'+coin.country+'</div>'
          +'<div style="font-size:10px;color:var(--muted);margin-top:3px">AGW: <span style="color:var(--text2);font-weight:600">'+coin.agw.toFixed(4)+' troy oz</span></div>'
        +'</div>'
      +'</div>'
      +'<div style="display:flex;gap:8px">'
        +'<div style="flex:1;background:rgba(212,175,55,0.08);border:1px solid rgba(212,175,55,0.2);border-radius:8px;padding:8px;text-align:center">'
          +'<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Melt Value</div>'
          +'<div style="font-size:16px;font-weight:800;color:var(--gold)">'+(gs?'$'+melt.toFixed(2):'—')+'</div>'
        +'</div>'
        +'<div style="flex:1;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);border-radius:8px;padding:8px;text-align:center">'
          +'<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Buy @ '+buyPct+'%</div>'
          +'<div style="font-size:16px;font-weight:800;color:var(--green)">'+(gs?'$'+buy.toFixed(2):'—')+'</div>'
        +'</div>'
      +'</div>'
      +'<div style="font-size:10px;color:var(--muted)">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
}

/* ── Silver Coin Library ── */
const SILVER_COINS=[
  {name:'American Silver Eagle 1 oz',country:'🇺🇸 USA',asw:1.0000,series:'Silver Eagle'},
  {name:'Canadian Silver Maple Leaf 1 oz',country:'🇨🇦 Canada',asw:1.0000,series:'Maple Leaf'},
  {name:'Austrian Silver Philharmonic 1 oz',country:'🇦🇹 Austria',asw:1.0000,series:'Philharmonic'},
  {name:'British Silver Britannia 1 oz',country:'🇬🇧 UK',asw:1.0000,series:'Britannia'},
  {name:'Australian Silver Kangaroo 1 oz',country:'🇦🇺 Australia',asw:1.0000,series:'Kangaroo'},
  {name:'Mexican Silver Libertad 1 oz',country:'🇲🇽 Mexico',asw:1.0000,series:'Libertad'},
  {name:'Chinese Silver Panda 1 oz',country:'🇨🇳 China',asw:1.0000,series:'Panda'},
  {name:'South African Silver Krugerrand 1 oz',country:'🇿🇦 S. Africa',asw:1.0000,series:'Krugerrand'},
  {name:'American Silver Eagle 1/2 oz',country:'🇺🇸 USA',asw:0.5000,series:'Silver Eagle'},
  {name:'Morgan Silver Dollar (BU)',country:'🇺🇸 USA',asw:0.7734,series:'Morgan'},
  {name:'Peace Silver Dollar (BU)',country:'🇺🇸 USA',asw:0.7734,series:'Peace'},
  {name:'Walking Liberty Half (BU)',country:'🇺🇸 USA',asw:0.3617,series:'Walking Liberty'},
  {name:'Franklin Half Dollar (BU)',country:'🇺🇸 USA',asw:0.3617,series:'Franklin'},
  {name:'Kennedy Half Dollar 1964 (90%)',country:'🇺🇸 USA',asw:0.3617,series:'Kennedy'},
  {name:'Kennedy Half Dollar 1965-70 (40%)',country:'🇺🇸 USA',asw:0.1479,series:'Kennedy 40%'},
  {name:'War Nickel 1942-45 (35%)',country:'🇺🇸 USA',asw:0.0563,series:'War Nickel'},
  {name:'Washington Quarter 1932-64 (90%)',country:'🇺🇸 USA',asw:0.1808,series:'Washington'},
  {name:'Mercury Dime 1916-45 (90%)',country:'🇺🇸 USA',asw:0.0723,series:'Mercury'},
  {name:'Roosevelt Dime 1946-64 (90%)',country:'🇺🇸 USA',asw:0.0723,series:'Roosevelt'},
  {name:'100 oz Silver Bar (.999)',country:'🇺🇸 USA',asw:100.0,series:'Bullion Bar'},
  {name:'10 oz Silver Bar (.999)',country:'🇺🇸 USA',asw:10.0,series:'Bullion Bar'},
  {name:'1 Kilo Silver Bar (.999)',country:'🇺🇸 USA',asw:32.15,series:'Bullion Bar'}
];
const SILVER_COIN_IMG={
  'Silver Eagle':'https://www.herobullion.com/wp-content/uploads/2020/03/2020-American-Silver-Eagle-1-oz-Coin-Obverse.jpg',
  'Maple Leaf':'https://www.herobullion.com/wp-content/uploads/2020/03/2020-Canadian-Silver-Maple-Leaf-1-oz-Coin-Obverse.jpg',
  'Philharmonic':'https://www.herobullion.com/wp-content/uploads/2020/12/2021-1-oz-Austria-Silver-Philharmonic-Coin.jpg',
  'Britannia':'https://www.herobullion.com/wp-content/uploads/2020/11/2021-1-oz-British-Silver-Britannia-Coin-Obverse.jpg',
  'Kangaroo':'https://www.herobullion.com/wp-content/uploads/2024/02/2024-1-oz-Australian-Silver-Kangaroo-Coin.jpg',
  'Libertad':'https://www.herobullion.com/wp-content/uploads/2021/03/2020-1-oz-Mexican-Silver-Libertad-Coin-1.jpg',
  'Panda':'https://www.herobullion.com/wp-content/uploads/2021/05/1-oz-Chinese-Silver-Panda-Coin-Random-Year.jpg',
  'Krugerrand':'https://www.herobullion.com/wp-content/uploads/2020/07/2020-1-oz-South-African-Silver-Krugerrand-Coin-Obverse.jpg'
};

function renderSilverCoins(){
  const ag=spot.XAG||0;
  const pctEl=document.getElementById('scl-buy-pct');
  const buyPct=pctEl?(parseFloat(pctEl.value)||85):85;
  const grid=document.getElementById('scl-grid');
  if(!grid) return;
  grid.innerHTML='';
  SILVER_COINS.forEach(coin=>{
    const melt=ag*coin.asw;
    const buy=melt*(buyPct/100);
    const imgSrc=SILVER_COIN_IMG[coin.series]||'';
    const imgHtml=imgSrc
      ?'<img src=\\\"'+imgSrc+'\\\" alt=\\\"'+coin.name+'\\\" style=\\\"width:72px;height:72px;object-fit:contain;border-radius:50%;border:2px solid rgba(154,174,201,0.35);background:#111;flex-shrink:0\\\" onerror=\\\"this.style.display=\\'none\\'\\\">'
      :'<div style=\"width:72px;height:72px;border-radius:50%;border:2px solid rgba(154,174,201,0.35);background:rgba(154,174,201,0.1);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:28px\">🪙</div>';
    const card=document.createElement('div');
    card.style.cssText='background:rgba(4,14,32,.7);border:1px solid rgba(154,174,201,0.15);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px;backdrop-filter:blur(8px)';
    card.innerHTML=
      '<div style=\"display:flex;gap:12px;align-items:center\">'
        +imgHtml
        +'<div style=\"flex:1;min-width:0\">'
          +'<div style=\"font-size:13px;font-weight:700;color:#c0d0e8;line-height:1.3;margin-bottom:2px\">'+coin.name+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted)\">'+coin.country+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted);margin-top:3px\">ASW: <span style=\"color:var(--text2);font-weight:600\">'+coin.asw.toFixed(4)+' troy oz</span></div>'
        +'</div>'
      +'</div>'
      +'<div style=\"display:flex;gap:8px\">'
        +'<div style=\"flex:1;background:rgba(154,174,201,0.06);border:1px solid rgba(154,174,201,0.15);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Melt Value</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:#c0d0e8\">'+(ag?'$'+melt.toFixed(2):'—')+'</div>'
        +'</div>'
        +'<div style=\"flex:1;background:rgba(63,185,80,0.06);border:1px solid rgba(63,185,80,0.15);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Buy @ '+buyPct+'%</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:var(--green)\">'+(ag?'$'+buy.toFixed(2):'—')+'</div>'
        +'</div>'
      +'</div>'
      +'<div style=\"font-size:10px;color:var(--muted)\">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
}

/* ── Platinum Coin Library ── */
const PLATINUM_COINS=[
  {name:'American Platinum Eagle 1 oz',country:'🇺🇸 USA',apw:1.0000,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/2 oz',country:'🇺🇸 USA',apw:0.5000,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/4 oz',country:'🇺🇸 USA',apw:0.2500,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/10 oz',country:'🇺🇸 USA',apw:0.1000,series:'Platinum Eagle'},
  {name:'Canadian Platinum Maple Leaf 1 oz',country:'🇨🇦 Canada',apw:1.0000,series:'Platinum Maple'},
  {name:'Australian Platinum Platypus 1 oz',country:'🇦🇺 Australia',apw:1.0000,series:'Platypus'},
  {name:'British Platinum Britannia 1 oz',country:'🇬🇧 UK',apw:1.0000,series:'Platinum Britannia'},
  {name:'Austrian Platinum Philharmonic 1 oz',country:'🇦🇹 Austria',apw:1.0000,series:'Platinum Philharmonic'},
  {name:'1 oz Platinum Bar (.9995)',country:'🌍 Various',apw:1.0000,series:'Bullion Bar'}
];
const PALLADIUM_COINS=[
  {name:'American Palladium Eagle 1 oz',country:'🇺🇸 USA',apw:1.0000,series:'Palladium Eagle'},
  {name:'Canadian Palladium Maple Leaf 1 oz',country:'🇨🇦 Canada',apw:1.0000,series:'Palladium Maple'},
  {name:'Russian Palladium Ballerina 1 oz',country:'🇷🇺 Russia',apw:1.0000,series:'Ballerina'},
  {name:'1 oz Palladium Bar (.9995)',country:'🌍 Various',apw:1.0000,series:'Bullion Bar'}
];

function renderPlatinumCoins(){
  const pt=spot.XPT||0;
  const pd=spot.XPD||0;
  const pctEl=document.getElementById('ptl-buy-pct');
  const buyPct=pctEl?(parseFloat(pctEl.value)||85):85;
  const grid=document.getElementById('ptl-grid');
  if(!grid) return;
  grid.innerHTML='';
  // Platinum section header
  grid.innerHTML+='<div style=\"grid-column:1/-1;font-size:13px;font-weight:700;color:var(--cyan);padding:8px 0 4px;border-bottom:1px solid rgba(34,211,238,.1);margin-bottom:4px\">⚗️ Platinum Coins & Bars</div>';
  PLATINUM_COINS.forEach(coin=>{
    const melt=pt*coin.apw;
    const buy=melt*(buyPct/100);
    const card=document.createElement('div');
    card.style.cssText='background:rgba(4,14,32,.7);border:1px solid rgba(34,211,238,.12);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    card.innerHTML=
      '<div style=\"display:flex;gap:12px;align-items:center\">'
        +'<div style=\"width:72px;height:72px;border-radius:50%;border:2px solid rgba(34,211,238,.3);background:rgba(34,211,238,.08);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:30px\">⚗️</div>'
        +'<div style=\"flex:1;min-width:0\">'
          +'<div style=\"font-size:13px;font-weight:700;color:var(--cyan);line-height:1.3;margin-bottom:2px\">'+coin.name+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted)\">'+coin.country+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted);margin-top:3px\">APW: <span style=\"color:var(--text2);font-weight:600\">'+coin.apw.toFixed(4)+' troy oz</span></div>'
        +'</div>'
      +'</div>'
      +'<div style=\"display:flex;gap:8px\">'
        +'<div style=\"flex:1;background:rgba(34,211,238,.05);border:1px solid rgba(34,211,238,.12);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Melt Value</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:var(--cyan)\">'+(pt?'$'+melt.toFixed(2):'—')+'</div>'
        +'</div>'
        +'<div style=\"flex:1;background:rgba(63,185,80,0.06);border:1px solid rgba(63,185,80,0.15);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Buy @ '+buyPct+'%</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:var(--green)\">'+(pt?'$'+buy.toFixed(2):'—')+'</div>'
        +'</div>'
      +'</div>'
      +'<div style=\"font-size:10px;color:var(--muted)\">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
  // Palladium section
  grid.innerHTML+='<div style=\"grid-column:1/-1;font-size:13px;font-weight:700;color:var(--violet);padding:12px 0 4px;border-bottom:1px solid rgba(167,139,250,.1);margin-bottom:4px\">⚛️ Palladium Coins & Bars</div>';
  PALLADIUM_COINS.forEach(coin=>{
    const melt=pd*coin.apw;
    const buy=melt*(buyPct/100);
    const card=document.createElement('div');
    card.style.cssText='background:rgba(4,14,32,.7);border:1px solid rgba(167,139,250,.12);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    card.innerHTML=
      '<div style=\"display:flex;gap:12px;align-items:center\">'
        +'<div style=\"width:72px;height:72px;border-radius:50%;border:2px solid rgba(167,139,250,.3);background:rgba(167,139,250,.08);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:30px\">⚛️</div>'
        +'<div style=\"flex:1;min-width:0\">'
          +'<div style=\"font-size:13px;font-weight:700;color:var(--violet);line-height:1.3;margin-bottom:2px\">'+coin.name+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted)\">'+coin.country+'</div>'
          +'<div style=\"font-size:10px;color:var(--muted);margin-top:3px\">APW: <span style=\"color:var(--text2);font-weight:600\">'+coin.apw.toFixed(4)+' troy oz</span></div>'
        +'</div>'
      +'</div>'
      +'<div style=\"display:flex;gap:8px\">'
        +'<div style=\"flex:1;background:rgba(167,139,250,.05);border:1px solid rgba(167,139,250,.12);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Melt Value</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:var(--violet)\">'+(pd?'$'+melt.toFixed(2):'—')+'</div>'
        +'</div>'
        +'<div style=\"flex:1;background:rgba(63,185,80,0.06);border:1px solid rgba(63,185,80,0.15);border-radius:8px;padding:8px;text-align:center\">'
          +'<div style=\"font-size:10px;color:var(--muted);margin-bottom:2px\">Buy @ '+buyPct+'%</div>'
          +'<div style=\"font-size:16px;font-weight:800;color:var(--green)\">'+(pd?'$'+buy.toFixed(2):'—')+'</div>'
        +'</div>'
      +'</div>'
      +'<div style=\"font-size:10px;color:var(--muted)\">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
}

async function doLogout(){await fetch('/api/logout',{method:'POST'});window.location.href='/';}

// ═══ INVENTORY ═══
let inventory=JSON.parse(localStorage.getItem('bdp-inv')||'[]');
let slabs=JSON.parse(localStorage.getItem('bdp-slabs')||'[]');
let invTabMode='general';
let syncEnabled=false;
let syncDebounceTimer=null;

// ── Cloud sync helpers ──
async function cloudPull(){
  try{
    const r=await fetch('/api/sync');
    if(!r.ok)return;
    const d=await r.json();
    // Check if local data exists and differs from cloud
    const hasLocal=inventory.length>0||slabs.length>0||Object.keys(tsLoadChecks()).length>0;
    const hasCloud=d.inventory.length>0||d.slabs.length>0||Object.keys(d.typesets).length>0;
    if(hasLocal&&!hasCloud){
      // Local data exists, nothing in cloud — offer to upload
      if(confirm('You have local collection data. Upload it to your PRO account so it syncs across all your devices?')){
        inventory=inventory; slabs=slabs;
        await cloudPush(true);
      }
    } else if(hasCloud){
      // Cloud has data — use it (cloud wins)
      inventory=d.inventory;
      slabs=d.slabs;
      localStorage.setItem('bdp-inv',JSON.stringify(inventory));
      localStorage.setItem('bdp-slabs',JSON.stringify(slabs));
      if(Object.keys(d.typesets).length>0){
        localStorage.setItem('bdp_typesets',JSON.stringify(d.typesets));
      }
      if(d.presets&&Object.keys(d.presets).length>0){
        localStorage.setItem('bdp-presets',JSON.stringify(d.presets));
        presetLoad();
      }
      if(d.alerts&&d.alerts.length>0){
        priceAlerts=d.alerts;
        localStorage.setItem('bdp-alerts',JSON.stringify(priceAlerts));
      }
    }
    syncEnabled=true;
    renderInventory();renderSlabs();
    showSyncBadge('✅ Synced');
  }catch(e){console.warn('Cloud pull failed',e);}
}

async function cloudPush(immediate=false){
  if(!syncEnabled&&!immediate)return;
  clearTimeout(syncDebounceTimer);
  syncDebounceTimer=setTimeout(async()=>{
    try{
      showSyncBadge('⏫ Saving…');
      const typesets=tsLoadChecks();
      const presets=JSON.parse(localStorage.getItem('bdp-presets')||'{}');
      const alerts=JSON.parse(localStorage.getItem('bdp-alerts')||'[]');
      await fetch('/api/sync',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({inventory,slabs,typesets,presets,alerts})});
      showSyncBadge('✅ Synced');
    }catch(e){showSyncBadge('⚠ Sync error');}
  }, immediate?0:1500);
}

function showSyncBadge(msg){
  let badge=$('sync-badge');
  if(!badge)return;
  badge.textContent=msg;
  badge.style.opacity='1';
  clearTimeout(badge._fadeTimer);
  badge._fadeTimer=setTimeout(()=>{badge.style.opacity='0';},3000);
}

function invSwitchTab(mode,btn){
  invTabMode=mode;
  document.querySelectorAll('#tab-admin .sub-nav .seg').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  $('inv-section-general').style.display=mode==='general'?'':'none';
  $('inv-section-slabs').style.display=mode==='slabs'?'':'none';
}

// ── General Inventory ──
function invAdd(){$('inv-form').style.display='block';}
function invSave(){
  const name=$('inv-name').value.trim();if(!name)return alert('Enter item name');
  inventory.push({name,qty:parseInt($('inv-qty').value)||1,cost:parseFloat($('inv-cost').value)||0,type:$('inv-type').value,date:new Date().toLocaleDateString()});
  localStorage.setItem('bdp-inv',JSON.stringify(inventory));
  $('inv-form').style.display='none';renderInventory();cloudPush();
}
function invDel(i){inventory.splice(i,1);localStorage.setItem('bdp-inv',JSON.stringify(inventory));renderInventory();cloudPush();}
function clearInv(){if(!confirm('Clear all inventory?'))return;inventory=[];localStorage.setItem('bdp-inv','[]');renderInventory();cloudPush();}
function invMeltVal(item){
  const ag=spot.XAG||0, au=spot.XAU||0, cu=spot.HG||0;
  const q=item.qty||1;
  switch(item.type){
    case'silver_coin':   return ag*0.7234*q;   // per $1 face
    case'morgan':        return ag*0.77344*q;
    case'silver_eagle':  return ag*1.0*q;
    case'gold_eagle_1oz':return au*1.0*q;
    case'gold_eagle_half':return au*0.5*q;
    case'gold_eagle_qtr':return au*0.25*q;
    case'gold_eagle_tenth':return au*0.1*q;
    case'gold_buffalo':  return au*1.0*q;
    case'gold_bar':      return au*(item.qty||1); // qty = troy oz
    case'silver_bar':    return ag*(item.qty||1);
    case'silver_bullion':return ag*(item.qty||1);
    case'copper_penny':  return cu*0.00220462262*3.11*0.95*q;
    default: return 0;
  }
}
function renderInventory(){
  const tb=$('inv-tbody');if(!tb)return;
  if(!inventory.length){tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:22px">No items yet</td></tr>';$('inv-summary').textContent='';return;}
  let totalCost=0,totalMelt=0;
  tb.innerHTML=inventory.map((item,i)=>{
    const cost=item.qty*item.cost;totalCost+=cost;
    const melt=invMeltVal(item);totalMelt+=melt;
    const meltStr=melt>0?`<span style="color:var(--gold);font-weight:600">${fmt(melt)}</span>`:'<span style="color:var(--muted)">—</span>';
    const pl=melt>0?melt-cost:0;
    const plColor2=pl>=0?'var(--green)':'var(--red)';
    const plStr=melt>0?'<span style="color:'+plColor2+';font-weight:600">'+(pl>=0?'+':'')+fmt(pl)+'</span>':'<span style="color:var(--muted)">—</span>';
    return`<tr><td style="font-weight:600">${item.name}</td><td>${item.qty}</td><td class="price-col">${fmt(item.cost)}</td><td class="price-col">${fmt(cost)}</td><td>${meltStr}</td><td>${plStr}</td><td><button onclick="invDel(${i})" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:2px 7px;border-radius:4px;cursor:pointer;font-size:10px">✕</button></td></tr>`;
  }).join('');
  const plTot=totalMelt-totalCost;
  $('inv-summary').innerHTML=inventory.length+' items · Cost: <strong>'+fmt(totalCost)+'</strong> · Melt: <strong style="color:var(--gold)">'+fmt(totalMelt)+'</strong>'+(totalMelt>0?' · P&L: <strong style="color:'+(plTot>=0?'var(--green)':'var(--red)')+'">'+  (plTot>=0?'+':'')+fmt(plTot)+'</strong>':'');
}

// ── Graded Slabs ──
function slabAdd(){$('slab-form').style.display='block';}
function slabSave(){
  const name=$('slab-name').value.trim();if(!name)return alert('Enter coin name');
  const svc=$('slab-service').value;
  const grade=$('slab-grade').value;
  const cert=$('slab-cert').value.trim();
  const cac=$('slab-cac').value;
  const cost=parseFloat($('slab-cost').value)||0;
  const value=parseFloat($('slab-value').value)||0;
  const notes=$('slab-notes').value.trim();
  const year=$('slab-year').value.trim();
  const mint=$('slab-mint').value;
  slabs.push({name,year,mint,svc,grade,cac,cert,cost,value,notes,date:new Date().toLocaleDateString()});
  localStorage.setItem('bdp-slabs',JSON.stringify(slabs));
  $('slab-form').style.display='none';
  // Reset form
  ['slab-name','slab-year','slab-cert','slab-cost','slab-value','slab-notes'].forEach(id=>{const el=$(id);if(el)el.value='';});
  renderSlabs();cloudPush();
}
function slabDel(i){if(!confirm('Remove this slab?'))return;slabs.splice(i,1);localStorage.setItem('bdp-slabs',JSON.stringify(slabs));renderSlabs();cloudPush();}
function clearSlabs(){if(!confirm('Clear all graded slabs?'))return;slabs=[];localStorage.setItem('bdp-slabs','[]');renderSlabs();cloudPush();}
function slabCertLink(svc,cert){
  if(!cert)return'—';
  const urls={
    PCGS:`https://www.pcgs.com/cert/${cert}`,
    NGC:`https://www.ngccoin.com/certlookup/${cert}/`,
    CAC:`https://www.caccoin.com/`,
    ANACS:`https://www.anacs.com/`,
    ICG:`https://www.icgcoin.com/`
  };
  const url=urls[svc]||'#';
  return`<a href="${url}" target="_blank" style="color:var(--blue2);font-weight:600;font-size:11px">${cert} ↗</a>`;
}
function exportInvCSV(){
  if(!inventory.length)return alert('No inventory to export');
  const rows=[['Item','Qty','Cost Each','Total Cost','Type','Date Added'],...inventory.map(i=>[i.name,i.qty,i.cost,(i.qty*i.cost).toFixed(2),i.type,i.date])];
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);a.download='inventory_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}
function exportSlabCSV(){
  if(!slabs.length)return alert('No slabs to export');
  const rows=[['Coin','Year','Mint','Service','Grade','CAC','Cert #','Paid','Est Value','P&L','Notes','Date Added'],...slabs.map(s=>{const pl=((s.value||0)-(s.cost||0)).toFixed(2);return[s.name,s.year||'',s.mint||'',s.svc,s.grade,s.cac||'none',s.cert||'',s.cost||'',s.value||'',pl,s.notes||'',s.date];})];
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);a.download='graded_slabs_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}
function renderSlabs(){
  const tb=$('slab-tbody');if(!tb)return;
  const q=(($('slab-search')||{}).value||'').toLowerCase();
  const filtered=q?slabs.filter(s=>[s.name,s.svc,s.grade,s.cert,s.notes,s.year,s.mint].join(' ').toLowerCase().includes(q)):slabs;
  if(!filtered.length){tb.innerHTML='<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:22px">'+(q?'No slabs match your search':'No graded slabs yet — click + Add Slab to get started')+'</td></tr>';$('slab-summary').textContent='';return;}
  const svcColors={PCGS:'#003087',NGC:'#4a90d9',CAC:'#16a34a',ANACS:'#b45309',ICG:'#7c3aed',Raw:'#6b7280'};
  const cacBadge={none:'',green:'<span style="color:#16a34a;font-size:13px" title="CAC Green Bean">✅</span>',gold:'<span style="color:#d97706;font-size:13px" title="CAC Gold Bean">⭐</span>'};
  const gradeColor=g=>{if(g.startsWith('MS7')||g==='PR70')return'var(--green)';if(g.startsWith('MS6')||g.startsWith('PR6'))return'var(--gold)';if(g.startsWith('AU'))return'var(--blue2)';return'var(--text)';};
  let totalCost2=0,totalValue2=0;
  tb.innerHTML=filtered.map((s,i)=>{
    totalCost2+=s.cost||0;totalValue2+=s.value||0;
    const pl=(s.value||0)-(s.cost||0);
    const plColor=pl>0?'var(--green)':pl<0?'var(--red)':'var(--muted)';
    const mm=s.mint?`-${s.mint}`:'';
    return`<tr>
      <td style="font-weight:700;max-width:160px">${s.name}</td>
      <td style="color:var(--muted)">${s.year||'—'}${mm}</td>
      <td><span style="background:${svcColors[s.svc]||'#666'};color:#fff;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700">${s.svc}</span></td>
      <td style="font-weight:700;color:${gradeColor(s.grade)}">${s.grade}</td>
      <td style="text-align:center">${cacBadge[s.cac||'none']||''}</td>
      <td>${slabCertLink(s.svc,s.cert)}</td>
      <td class="price-col">${s.cost?fmt(s.cost):'—'}</td>
      <td class="price-col rv-gold">${s.value?fmt(s.value):'—'}</td>
      <td style="font-weight:700;color:${plColor}">${s.cost&&s.value?(pl>=0?'+':'')+fmt(pl):'—'}</td>
      <td><button onclick="slabDel(slabs.indexOf(s))" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:2px 7px;border-radius:4px;cursor:pointer;font-size:10px">✕</button></td>
    </tr>`;
  }).join('');
  const totalPL=totalValue2-totalCost2;
  const plColor=totalPL>0?'var(--green)':totalPL<0?'var(--red)':'var(--muted)';
  $('slab-summary').innerHTML=`${filtered.length}${q?' matching':''} of ${slabs.length} slabs · Total paid: <strong>${fmt(totalCost2)}</strong> · Est. value: <strong style="color:var(--gold)">${fmt(totalValue2)}</strong> · P&L: <strong style="color:${plColor}">${totalPL>=0?'+':''}${fmt(totalPL)}</strong>`;
}

// ═══ DEALER PRESETS ═══
function presetLoad(){
  const p=JSON.parse(localStorage.getItem('bdp-presets')||'{}');
  if(p.agBuy!=null){const el=$('deal-buy-pct');if(el)el.value=p.agBuy;}
  if(p.agSell!=null){const el=$('deal-sell-pct');if(el)el.value=p.agSell;}
  if($('preset-ag-buy'))$('preset-ag-buy').value=p.agBuy||'';
  if($('preset-ag-sell'))$('preset-ag-sell').value=p.agSell||'';
  if($('preset-au-buy'))$('preset-au-buy').value=p.auBuy||'';
  if($('preset-au-sell'))$('preset-au-sell').value=p.auSell||'';
}
function presetSave(){
  const p={
    agBuy:parseFloat($('preset-ag-buy').value)||null,
    agSell:parseFloat($('preset-ag-sell').value)||null,
    auBuy:parseFloat($('preset-au-buy').value)||null,
    auSell:parseFloat($('preset-au-sell').value)||null,
  };
  localStorage.setItem('bdp-presets',JSON.stringify(p));
  presetLoad();
  const msg=$('preset-msg');msg.textContent='✅ Saved!';setTimeout(()=>msg.textContent='',2500);
  cloudPush();
}
function presetPreview(){}

// ═══ PRICE ALERTS ═══
let priceAlerts=JSON.parse(localStorage.getItem('bdp-alerts')||'[]');
const metalNames={XAU:'Gold',XAG:'Silver',HG:'Copper',XPT:'Platinum',XPD:'Palladium'};

function alertAdd(){
  const metal=$('alert-metal').value;
  const dir=$('alert-dir').value;
  const price=parseFloat($('alert-price').value);
  if(!price||price<=0)return alert('Enter a valid target price');
  priceAlerts.push({metal,dir,price,triggered:false,id:Date.now()});
  localStorage.setItem('bdp-alerts',JSON.stringify(priceAlerts));
  $('alert-price').value='';
  renderAlerts();
}
function alertDel(id){
  priceAlerts=priceAlerts.filter(a=>a.id!==id);
  localStorage.setItem('bdp-alerts',JSON.stringify(priceAlerts));
  renderAlerts();
}
function renderAlerts(){
  const el=$('alert-list');if(!el)return;
  if(!priceAlerts.length){el.innerHTML='<div style="font-size:12px;color:var(--muted);text-align:center;padding:8px">No alerts set</div>';return;}
  el.innerHTML=priceAlerts.map(a=>{
    const cur=spot[a.metal]||0;
    const triggered=a.dir==='above'?cur>=a.price:cur<=a.price;
    const status=triggered?'<span style="color:var(--green);font-weight:700">🔔 HIT</span>':'<span style="color:var(--muted)">⏳ Watching</span>';
    return`<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border);gap:8px;flex-wrap:wrap">
      <div style="font-size:13px;font-weight:600">${metalNames[a.metal]} ${a.dir==='above'?'↑ above':'↓ below'} ${fmt(a.price)}</div>
      <div style="display:flex;align-items:center;gap:8px">${status}<button onclick="alertDel(${a.id})" style="background:transparent;border:1px solid var(--red);color:var(--red);padding:2px 7px;border-radius:4px;cursor:pointer;font-size:10px">✕</button></div>
    </div>`;
  }).join('');
}
function checkAlerts(){
  if(!priceAlerts.length)return;
  priceAlerts.forEach(a=>{
    if(a.triggered)return;
    const cur=spot[a.metal]||0;if(!cur)return;
    const hit=a.dir==='above'?cur>=a.price:cur<=a.price;
    if(hit){
      a.triggered=true;
      alert(`🔔 Price Alert: ${metalNames[a.metal]} has ${a.dir==='above'?'risen above':'fallen below'} your target of ${fmt(a.price)}!\nCurrent price: ${fmt(cur)}`);
      localStorage.setItem('bdp-alerts',JSON.stringify(priceAlerts));
      renderAlerts();
    }
  });
}
setInterval(checkAlerts,900000); // check every 15 min

// ═══ PRINT REPORT ═══
function printSlabReport(){
  if(!slabs.length)return alert('No slabs to print');
  const d=new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
  const auPrice=spot.XAU?fmt(spot.XAU):'—';
  const agPrice=spot.XAG?fmt(spot.XAG):'—';
  let totalCost=0,totalVal=0;
  const svcColors={PCGS:'#003087',NGC:'#2563eb',CAC:'#16a34a',ANACS:'#b45309',ICG:'#7c3aed',Raw:'#6b7280'};
  const rows=slabs.map(s=>{
    totalCost+=s.cost||0;totalVal+=s.value||0;
    const pl=(s.value||0)-(s.cost||0);
    const mm=s.mint?`-${s.mint}`:'';
    const cacLabel=s.cac==='green'?'Green ✅':s.cac==='gold'?'Gold ⭐':'—';
    return`<tr>
      <td><strong>${s.name}</strong></td>
      <td>${s.year||'—'}${mm}</td>
      <td><span style="background:${svcColors[s.svc]||'#666'};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">${s.svc}</span></td>
      <td><strong>${s.grade}</strong></td>
      <td>${cacLabel}</td>
      <td>${s.cert||'—'}</td>
      <td>$${(s.cost||0).toFixed(2)}</td>
      <td>$${(s.value||0).toFixed(2)}</td>
      <td style="color:${pl>=0?'#16a34a':'#dc2626'};font-weight:700">${pl>=0?'+':''}$${pl.toFixed(2)}</td>
    </tr>`;
  }).join('');
  const totalPL=totalVal-totalCost;
  const w=window.open('','_blank','width=900,height=700');
  w.document.write(`<!DOCTYPE html><html><head><title>Graded Coin Collection Report</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',Arial,sans-serif;padding:32px;color:#111;font-size:13px}
    h1{font-size:22px;font-weight:800;margin-bottom:4px}
    .subtitle{color:#555;font-size:13px;margin-bottom:20px}
    .meta{display:flex;gap:32px;margin-bottom:24px;padding:12px 16px;background:#f8f9fa;border-radius:8px;border:1px solid #e5e7eb}
    .meta-item{text-align:center}
    .meta-label{font-size:10px;font-weight:700;letter-spacing:1px;color:#888;text-transform:uppercase}
    .meta-value{font-size:16px;font-weight:800;color:#111;margin-top:2px}
    table{width:100%;border-collapse:collapse;margin-top:8px}
    th{background:#1e3a5f;color:#fff;padding:8px 10px;font-size:11px;font-weight:700;text-align:left;letter-spacing:.5px}
    td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:middle}
    tr:nth-child(even) td{background:#f9fafb}
    .totals{margin-top:20px;padding:14px 16px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;display:flex;gap:32px;flex-wrap:wrap}
    .tot-item{text-align:center}
    .tot-label{font-size:10px;font-weight:700;letter-spacing:1px;color:#555;text-transform:uppercase}
    .tot-val{font-size:18px;font-weight:800;margin-top:2px}
    .footer{margin-top:28px;font-size:11px;color:#999;text-align:center;border-top:1px solid #e5e7eb;padding-top:12px}
    @media print{body{padding:20px}.footer{position:fixed;bottom:0;width:100%}}
  </style></head><body>
  <h1>🏅 Graded Coin Collection Report</h1>
  <div class="subtitle">Spot Prices &amp; Dealer Tools &nbsp;·&nbsp; ${d}</div>
  <div class="meta">
    <div class="meta-item"><div class="meta-label">Total Slabs</div><div class="meta-value">${slabs.length}</div></div>
    <div class="meta-item"><div class="meta-label">Total Paid</div><div class="meta-value">$${totalCost.toFixed(2)}</div></div>
    <div class="meta-item"><div class="meta-label">Est. Value</div><div class="meta-value" style="color:#d97706">$${totalVal.toFixed(2)}</div></div>
    <div class="meta-item"><div class="meta-label">Overall P&amp;L</div><div class="meta-value" style="color:${totalPL>=0?'#16a34a':'#dc2626'}">${totalPL>=0?'+':''}$${totalPL.toFixed(2)}</div></div>
    <div class="meta-item"><div class="meta-label">Gold Spot</div><div class="meta-value">${auPrice}</div></div>
    <div class="meta-item"><div class="meta-label">Silver Spot</div><div class="meta-value">${agPrice}</div></div>
  </div>
  <table>
    <thead><tr><th>Coin</th><th>Year/MM</th><th>Service</th><th>Grade</th><th>CAC</th><th>Cert #</th><th>Paid</th><th>Est. Value</th><th>P&amp;L</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <div class="footer">Generated by Spot Prices &amp; Dealer Tools · bulliondealerpro.com · ${d}</div>
  <script>window.onload=()=>window.print();<\/script>
  </body></html>`);
  w.document.close();
}

// ═══ INIT ═══
async function init(){
  adjustPad();
  // renderCoinVals and renderAllKeyDates are called when their tabs open — not at startup
  try{calcGold();calcConst();calcPenny();calcPlatPal();tsUpdateOverall();}catch(e){console.warn('[init] calc error:',e);}
  // Spot prices and auth are FULLY independent — run simultaneously
  loadSpot().catch(e=>console.warn('loadSpot:',e));
  loadAccount().catch(e=>{ window_isPro=false; window_authReady=true; applyGuestUI(); console.warn('loadAccount:',e); });
  loadNews().catch(()=>{});
  setInterval(()=>loadSpot().catch(()=>{}), 5*60*1000);
  setInterval(()=>loadNews().catch(()=>{}), 10*60*1000);
}
init();



function copySpotPrices(){
  const gEl=$('gold-hero-price');
  const sEl=$('silver-spotlight-price');
  const rEl=$('gs-ratio');
  const g=gEl?gEl.textContent.trim():'—';
  const s=sEl?sEl.textContent.trim():'—';
  const r=rEl?rEl.textContent.trim():'—';
  const now=new Date();
  const ts=now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  const text='📊 Spot Prices as of '+ts+'\n🥇 Gold: '+g+'/oz\n🪙 Silver: '+s+'/oz\n⚖️ Gold:Silver Ratio: '+r;
  const btn=$('copy-prices-btn');
  function flash(){if(btn){btn.textContent='✅ Copied!';setTimeout(()=>{btn.textContent='📋 Copy Prices';},2000);}}
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(text).then(flash).catch(()=>{
      const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0;top:0;left:0';
      document.body.appendChild(ta);ta.focus();ta.select();
      try{document.execCommand('copy');flash();}catch(e){}
      document.body.removeChild(ta);
    });
  } else {
    const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0;top:0;left:0';
    document.body.appendChild(ta);ta.focus();ta.select();
    try{document.execCommand('copy');flash();}catch(e){}
    document.body.removeChild(ta);
  }
}

const GOLD_FACTS=[
"Gold has been valued for over 5,000 years — the earliest known coins date to 600 BC in ancient Lydia.",
"The word 'gold' comes from the Old English word 'geolu,' meaning yellow.",
"All the gold ever mined in history would fit into a cube roughly 21 meters on each side.",
"Gold is so malleable that one ounce can be beaten into a sheet covering 100 square feet.",
"The United States held the world's largest gold reserve at Fort Knox — over 4,600 tons.",
"Gold was the foundation of the international monetary system until the US ended the gold standard in 1971.",
"Ancient Egyptians associated gold with the sun god Ra and used it extensively in burial rituals.",
"The California Gold Rush of 1848–1855 brought over 300,000 prospectors to the state.",
"The highest recorded gold price was over $3,500 per troy ounce in 2025.",
"Gold is one of the few elements that occurs in nature in its pure metallic form.",
"The Witwatersrand Basin in South Africa has produced roughly 40% of all gold ever mined.",
"Gold melts at 1,064°C (1,947°F) and boils at 2,856°C (5,173°F).",
"Pure gold (24 karat) is too soft for most jewelry — it's typically alloyed with silver or copper.",
"The Aztec word for gold was 'teocuitlatl,' meaning 'excrement of the gods.'",
"Spain looted an estimated 200 tons of gold and silver from the Americas between 1500–1600.",
"Gold is chemically inert — it doesn't rust, tarnish, or corrode under normal conditions.",
"The Midas touch legend comes from King Midas of Phrygia, a real ancient ruler known for his wealth.",
"NASA uses gold-coated visors on astronaut helmets to reflect solar radiation.",
"The Klondike Gold Rush of 1896 in Yukon, Canada led to the founding of Dawson City.",
"Gold's atomic number is 79 and its chemical symbol Au comes from the Latin 'aurum.'",
"The largest gold nugget ever found was the 'Welcome Stranger' — 2,316 troy ounces, found in Australia in 1869.",
"Central banks collectively hold over 35,000 tons of gold as monetary reserves.",
"Gold is edible — 24-karat gold leaf is used as a food decoration and is classified as safe.",
"The phrase 'good as gold' dates to at least the 1840s and reflects gold's reputation for reliability.",
"Gold's rarity on Earth is partly because most of it sank to the planet's core during formation.",
"Scientists believe most gold on Earth arrived via meteorite bombardment 4 billion years ago.",
"The first gold coins in the US were minted in 1795 by the Philadelphia Mint.",
"South Africa was the world's top gold producer for most of the 20th century; China now holds that title.",
"The Gold Reserve Act of 1934 raised the official gold price from \$20.67 to \$35 per troy ounce.",
"During WWII, many countries secretly moved gold reserves to prevent capture by Axis powers.",
"Gold's thermal and electrical conductivity make it essential in electronics and aerospace.",
"The Dead Sea Scrolls jars were sealed with a bitumen that contained trace amounts of gold.",
"Roman soldiers were sometimes paid in gold — the term 'salary' traces back to salt, but gold was the prestige pay.",
"The Swiss Franc was backed by gold at a 40% reserve requirement until the year 2000.",
"Jewelry accounts for roughly 50% of global gold demand each year."
];
const SILVER_FACTS=[
"Silver has been used as money for over 4,000 years — longer than gold in many civilizations.",
"The chemical symbol for silver, Ag, comes from the Latin word 'argentum.'",
"Argentina was named after silver — Spanish explorers believed it held vast silver deposits.",
"Silver is the best electrical conductor of all metals, surpassing even copper.",
"The largest silver nugget ever found weighed 1,840 pounds and was discovered in Mexico.",
"In the 1800s, the Comstock Lode in Nevada produced over 300 million ounces of silver.",
"Silver has natural antimicrobial properties — ancient civilizations stored water in silver vessels.",
"The US officially demonetized silver in 1873, an act critics called the 'Crime of 1873.'",
"Silver's melting point is 961.8°C (1,763°F).",
"The Hunt Brothers attempted to corner the silver market in 1980, driving prices to \$50/oz before a dramatic collapse.",
"One troy ounce of silver can be drawn into a wire over 8,000 feet long.",
"Silver is used in solar panels — approximately 100 million ounces per year go to the solar industry.",
"The phrase 'born with a silver spoon' reflects the historical association of silver with wealth and good health.",
"Bolivia's Cerro Rico mountain produced so much silver that it was called the 'mountain that eats men.'",
"90% silver US coins — dimes, quarters, and halves — were struck from 1892 through 1964.",
"Silver iodide is used in cloud seeding to induce rainfall.",
"Ancient Romans used silver acetate as an early treatment for alcoholism.",
"The Morgan Silver Dollar (1878–1921) is the most collected US coin series of all time.",
"Silver's reflectivity is the highest of any metal — over 99% of visible light.",
"The term 'sterling silver' (92.5% pure) dates to medieval England and the Easterling traders.",
"During WWI, the US Mint melted over 270 million silver dollars to provide silver to Britain.",
"Silver was once more valuable than gold in ancient Egypt due to its relative scarcity.",
"Photography relied on silver halide compounds from the 1830s until the digital age.",
"Silver is a byproduct of lead, zinc, and copper mining — less than 30% comes from primary silver mines.",
"The Peace Dollar (1921–1935) was designed to commemorate the end of World War I.",
"Mexico is the world's largest silver-producing country, followed by China and Peru.",
"The US Strategic Stockpile once held over 2 billion ounces of silver.",
"Silver nanoparticles are embedded in clothing, bandages, and medical devices for their antibacterial properties.",
"The Walking Liberty Half Dollar (1916–1947) is considered one of the most beautiful US coin designs.",
"Silver prices hit an all-time high of about \$50/oz twice — in 1980 and again in 2011.",
"Warren Buffett purchased 130 million ounces of silver in 1997 — about 30% of world supply at the time.",
"Silver is used in every new car — approximately one ounce per vehicle for electrical contacts.",
"The first American silver coin was the Flowing Hair Dollar, struck in 1794.",
"Ancient Greeks used silver to purify water during military campaigns.",
"Silver's role in mirrors dates to the 13th century — modern mirrors still use a thin silver coating."
];
const CONST_FACTS=[
"US dimes, quarters, and half dollars minted before 1965 contain 90% silver.",
"The Coinage Act of 1792 established the US Mint and set the silver dollar at 371.25 grains of pure silver.",
"War nickels (1942–1945) contain 35% silver — minted to save nickel for WWII military use.",
"Franklin Half Dollars minted 1948–1963 contain .3617 oz of silver each.",
"Kennedy Half Dollars from 1965–1970 are 40% silver, not 90%.",
"A roll of 90% silver quarters (40 coins) contains approximately 7.15 troy ounces of silver.",
"The Mercury Dime (1916–1945) is actually Lady Liberty — not the Roman god Mercury.",
"Barber coinage (1892–1916) includes dimes, quarters, and half dollars — all 90% silver.",
"The Standing Liberty Quarter was redesigned in 1917 after the public objected to Liberty's exposed breast.",
"A 'junk silver' bag containing \$1,000 face value holds approximately 715 troy ounces of silver.",
"The term 'constitutional silver' refers to coins that were legal tender under the original US monetary system.",
"Morgan Dollars (1878–1921) and Peace Dollars (1921–1935) each contain .7734 oz of silver.",
"Eisenhower Dollars (1971–1978) struck for circulation contain no silver — only proof versions do.",
"The Walking Liberty Half Dollar inspired the design of the modern American Silver Eagle.",
"Silver coins were removed from circulation when the rising silver price made their melt value exceed face value.",
"The Coinage Act of 1965, signed by LBJ, eliminated silver from dimes and quarters entirely.",
"A \$1 face value of 90% silver coins contains approximately 0.715 troy ounces of silver.",
"Pre-1965 Roosevelt Dimes are one of the most affordable ways to accumulate silver by weight.",
"The design on the Standing Liberty Quarter was modified in 1925 to add a date that was wearing off too quickly.",
"The 1916-D Mercury Dime is one of the most coveted key dates in 20th century US coinage.",
"Silver Washington Quarters were first minted in 1932 to commemorate the 200th anniversary of his birth.",
"The Seated Liberty design appeared on US silver coins from 1836 through 1891.",
"During WWII, the US Mint used silver in nickels to free up nickel for military equipment like armor plating.",
"The 1955 Doubled Die Lincoln Cent is the most famous US mint error coin.",
"Franklin Half Dollars were only minted for 15 years — making them relatively scarce compared to other series.",
"Proof sets containing 90% silver coins were sold directly to collectors by the US Mint starting in 1936.",
"A full set of circulated 90% silver coins from 1892–1964 spans over 70 years of US monetary history.",
"The New Orleans Mint produced silver coins from 1838 until it was captured by Confederate forces in 1861.",
"The 1804 Silver Dollar — though dated 1804 — was actually struck decades later as a diplomatic gift.",
"Coin roll hunting is a popular hobby where collectors search through bank rolls for silver coins still in circulation."
];
const COPPER_FACTS=[
"Pennies minted before 1982 are 95% copper and worth more than face value in melt.",
"The 1943 Steel Penny was made of zinc-coated steel to save copper for WWII ammunition casings.",
"A few 1943 copper pennies were accidentally struck — one sold for over \$1.7 million.",
"Copper has been used by humans for over 10,000 years — longer than any other metal.",
"The US switched pennies from 95% copper to copper-plated zinc in 1982 to cut production costs.",
"Copper's chemical symbol Cu comes from 'Cuprum,' the Latin name for Cyprus, where Romans mined it.",
"Modern pennies cost about 2 cents each to produce — the US loses money on every penny minted.",
"Copper is essential for electric vehicles — a single EV uses about 183 pounds of copper.",
"The Statue of Liberty is clad in approximately 80 tons of copper sheet — now green from oxidation.",
"Chile holds the world's largest copper reserves and produces about 27% of global supply.",
"Copper is one of the best conductors of electricity, second only to silver.",
"The first US cent was the large cent — nearly the size of a modern half dollar — minted from 1793 to 1857.",
"Lincoln replaced the Indian Head Cent design in 1909 — the first US coin to feature a real person.",
"The Flying Eagle Cent (1856–1858) was the first small cent produced by the US Mint.",
"Copper's antimicrobial properties have led hospitals to install copper door handles to reduce infection spread.",
"The Bronze Age (3300–1200 BC) was named after the copper-tin alloy that defined that era.",
"A pre-1982 penny contains about 2.95 grams of copper worth more than its 1-cent face value.",
"The 1955 Doubled Die Cent is worth thousands — caused by a misaligned hub during the minting process.",
"Copper is 100% recyclable without any loss of quality — about 80% of all copper ever mined is still in use.",
"The wheat penny (1909–1958) is one of the most collected US coin series ever produced.",
"Chilean copper mining giant Codelco is the world's largest copper producer.",
"The Indian Head Cent was designed by James Barton Longacre — the chief engraver of the US Mint.",
"Romans used copper coins called 'as' as their primary small denomination currency.",
"Zinc prices heavily influence the modern penny's cost since they make up 97.5% of its composition.",
"Copper shortages during WWII also led to the brief use of plastic pennies in experimental test strikes.",
"The Shield Nickel (1866–1883) was the first US five-cent piece made of copper-nickel alloy.",
"Copper futures trade on the COMEX exchange under the symbol HG (High Grade copper).",
"China consumes about 50% of the world's annual copper production.",
"The US Mint struck over 8 billion pennies in 2023 — more than any other coin denomination.",
"Hoarding pre-1982 pennies for their copper content is technically legal in the US as long as you don't export them in bulk."
];
const NUMIS_FACTS=[
"The word 'numismatics' comes from the Greek 'nomisma,' meaning coin.",
"The 1913 Liberty Head Nickel is one of the rarest US coins — only 5 are known to exist.",
"The Professional Coin Grading Service (PCGS) was founded in 1986 and has graded over 45 million coins.",
"A coin graded MS-70 is considered perfect with no post-production imperfections under 5x magnification.",
"The Sheldon scale (1–70) used to grade coins was created by Dr. William Sheldon in 1949.",
"The 1804 Silver Dollar is known as the 'King of American Coins' — only 15 known examples exist.",
"The American Numismatic Association (ANA) was founded in 1891 and has over 25,000 members.",
"Key date coins are those with the lowest mintage in a series — they command the highest premiums.",
"A coin's luster refers to the cartwheel-like reflective flow lines created during the minting process.",
"Toning on silver coins can be desirable — original natural toning often adds to a coin's value.",
"The Numismatic Guaranty Corporation (NGC) was founded in 1987 and is PCGS's main competitor.",
"Proof coins are struck at least twice with specially polished dies to create mirror-like fields.",
"The most expensive coin ever sold was the 1933 Saint-Gaudens Double Eagle — \$18.9 million in 2021.",
"Error coins result from mistakes in the minting process — doubled dies, off-centers, and broadstrikes.",
"CAC (Certified Acceptance Corporation) stickers indicate a coin grades solidly for its assigned grade.",
"Mintmarks identify which facility struck a coin — P (Philadelphia), D (Denver), S (San Francisco), O (New Orleans).",
"The term 'slider' refers to a coin that's been circulated but looks close to uncirculated.",
"Strike refers to the sharpness of detail on a coin — a full strike means all design elements are sharp.",
"Bag marks are small nicks from coins contacting each other in mint bags — common on large silver dollars.",
"Eye appeal is a subjective but important factor — a coin with great eye appeal often brings a premium.",
"The 1916-D Mercury Dime had a mintage of only 264,000 — making it one of the rarest 20th century dimes.",
"Ancient coins from Greece and Rome can often be purchased for under \$100 — making them accessible to new collectors.",
"The Flying Eagle Cent pattern coins struck in 1856 were used to lobby Congress to approve the new small cent design.",
"A coin's obverse is the front (usually with a portrait), and the reverse is the back.",
"The edge of a coin is called the third side — reeding (ridges) was added to detect coin clipping.",
"The Barber coinage series was so unpopular that very few were saved in high grades — making MS examples very rare.",
"Coin albums and folders should be acid-free to prevent chemical damage to stored coins.",
"The greysheet (CDN) provides wholesale bid prices used by dealers — retail is typically 10–30% above.",
"Cleaning a coin — even lightly — almost always permanently damages its surface and reduces its value.",
"A type set is a collection containing one example of each major design type rather than every date and mintmark."
];
const FX_FACTS=[
"The US Dollar has been the world's primary reserve currency since the Bretton Woods Agreement in 1944.",
"The Zimbabwean dollar experienced hyperinflation so severe that a \$100 trillion note was issued in 2009.",
"The British Pound Sterling is the oldest currency still in use today — dating back to 775 AD.",
"The Euro was introduced as a virtual currency in 1999 and as physical coins and notes in 2002.",
"Switzerland's Swiss Franc is considered one of the world's most stable currencies.",
"The term 'dollar' traces back to the Bohemian 'thaler' coin first minted in 1518.",
"Currency exchange rates fluctuate 24 hours a day, 5 days a week across global forex markets.",
"The daily forex market trades over \$7.5 trillion — the largest financial market on Earth.",
"Gold was the backbone of the international monetary system until Nixon ended convertibility in 1971.",
"The strongest currency by face value is the Kuwaiti Dinar — 1 KWD ≈ \$3.25 USD.",
"In 1923 Germany, hyperinflation was so bad that workers were paid twice a day so they could spend wages before prices rose.",
"The US Dollar is used in about 88% of all currency transactions globally.",
"Currency pegging ties one country's exchange rate to another — many Middle Eastern countries peg to the USD.",
"The Yuan/Renminbi is China's official currency — 'renminbi' means 'people's currency.'",
"Dollarization is when a country abandons its own currency and adopts the US Dollar — Ecuador did this in 2000.",
"The Japanese Yen is one of the most traded currencies in the world, despite Japan's relatively small economy.",
"The Euro is used by 20 of the 27 EU member states.",
"The first paper money was used in Tang Dynasty China around the 7th century AD.",
"Purchasing Power Parity (PPP) compares currencies based on the cost of a basket of goods.",
"The Big Mac Index, created by The Economist in 1986, uses burger prices to measure currency valuation.",
"Currency carries color — the US \$100 bill is green; the British £50 note is red; the EU €500 was purple.",
"The Mexican Peso was the world's most widely traded currency in the 18th and 19th centuries.",
"When a currency depreciates, exports become cheaper and more competitive on the global market.",
"The Canadian Dollar is informally called the 'Loonie' because of the loon bird on the \$1 coin.",
"Australian Dollar notes are made of polymer plastic — more durable and harder to counterfeit than paper.",
"Currency futures allow traders to lock in an exchange rate for a future date.",
"The Russian Ruble lost 50% of its value in late 2014 due to falling oil prices and sanctions.",
"The Turkish Lira redenominated in 2005, removing six zeros — 1,000,000 old lira became 1 new lira.",
"The US \$2 bill is still being produced but is rarely seen in circulation — many people think it's rare.",
"In 2022, the US Dollar Index hit a 20-year high as the Fed aggressively raised interest rates."
];
const COLLECT_FACTS=[
"The US Mint has been continuously operating since 1792 — making it one of the oldest government agencies.",
"Coin collecting is one of the oldest hobbies in the world — Roman emperors collected ancient Greek coins.",
"The American Numismatic Association hosts the World's Fair of Money — the largest coin show in the US.",
"A complete set of Lincoln cents from 1909–present contains over 100 coins.",
"The most popular modern US coin series to collect is the 50 State Quarters program (1999–2008).",
"Proof sets have been sold by the US Mint to collectors every year since 1936.",
"The Presidential Dollar series (2007–2016) featured all US presidents in order of service.",
"First Spouse Gold Coins were issued alongside Presidential Dollars, featuring the First Ladies.",
"The American Silver Eagle, first minted in 1986, is the best-selling silver bullion coin in the world.",
"The American Gold Eagle comes in four sizes: 1/10 oz, 1/4 oz, 1/2 oz, and 1 oz.",
"The US Mint at West Point produces most of the nation's bullion and commemorative gold and silver coins.",
"The National Coin Week is celebrated each April — sponsored by the ANA since 1924.",
"World coins can be collected for far less than US coins — ancient Roman coins start under \$20.",
"The Hawaii Five-O quarters from the America the Beautiful series are some of the most sought-after modern quarters.",
"A complete set of Morgan Dollars by date and mintmark requires over 100 coins.",
"The first commemorative US coin was the Columbian Exposition Half Dollar of 1892.",
"The US Mint's S-Mint proof coins are highly sought after by collectors for their mirrored surfaces.",
"Type collecting focuses on one coin per design type rather than every date — a popular approach for beginners.",
"The Numismatic Coin Bulletin (NCB) and Coin World are two of the oldest publications in the hobby.",
"Coins stored in 2x2 cardboard holders (flips) should be Mylar-lined to prevent PVC damage.",
"The Denver Mint has operated since 1906 and is one of the highest-output mints in the world.",
"The San Francisco Mint earned the nickname 'Granite Lady' for its imposing stone building.",
"The New Orleans Mint struck coins from 1838–1909 — O-mint coins are popular with collectors.",
"The Carson City Mint (1870–1893) produced some of the most iconic and valuable coins in US history.",
"The West Point Bullion Depository held \$100 billion in gold before becoming a mint in 1988.",
"The US Mint produces over 14 billion coins per year for general circulation.",
"Coin albums are a popular storage and display option — Dansco and Whitman are the most respected brands.",
"The 2009 Lincoln cents featured four reverse designs commemorating Lincoln's bicentennial.",
"The Smithsonian National Numismatic Collection holds over 1.6 million coins and is the world's largest.",
"Numismatic literature — books, price guides, auction records — is considered an important part of the hobby."
];
function getDailyFact(arr){
  const day=Math.floor(Date.now()/86400000);
  return arr[day%arr.length];
}
function injectDailyFacts(){
  const map=[
    ['gold-daily-fact',GOLD_FACTS],
    ['silver-daily-fact',SILVER_FACTS],
    ['const-daily-fact',CONST_FACTS],
    ['copper-daily-fact',COPPER_FACTS],
    ['numis-daily-fact',NUMIS_FACTS],
    ['fx-daily-fact',FX_FACTS],
    ['collect-daily-fact',COLLECT_FACTS]
  ];
  map.forEach(([id,arr])=>{
    const el=document.getElementById(id);
    if(el)el.textContent=getDailyFact(arr);
  });
}

injectDailyFacts();
