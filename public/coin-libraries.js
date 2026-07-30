/* Silver & Platinum Coin Libraries */
var SILVER_COINS=[
  {name:'American Silver Eagle 1 oz',country:'USA',asw:1.0,series:'Silver Eagle'},
  {name:'Canadian Silver Maple Leaf 1 oz',country:'Canada',asw:1.0,series:'Maple Leaf'},
  {name:'Austrian Silver Philharmonic 1 oz',country:'Austria',asw:1.0,series:'Philharmonic'},
  {name:'British Silver Britannia 1 oz',country:'UK',asw:1.0,series:'Britannia'},
  {name:'Australian Silver Kangaroo 1 oz',country:'Australia',asw:1.0,series:'Kangaroo'},
  {name:'Mexican Silver Libertad 1 oz',country:'Mexico',asw:1.0,series:'Libertad'},
  {name:'South African Silver Krugerrand 1 oz',country:'S. Africa',asw:1.0,series:'Krugerrand'},
  {name:'Chinese Silver Panda 1 oz',country:'China',asw:1.0,series:'Panda'},
  {name:'American Silver Eagle 1/2 oz',country:'USA',asw:0.5,series:'Silver Eagle'},
  {name:'Morgan Silver Dollar (BU)',country:'USA',asw:0.7734,series:'Morgan'},
  {name:'Peace Silver Dollar (BU)',country:'USA',asw:0.7734,series:'Peace'},
  {name:'Walking Liberty Half (BU)',country:'USA',asw:0.3617,series:'Walking Liberty'},
  {name:'Franklin Half Dollar (BU)',country:'USA',asw:0.3617,series:'Franklin'},
  {name:'Kennedy Half 1964 (90%)',country:'USA',asw:0.3617,series:'Kennedy'},
  {name:'Kennedy Half 1965-70 (40%)',country:'USA',asw:0.1479,series:'Kennedy 40%'},
  {name:'War Nickel 1942-45 (35%)',country:'USA',asw:0.0563,series:'War Nickel'},
  {name:'Washington Quarter 1932-64',country:'USA',asw:0.1808,series:'Washington'},
  {name:'Mercury Dime 1916-45',country:'USA',asw:0.0723,series:'Mercury'},
  {name:'Roosevelt Dime 1946-64',country:'USA',asw:0.0723,series:'Roosevelt'},
  {name:'100 oz Silver Bar (.999)',country:'USA',asw:100.0,series:'Bullion Bar'},
  {name:'10 oz Silver Bar (.999)',country:'USA',asw:10.0,series:'Bullion Bar'},
  {name:'1 Kilo Silver Bar (.999)',country:'USA',asw:32.15,series:'Bullion Bar'}
];

var SILVER_COIN_IMG={
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
  var ag=spot.XAG||0;
  var spotEl=document.getElementById('scl-spot');
  if(spotEl) spotEl.textContent=ag?'$'+ag.toFixed(2)+'/oz':'—';
  var pctEl=document.getElementById('scl-buy-pct');
  var buyPct=pctEl?(parseFloat(pctEl.value)||85):85;
  var grid=document.getElementById('scl-grid');
  if(!grid) return;
  grid.innerHTML='';
  SILVER_COINS.forEach(function(coin){
    var melt=ag*coin.asw;
    var buy=melt*(buyPct/100);
    var card=document.createElement('div');
    card.style.cssText='background:#0d1117;border:1px solid rgba(148,163,184,0.2);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    var imgSrc=SILVER_COIN_IMG[coin.series]||'';
    card.innerHTML='<div style="display:flex;gap:12px;align-items:center">'+
      (imgSrc?'<img src="'+imgSrc+'" alt="" style="width:64px;height:64px;object-fit:contain;border-radius:50%;border:2px solid rgba(148,163,184,0.35);background:#111;flex-shrink:0" onerror="this.style.display=\'none\'">':'<div style="width:64px;height:64px;border-radius:50%;border:2px solid rgba(148,163,184,0.3);background:rgba(148,163,184,0.08);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:24px">🪙</div>')+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:#c0d4e8;line-height:1.3;margin-bottom:2px">'+coin.name+'</div>'+
        '<div style="font-size:10px;color:var(--muted)">'+coin.country+'</div>'+
        '<div style="font-size:10px;color:var(--muted);margin-top:3px">ASW: <span style="color:var(--text2);font-weight:600">'+coin.asw.toFixed(4)+' troy oz</span></div>'+
      '</div>'+
    '</div>'+
    '<div style="display:flex;gap:8px">'+
      '<div style="flex:1;background:rgba(148,163,184,0.06);border:1px solid rgba(148,163,184,0.15);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Melt Value</div>'+
        '<div style="font-size:16px;font-weight:800;color:#c0d4e8">'+(ag?'$'+melt.toFixed(2):'—')+'</div>'+
      '</div>'+
      '<div style="flex:1;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Buy @ '+buyPct+'%</div>'+
        '<div style="font-size:16px;font-weight:800;color:var(--green)">'+(ag?'$'+buy.toFixed(2):'—')+'</div>'+
      '</div>'+
    '</div>'+
    '<div style="font-size:10px;color:var(--muted)">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
}

/* Platinum & Palladium Coin Library */
var PLATINUM_COINS=[
  {name:'American Platinum Eagle 1 oz',country:'USA',apw:1.0,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/2 oz',country:'USA',apw:0.5,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/4 oz',country:'USA',apw:0.25,series:'Platinum Eagle'},
  {name:'American Platinum Eagle 1/10 oz',country:'USA',apw:0.1,series:'Platinum Eagle'},
  {name:'Canadian Platinum Maple Leaf 1 oz',country:'Canada',apw:1.0,series:'Platinum Maple'},
  {name:'Australian Platinum Platypus 1 oz',country:'Australia',apw:1.0,series:'Platypus'},
  {name:'British Platinum Britannia 1 oz',country:'UK',apw:1.0,series:'Platinum Britannia'},
  {name:'Austrian Platinum Philharmonic 1 oz',country:'Austria',apw:1.0,series:'Platinum Philharmonic'},
  {name:'1 oz Platinum Bar (.9995)',country:'Various',apw:1.0,series:'Bullion Bar'}
];

var PALLADIUM_COINS=[
  {name:'American Palladium Eagle 1 oz',country:'USA',apw:1.0,series:'Palladium Eagle'},
  {name:'Canadian Palladium Maple Leaf 1 oz',country:'Canada',apw:1.0,series:'Palladium Maple'},
  {name:'Russian Palladium Ballerina 1 oz',country:'Russia',apw:1.0,series:'Ballerina'},
  {name:'1 oz Palladium Bar (.9995)',country:'Various',apw:1.0,series:'Bullion Bar'}
];

function renderPlatinumCoins(){
  var pt=spot.XPT||0;
  var pd=spot.XPD||0;
  var pctEl=document.getElementById('ptl-buy-pct');
  var buyPct=pctEl?(parseFloat(pctEl.value)||85):85;
  var grid=document.getElementById('ptl-grid');
  if(!grid) return;
  grid.innerHTML='';
  // Platinum section
  var hdr1=document.createElement('div');
  hdr1.style.cssText='grid-column:1/-1;font-size:13px;font-weight:700;color:var(--cyan);padding:8px 0 4px;border-bottom:1px solid rgba(34,211,238,.1);margin-bottom:4px';
  hdr1.textContent='⚗️ Platinum Coins & Bars';
  grid.appendChild(hdr1);
  PLATINUM_COINS.forEach(function(coin){
    var melt=pt*coin.apw;
    var buy=melt*(buyPct/100);
    var card=document.createElement('div');
    card.style.cssText='background:#0d1117;border:1px solid rgba(34,211,238,.12);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    card.innerHTML='<div style="display:flex;gap:12px;align-items:center">'+
      '<div style="width:64px;height:64px;border-radius:50%;border:2px solid rgba(34,211,238,.3);background:rgba(34,211,238,.08);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:26px">⚗️</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:var(--cyan);line-height:1.3;margin-bottom:2px">'+coin.name+'</div>'+
        '<div style="font-size:10px;color:var(--muted)">'+coin.country+'</div>'+
        '<div style="font-size:10px;color:var(--muted);margin-top:3px">APW: <span style="color:var(--text2);font-weight:600">'+coin.apw.toFixed(4)+' troy oz</span></div>'+
      '</div>'+
    '</div>'+
    '<div style="display:flex;gap:8px">'+
      '<div style="flex:1;background:rgba(34,211,238,.05);border:1px solid rgba(34,211,238,.12);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Melt Value</div>'+
        '<div style="font-size:16px;font-weight:800;color:var(--cyan)">'+(pt?'$'+melt.toFixed(2):'—')+'</div>'+
      '</div>'+
      '<div style="flex:1;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Buy @ '+buyPct+'%</div>'+
        '<div style="font-size:16px;font-weight:800;color:var(--green)">'+(pt?'$'+buy.toFixed(2):'—')+'</div>'+
      '</div>'+
    '</div>'+
    '<div style="font-size:10px;color:var(--muted)">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
  // Palladium section
  var hdr2=document.createElement('div');
  hdr2.style.cssText='grid-column:1/-1;font-size:13px;font-weight:700;color:var(--violet);padding:12px 0 4px;border-bottom:1px solid rgba(167,139,250,.1);margin-bottom:4px';
  hdr2.textContent='⚛️ Palladium Coins & Bars';
  grid.appendChild(hdr2);
  PALLADIUM_COINS.forEach(function(coin){
    var melt=pd*coin.apw;
    var buy=melt*(buyPct/100);
    var card=document.createElement('div');
    card.style.cssText='background:#0d1117;border:1px solid rgba(167,139,250,.12);border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:8px';
    card.innerHTML='<div style="display:flex;gap:12px;align-items:center">'+
      '<div style="width:64px;height:64px;border-radius:50%;border:2px solid rgba(167,139,250,.3);background:rgba(167,139,250,.08);flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:26px">⚛️</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:var(--violet);line-height:1.3;margin-bottom:2px">'+coin.name+'</div>'+
        '<div style="font-size:10px;color:var(--muted)">'+coin.country+'</div>'+
        '<div style="font-size:10px;color:var(--muted);margin-top:3px">APW: <span style="color:var(--text2);font-weight:600">'+coin.apw.toFixed(4)+' troy oz</span></div>'+
      '</div>'+
    '</div>'+
    '<div style="display:flex;gap:8px">'+
      '<div style="flex:1;background:rgba(167,139,250,.05);border:1px solid rgba(167,139,250,.12);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Melt Value</div>'+
        '<div style="font-size:16px;font-weight:800;color:var(--violet)">'+(pd?'$'+melt.toFixed(2):'—')+'</div>'+
      '</div>'+
      '<div style="flex:1;background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.15);border-radius:8px;padding:8px;text-align:center">'+
        '<div style="font-size:10px;color:var(--muted);margin-bottom:2px">Buy @ '+buyPct+'%</div>'+
        '<div style="font-size:16px;font-weight:800;color:var(--green)">'+(pd?'$'+buy.toFixed(2):'—')+'</div>'+
      '</div>'+
    '</div>'+
    '<div style="font-size:10px;color:var(--muted)">Series: '+coin.series+'</div>';
    grid.appendChild(card);
  });
}
