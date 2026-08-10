const menuButton=document.querySelector('.menu-button');
const nav=document.querySelector('.main-nav');
menuButton?.addEventListener('click',()=>{const open=menuButton.getAttribute('aria-expanded')==='true';menuButton.setAttribute('aria-expanded',String(!open));nav.classList.toggle('open',!open)});
nav?.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{menuButton.setAttribute('aria-expanded','false');nav.classList.remove('open')}));
document.getElementById('year').textContent=new Date().getFullYear();

const symbols=['XAU','XAG','XPT','XPD'];
const money=new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',minimumFractionDigits:2,maximumFractionDigits:2});
async function loadMarkets(){
  await Promise.all(symbols.map(async symbol=>{
    const priceNode=document.getElementById(`price-${symbol}`),changeNode=document.getElementById(`change-${symbol}`);
    try{
      const response=await fetch(`/api/metals/${symbol}`);
      if(!response.ok)throw new Error('Market unavailable');
      const data=await response.json(),change=Number(data.ch||0),pct=data.prev_close_price?change/Number(data.prev_close_price)*100:0;
      priceNode.textContent=money.format(Number(data.price));
      if(symbol==='XAU'){const preview=document.getElementById('preview-gold');if(preview)preview.textContent=money.format(Number(data.price))}
      if(symbol==='XAG'){const preview=document.getElementById('preview-silver');if(preview)preview.textContent=money.format(Number(data.price))}
      changeNode.textContent=`${change>=0?'▲':'▼'} ${change>=0?'+':''}${money.format(change).replace('$','')} (${pct>=0?'+':''}${pct.toFixed(2)}%)`;
      changeNode.className=change>=0?'up':'down';
    }catch(error){priceNode.textContent='Unavailable';changeNode.textContent='Try again shortly';changeNode.className='muted'}
  }));
  document.getElementById('market-time').textContent=`Updated ${new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'})}`;
}
loadMarkets();setInterval(loadMarkets,300000);

const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}}),{threshold:.12});
document.querySelectorAll('.tool-card,.section-intro,.why-copy,.quote-card').forEach(el=>observer.observe(el));
