/* Ambient dashboard for /living-room. All external data is fetched server-side. */
(function () {
  'use strict';
  var TZ = 'Africa/Dar_es_Salaam';
  var CITY_CLOCKS = [
    ['Dar es Salaam','Africa/Dar_es_Salaam'],['Arusha','Africa/Dar_es_Salaam'],
    ['Mwanza','Africa/Dar_es_Salaam'],['Nairobi','Africa/Nairobi'],
    ['Mombasa','Africa/Nairobi'],['Kampala','Africa/Kampala'],
    ['Kigali','Africa/Kigali'],['Addis Ababa','Africa/Addis_Ababa'],
    ['London','Europe/London'],['Paris','Europe/Paris'],['Berlin','Europe/Berlin']
  ];
  var CURRENCY_NAMES = {
    TZS:'Tanzanian shilling',KES:'Kenyan shilling',UGX:'Ugandan shilling',
    RWF:'Rwandan franc',BIF:'Burundian franc',ETB:'Ethiopian birr',
    SSP:'South Sudanese pound',SOS:'Somali shilling',EUR:'Euro',
    GBP:'British pound',CHF:'Swiss franc'
  };
  var WEATHER_ICONS = {
    0:'☀',1:'🌤',2:'⛅',3:'☁',45:'🌫',48:'🌫',51:'🌦',53:'🌦',55:'🌧',
    56:'🌧',57:'🌧',61:'🌦',63:'🌧',65:'🌧',66:'🌧',67:'🌧',71:'❄',
    73:'❄',75:'❄',77:'❄',80:'🌦',81:'🌧',82:'🌧',85:'🌨',86:'🌨',
    95:'⛈',96:'⛈',99:'⛈'
  };
  function node(tag, cls, parent, value) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (value !== undefined && value !== null) el.textContent = String(value);
    if (parent) parent.appendChild(el);
    return el;
  }
  function formatTime(zone, seconds) {
    try {
      return new Intl.DateTimeFormat('en-GB', {
        timeZone:zone,hour:'2-digit',minute:'2-digit',
        ...(seconds ? {second:'2-digit'} : {})
      }).format(new Date());
    } catch (_) { return '--:--'; }
  }
  function formatDate(zone) {
    try { return new Intl.DateTimeFormat('en-GB',{timeZone:zone,weekday:'long',day:'numeric',month:'long',year:'numeric'}).format(new Date()); }
    catch (_) { return ''; }
  }
  function fmt(value, digits) {
    var n = Number(value);
    return Number.isFinite(n) ? n.toFixed(digits === undefined ? 0 : digits) : '—';
  }
  function elLabel(parent, text) { return node('div','amb-label',parent,text); }
  function buildClock(parent) {
    var shell = node('div','amb-clock-shell',parent);
    var face = node('div','amb-dial',shell);
    for (var i=0;i<60;i++) {
      var mark = node('span',i%5===0?'amb-mark amb-hour-mark':'amb-mark',face);
      mark.style.transform = 'translateX(-50%) rotate('+(i*6)+'deg)';
    }
    var hour = node('i','amb-hand amb-hour',face);
    var minute = node('i','amb-hand amb-minute',face);
    var second = node('i','amb-hand amb-second',face);
    node('i','amb-clock-pin',face);
    function tick() {
      var now = new Date();
      var parts = new Intl.DateTimeFormat('en-GB',{
        timeZone:TZ,hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'
      }).formatToParts(now);
      var p = {}; parts.forEach(function(x){p[x.type]=Number(x.value);});
      var h=(p.hour%12)+(p.minute/60),m=p.minute+(p.second/60),s=p.second;
      hour.style.transform='translateX(-50%) rotate('+(h*30)+'deg)';
      minute.style.transform='translateX(-50%) rotate('+(m*6)+'deg)';
      second.style.transform='translateX(-50%) rotate('+(s*6)+'deg)';
      digital.textContent = formatTime(TZ,true);
      date.textContent = formatDate(TZ);
    }
    var digital = node('div','amb-digital',parent,'--:--:--');
    var date = node('div','amb-date',parent,'');
    tick();
    return {tick:tick};
  }
  function renderWeather(host, rows) {
    host.replaceChildren();
    (rows || []).forEach(function(row) {
      var item=node('div','amb-weather-item',host);
      var icon=node('span','amb-weather-icon',item,WEATHER_ICONS[row.weather_code]||'◌');
      icon.setAttribute('aria-hidden','true');
      var details=node('div','amb-weather-details',item);
      node('strong','',details,row.name||'Unknown');
      node('small','',details,(row.condition||'Weather unavailable')+(row.humidity_percent!==null&&row.humidity_percent!==undefined?' · '+fmt(row.humidity_percent)+'% humidity':''));
      node('b','amb-temp',item,row.temperature_c===null||row.temperature_c===undefined?'—':fmt(row.temperature_c)+'°');
    });
    if (!rows || !rows.length) node('div','amb-empty',host,'Weather data unavailable');
  }
  function renderCurrencies(host, fx) {
    host.replaceChildren();
    var rates=fx&&fx.rates||[];
    rates.forEach(function(row) {
      var item=node('div','amb-fx-item',host);
      node('b','amb-fx-code',item,row.code);
      node('span','amb-fx-value',item,row.per_usd===null||row.per_usd===undefined?'—':Number(row.per_usd).toLocaleString('en-US',{maximumFractionDigits:4}));
    });
    if(!rates.length) node('div','amb-empty',host,'Exchange rates unavailable');
  }
  function renderNews(host, rows) {
    host.replaceChildren();
    (rows||[]).slice(0,6).forEach(function(row) {
      var item=node('a','amb-news-item',host);
      item.href=row.url;
      item.target='_blank';
      item.rel='noopener noreferrer';
      node('small','',item,row.source||'Technology');
      node('strong','',item,row.title||'Headline unavailable');
      if(row.timestamp) node('time','',item,new Date(row.timestamp*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}));
    });
    if(!rows||!rows.length) node('div','amb-empty',host,'Technology headlines unavailable');
  }
  function build(parent, options) {
    options=options||{};
    var root=node('main','ambient-board',parent);
    root.setAttribute('aria-label','Ambient dashboard');
    var top=node('div','amb-top-grid',root);
    var weatherPanel=node('section','amb-panel amb-weather-panel',top);
    elLabel(weatherPanel,'WEATHER · EAST AFRICA');
    var locationCard=node('div','amb-location-card',weatherPanel);
    node('div','amb-sub-label',locationCard,'YOUR NETWORK LOCATION');
    var locationName=node('strong','amb-location-name',locationCard,'Checking router…');
    var locationSource=node('div','amb-location-source',locationCard,'ZLT X17U · LTE cell estimate, then router WAN IP');
    var localWeather=node('div','amb-local-weather',locationCard,'Waiting for location');
    var cityWeather=node('div','amb-city-weather',weatherPanel);
    node('div','amb-sub-label',cityWeather,'REGIONAL CONDITIONS');
    var weatherList=node('div','amb-weather-list',cityWeather);

    var centre=node('section','amb-centre',top);
    var centreHeader=node('div','amb-centre-header',centre);
    node('div','amb-kicker',centreHeader,'SBC CONTROL CENTER');
    node('div','amb-live-dot',centreHeader,'LIVE');
    var greet=node('div','amb-greeting',centre,'HEY, GOOD EVENING');
    var clock=buildClock(centre);
    var quoteBox=node('figure','amb-quote',centre);
    var quote=node('blockquote','',quoteBox,'');
    var quoteAuthor=node('figcaption','',quoteBox,'');
    var quoteRows=(window.SBC_QUOTES||[]).filter(function(q){return q&&q.q;});
    var shown=-1;
    function quoteTick(){
      if(!quoteRows.length)return;
      var slot=Math.floor(Date.now()/45000)%quoteRows.length;
      if(slot===shown)return;shown=slot;
      var item=quoteRows[slot];
      quote.textContent=item.o?item.q:'“'+item.q+'”';
      quoteAuthor.textContent=item.a||'';
      quoteBox.classList.remove('amb-fade');
    }
    quoteTick();

    var worldPanel=node('section','amb-panel amb-world-panel',top);
    elLabel(worldPanel,'WORLD CLOCKS');
    var clocks=node('div','amb-world-clocks',worldPanel);
    var clockRows=[];
    CITY_CLOCKS.forEach(function(row){
      var item=node('div','amb-world-row',clocks);
      node('span','amb-world-name',item,row[0]);
      var value=node('time','amb-world-time',item,'--:--');
      clockRows.push({node:value,zone:row[1]});
    });

    var bottom=node('div','amb-bottom-grid',root);
    var fxPanel=node('section','amb-panel amb-fx-panel',bottom);
    var fxHead=node('div','amb-panel-head',fxPanel);
    elLabel(fxHead,'CURRENCY SNAPSHOT');
    node('span','amb-base-label',fxHead,'USD BASE');
    var fxRows=node('div','amb-fx-list',fxPanel);
    var newsPanel=node('section','amb-panel amb-news-panel',bottom);
    var newsHead=node('div','amb-panel-head',newsPanel);
    elLabel(newsHead,'TECHNOLOGY BRIEFING');
    node('span','amb-base-label',newsHead,'LATEST HEADLINES');
    var newsRows=node('div','amb-news-list',newsPanel);
    var footer=node('div','amb-footer',root);
    node('span','',footer,'Weather: Open-Meteo · FX: ExchangeRate-API · Cell data: OpenCelliD');
    var updated=node('span','',footer,'Waiting for live data');

    function clockTick() {
      clock.tick();
      clockRows.forEach(function(row){row.node.textContent=formatTime(row.zone,false);});
      var hr=Number(new Intl.DateTimeFormat('en-GB',{timeZone:TZ,hour:'2-digit',hourCycle:'h23'}).format(new Date()));
      var greeting=hr<5?'HEY, GOOD NIGHT':hr<12?'HEY, GOOD MORNING':hr<17?'HEY, GOOD AFTERNOON':'HEY, GOOD EVENING';
      greet.textContent=greeting;
      quoteTick();
    }
    clockTick();
    var timer=setInterval(clockTick,1000);

    function render(data) {
      var loc=data.location||{};
      locationName.textContent=loc.label||'Location unavailable';
      locationSource.textContent=(loc.source||'Location resolver')+' · '+(loc.message||'');
      locationCard.dataset.confidence=loc.confidence||'none';
      var local=(data.local_weather||[])[0];
      localWeather.replaceChildren();
      if(local){
        node('span','amb-local-condition',localWeather,(WEATHER_ICONS[local.weather_code]||'◌')+'  '+(local.condition||'Conditions'));
        node('strong','amb-local-temp',localWeather,fmt(local.temperature_c)+'°C');
        node('small','',localWeather,'Local estimate · '+(loc.confidence==='cell'?'cell area':'network area'));
      } else node('small','amb-awaiting',localWeather,'Your-area weather appears when the router location is resolved.');
      renderWeather(weatherList,data.city_weather||[]);
      renderCurrencies(fxRows,data.fx||{});
      renderNews(newsRows,data.news||[]);
      updated.textContent='Updated '+new Date((data.generated_at||Date.now()/1000)*1000).toLocaleTimeString();
    }
    var stopped=false,busy=false;
    function refresh() {
      if(stopped||busy||document.visibilityState==='hidden')return;
      busy=true;
      fetch('/api/ambient',{cache:'no-store',credentials:'same-origin'})
        .then(function(response){if(!response.ok)throw new Error('Ambient feed unavailable');return response.json();})
        .then(render)
        .catch(function(){locationSource.textContent='Live feeds temporarily unavailable · retrying automatically';})
        .finally(function(){busy=false;});
    }
    refresh();
    var refreshTimer=setInterval(refresh,180000);
    document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible')refresh();});
    return {stop:function(){stopped=true;clearInterval(timer);clearInterval(refreshTimer);if(root.parentNode)root.parentNode.removeChild(root);}};
  }
  window.SbcAmbientDashboard={mount:build};
})();
