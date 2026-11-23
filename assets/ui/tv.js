/* HomeTube, the TV page: remote-control navigation, search, subscriptions, channels, and a player with
 * transport controls, full screen or windowed, Up next, previous/next, quality, speed, subtitles,
 * chapters, resume and history. Everything personal (subscriptions, history, Watch Later) is kept
 * on the board, not with Google. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var BACK = [8, 27, 461, 10009, 166];          // Backspace, Escape and the TV remotes' Back keys
  var PLAYPAUSE = [179, 415, 19, 463, 10252];   // media play/pause, play, pause
  var FFWD = [417, 228], REWIND = [412, 227];
  var NEXTV = [425, 176, 427], PREVV = [424, 177, 428];   // track next/previous, channel up/down
  var DIRS = {37: 'left', 38: 'up', 39: 'right', 40: 'down'};
  var ICON = {play: 'M8 5v14l11-7z', pause: 'M6 19h4V5H6v14zm8-14v14h4V5h-4z',
              enter: 'M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z',
              exit: 'M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z'};
  var current = null, hls = null, dockTimer = null, saveTimer = null, warmTimer = null, upTimer = null;
  var subs = [], account = false, items = {}, warmed = {};
  var queue = [], qi = -1, queueName = '', played = [], related = [], full = true, homeScroll = 0, lastCard = null, opening = 0;

  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function dur(s) { if (!s && s !== 0) return ''; s = Math.round(s); var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + (m < 10 ? '0' : '') : '') + m + ':' + (x < 10 ? '0' : '') + x; }
  function api(path, body) {
    return fetch('/api/tv/' + path, body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})
      .then(function (r) { return r.json().then(function (d) { if (!r.ok || d.ok === false) throw new Error(d.error || ('error ' + r.status)); return d; }); });
  }
  function status(text) { $('status').textContent = text || ''; }
  function inPlayer() { return !$('player').hidden; }

  // ---- lists: home is rows you scroll sideways; search, history and Watch Later are a grid
  var TOPICS = [['Bongo Flava', 'bongo flava new songs'], ['Music', 'official music video'], ['Live now', 'live stream'],
                ['Chill', 'lofi hip hop'], ['Tech', 'tech review'], ['News', 'world news today'], ['Comedy', 'stand up comedy']];
  function card(v) {
    items[v.id] = v;
    var progress = v.position && v.duration ? '<i class="bar" style="width:' + Math.min(100, v.position / v.duration * 100).toFixed(0) + '%"></i>' : '';
    var badge = v.live ? '<span class="d live">LIVE</span>' : (v.duration ? '<span class="d">' + dur(v.duration) + '</span>' : '');
    return '<article class="tv-card" tabindex="0" data-nav data-id="' + esc(v.id) + '"><div class="thumb"><img loading="lazy" decoding="async" alt="" src="' + esc(v.thumb) + '">' +
      badge + progress + '</div><div class="meta"><div class="t">' + esc(v.title) + '</div><div class="c">' + esc(v.channel || '') + '</div></div></article>';
  }
  function skeleton(n) { var out = ''; for (var i = 0; i < n; i++) out += '<div class="tv-card tv-skel"><div class="thumb"></div></div>'; return out; }
  function tab(id) { ['homeBtn', 'recBtn', 'historyBtn', 'laterBtn'].forEach(function (b) { $(b).classList.toggle('on', b === id); }); }
  function focusFirst(scope) {
    var f = scope.querySelector('.tv-card[data-nav]');
    if (f && !inPlayer() && (document.activeElement === document.body || !document.activeElement)) focusCard(f);
  }
  function show(title, list, note) {
    $('rows').hidden = true; $('list').hidden = false;
    $('rowTitle').textContent = title;
    status(note || (list.length ? '' : 'Nothing here yet.'));
    $('grid').innerHTML = list.map(card).join('');
    window.scrollTo(0, 0);
    focusFirst($('grid'));
  }
  function row(title) {
    var sec = document.createElement('section'); sec.className = 'tv-row';
    sec.innerHTML = '<h2>' + esc(title) + '</h2><div class="tv-strip">' + skeleton(6) + '</div>';
    $('rows').appendChild(sec);
    return {fill: function (list) {
      if (!list.length) { sec.remove(); return; }
      sec.lastChild.innerHTML = list.map(card).join('');
      focusFirst($('rows'));
    }, drop: function () { sec.remove(); }};
  }
  function loadHome() {
    tab('homeBtn');
    $('list').hidden = true; $('rows').hidden = false; $('rows').innerHTML = '';
    status('');
    var cont = row('Continue watching');
    api('history').then(function (h) {
      var list = (h.items || []).filter(function (v) { return v.position && v.duration && v.position < v.duration - 30; }).slice(0, 12);
      cont.fill(list);
      list.slice(0, 2).forEach(function (v) { warm(v.id); });   // the likeliest picks get looked up now
    }).catch(cont.drop);
    var subsRow = row(account ? 'Your subscriptions' : 'Subscriptions');
    (account ? api('feed?name=subs') : api('home')).then(function (d) {
      if (d.subscriptions) subs = d.subscriptions;
      subsRow.fill(d.items || []);
    }).catch(subsRow.drop);
    TOPICS.forEach(function (t) {   // filled as each search returns (cached for an hour on the board)
      var r = row(t[0]);
      api('search?q=' + encodeURIComponent(t[1]) + '&topic=1').then(function (d) { r.fill((d.items || []).slice(0, 16)); }).catch(r.drop);
    });
  }
  function search(q) {
    if (!q.trim()) return;
    status('Searching…');
    tab(null);
    api('search?q=' + encodeURIComponent(q)).then(function (d) { show('Results for "' + q + '"', d.items); }).catch(function (e) { status(e.message); });
  }
  function openChannel(id, name) {
    status('Loading channel…');
    api('channel?id=' + encodeURIComponent(id)).then(function (d) { show(name || 'Channel', d.items); }).catch(function (e) { status(e.message); });
  }

  // a lookup takes 15 to 18 s on the board: start it while a card is focused, before OK is pressed
  function warm(id) {
    if (!id || warmed[id] && Date.now() - warmed[id] < 600000) return;
    warmed[id] = Date.now();
    api('warm?id=' + encodeURIComponent(id)).catch(function () {});
  }

  // ---- player
  function siblingsOf(el) {
    var box = el && el.parentNode;
    if (!box) return [];
    return Array.prototype.map.call(box.querySelectorAll('.tv-card[data-id]'), function (c) { return c.dataset.id; });
  }
  function openFromCard(el) {
    var ids = siblingsOf(el), row = el.closest('.tv-row');
    var name = row ? row.querySelector('h2').textContent : $('rowTitle').textContent;
    play(el.dataset.id, ids, ids.indexOf(el.dataset.id), name);
  }
  function play(id, list, index, name) {
    queue = list && list.length ? list : [id];
    qi = index >= 0 ? index : queue.indexOf(id);
    if (name !== undefined) queueName = name;
    if (!inPlayer()) {
      homeScroll = window.pageYOffset || 0;
      document.body.classList.add('playing');
      $('player').hidden = false;
      setFull(true);
    }
    if (current && current.id !== id) played.push(current.id);
    teardown();
    var seen = items[id] || {};
    current = {id: id, title: seen.title, channel: seen.channel};
    $('vTitle').textContent = seen.title || '';
    $('vChannel').textContent = seen.channel || '';
    spinner('Opening…');
    wake(true);
    $('playBtn').focus();
    renderQueue();
    showLower(queue.length > 1 ? 'queue' : 'next');
    loadRelated(id);
    var token = ++opening;
    // the resume point is read alongside the lookup, so the player starts loading right there
    var resumeAt = api('history').then(function (h) {
      var s = (h.items || []).filter(function (x) { return x.id === id; })[0];
      return s && s.position && (!s.duration || s.position < s.duration - 30) ? s.position : -1;
    }).catch(function () { return -1; });
    Promise.all([api('video?id=' + encodeURIComponent(id)), resumeAt]).then(function (both) {
      if (token !== opening) return;   // another video was chosen meanwhile
      var v = both[0], startAt = both[1];
      if (!v.hls) throw new Error('No playable stream for this video.');
      current = v; items[v.id] = v;
      $('vTitle').textContent = v.title || '';
      $('vChannel').textContent = (v.channel || '') + (v.live ? ' · LIVE' : '');
      $('subBtn').textContent = subs.some(function (s) { return s.id === v.channel_id; }) ? 'Unsubscribe' : 'Subscribe';
      $('laterAdd').textContent = 'Watch Later';
      buildMenus(v);
      spinner('Loading video…');
      var video = $('video');
      if (window.Hls && window.Hls.isSupported()) {
        hls = new window.Hls({maxBufferLength: 30, startPosition: startAt});
        hls.loadSource(v.hls);
        hls.attachMedia(video);
        hls.on(window.Hls.Events.MANIFEST_PARSED, function () {
          fillQuality();
          // always the highest quality: lock to the top level (hls.js sorts levels by bitrate)
          var top = hls.levels.length - 1;
          if (top >= 0) { hls.currentLevel = top; $('qSel').value = String(top); }
          start();
        });
        hls.on(window.Hls.Events.ERROR, function (_e, data) { if (data.fatal) { spinner(null); status('Playback error: ' + data.details); $('spinText').textContent = ''; } });
      } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = v.hls;
        video.addEventListener('loadedmetadata', function () { if (startAt > 0) video.currentTime = startAt; start(); }, {once: true});
      } else { throw new Error('This browser cannot play HLS video.'); }
    }).catch(function (e) { if (token === opening) spinner(e.message, true); });
  }
  function start() {
    $('video').play().catch(function () {});
    clearInterval(saveTimer);
    saveTimer = setInterval(remember, 15000);
  }
  function remember() {
    var video = $('video');
    if (!current || !current.duration && !isFinite(video.duration) || !isFinite(video.currentTime) || !video.currentTime) return;
    api('history', {item: {id: current.id, title: current.title, channel: current.channel, channel_id: current.channel_id,
                           position: video.currentTime, duration: video.duration || current.duration}}).catch(function () {});
  }
  function teardown() {
    clearInterval(saveTimer); cancelUpNext();
    if (current && current.hls) remember();
    var video = $('video');
    video.pause();
    if (hls) { hls.destroy(); hls = null; }
    video.removeAttribute('src'); video.load();
    while (video.firstChild) video.removeChild(video.firstChild);
    setProgress(0, 0, 0);
  }
  function closePlayer() {
    teardown();
    opening++;
    var last = current;
    current = null; played = [];
    $('player').hidden = true;
    document.body.classList.remove('playing');
    window.scrollTo(0, homeScroll);
    var c = last && document.querySelector('#rows:not([hidden]) .tv-card[data-id="' + last.id + '"], #list:not([hidden]) .tv-card[data-id="' + last.id + '"]');
    focusCard(c || lastCard || $('q'));
  }
  function nextId() {
    if (qi + 1 < queue.length) return {id: queue[qi + 1], list: queue, index: qi + 1};
    if (related.length) return {id: related[0].id, list: related.map(function (r) { return r.id; }), index: 0, name: 'Suggested'};
    return null;
  }
  function next() { var n = nextId(); if (n) play(n.id, n.list, n.index, n.name); }
  function prev() {
    var video = $('video');
    if (video.currentTime > 15 || (!played.length && qi <= 0)) { video.currentTime = 0; return; }   // like YouTube: first back to the start
    if (played.length) {   // back through what was played, without adding the current video to that list
      var id = played.pop();
      remember(); current = null;
      play(id, queue, queue.indexOf(id)); return;
    }
    play(queue[qi - 1], queue, qi - 1);
  }
  function loadRelated(id) {
    related = [];
    $('relStrip').innerHTML = skeleton(6);
    api('related?id=' + encodeURIComponent(id)).then(function (d) {
      if (!current || current.id !== id) return;
      related = d.items || [];
      $('relStrip').innerHTML = related.length ? related.map(card).join('') : '<p class="tv-empty">Nothing suggested for this video.</p>';
    }).catch(function () {
      // no suggestions from YouTube: the rest of the list it was opened from
      related = queue.slice(qi + 1).map(function (q) { return items[q]; }).filter(Boolean);
      $('relStrip').innerHTML = related.length ? related.map(card).join('') : '';
    });
  }

  // ---- the queue: what was opened together (a row, a search, a mix or playlist), now-playing marked
  function renderQueue() {
    var has = queue.length > 1;
    $('tabQueue').hidden = !has;
    $('tabQueue').textContent = (queueName || 'Queue') + ' · ' + (qi + 1) + ' of ' + queue.length;
    if (!has) { $('queueStrip').innerHTML = ''; return; }
    $('queueStrip').innerHTML = queue.map(function (qid, i) {
      return card(items[qid] || {id: qid, title: '', thumb: '/assets/ui-background.png'}).replace('class="tv-card"', 'class="tv-card' + (i === qi ? ' now' : '') + '"');
    }).join('');
    revealNow();
  }
  function revealNow() {   // scroll the queue so the playing video is in view, without moving focus
    var now = $('queueStrip').querySelector('.tv-card.now'), strip = $('queueStrip');
    if (!now || strip.hidden) return;
    strip.scrollLeft = Math.max(0, now.offsetLeft - strip.offsetLeft - strip.clientWidth * 0.04);
  }
  function showLower(which) {
    if (which === 'queue' && $('tabQueue').hidden) which = 'next';
    $('queueStrip').hidden = which !== 'queue'; $('relStrip').hidden = which === 'queue';
    $('tabQueue').classList.toggle('on', which === 'queue'); $('tabNext').classList.toggle('on', which !== 'queue');
    if (which === 'queue') revealNow();
  }
  function lowerCards() { var s = $('queueStrip').hidden ? $('relStrip') : $('queueStrip'); return cardsIn(s); }
  function startMix() {
    if (!current) return;
    var id = current.id, label = $('mixBtn').lastChild;
    label.textContent = 'Loading mix…';
    api('playlist?list=RD' + encodeURIComponent(id) + '&v=' + encodeURIComponent(id)).then(function (d) {
      label.textContent = 'Mix';
      if (!current || current.id !== id) return;
      (d.items || []).forEach(function (v) { if (!items[v.id]) items[v.id] = v; });
      var ids = (d.items || []).map(function (v) { return v.id; });
      if (ids.indexOf(id) < 0) ids.unshift(id);
      queue = ids; qi = ids.indexOf(id); queueName = d.title || 'Mix';
      renderQueue(); showLower('queue');
      var now = $('queueStrip').querySelector('.tv-card.now');
      focusCard(now && now.nextElementSibling || now);
    }).catch(function (e) { label.textContent = 'Mix'; status(e.message); spinner(null); });
  }
  function playFromStrip(el) {
    if (el.parentNode === $('queueStrip')) { play(el.dataset.id, queue, cardsIn($('queueStrip')).indexOf(el)); return; }
    var ids = related.map(function (r) { return r.id; });
    play(el.dataset.id, ids, ids.indexOf(el.dataset.id), 'Suggested');
  }

  // ---- player chrome: spinner, progress, the dock (controls + Up next), full screen or windowed
  function spinner(text, isError) {
    $('spin').hidden = !text;
    $('spin').classList.toggle('err', !!isError);
    $('spinText').textContent = text || '';
  }
  function setProgress(pos, total, buffered) {
    $('tCur').textContent = dur(pos || 0); $('tDur').textContent = total ? dur(total) : (current && current.live ? 'LIVE' : '0:00');
    $('tPos').style.width = total ? Math.min(100, pos / total * 100).toFixed(2) + '%' : '0';
    $('tBuf').style.width = total ? Math.min(100, buffered / total * 100).toFixed(2) + '%' : '0';
  }
  function syncPlay() {
    var paused = $('video').paused;
    $('playIcon').setAttribute('d', paused ? ICON.play : ICON.pause);
    $('playLabel').textContent = paused ? 'Play' : 'Pause';
  }
  function dockShown() { return !$('dock').classList.contains('hide'); }
  function wake(keep) {
    $('dock').classList.remove('hide');
    clearTimeout(dockTimer);
    if (!full || keep) return;
    dockTimer = setTimeout(function () {
      var a = document.activeElement;
      if (full && !$('video').paused && !(a && a.closest && a.closest('.tv-related'))) { $('dock').classList.add('hide'); if (a) a.blur(); }
    }, 6000);
  }
  function hideDock() { if (full) { clearTimeout(dockTimer); $('dock').classList.add('hide'); if (document.activeElement) document.activeElement.blur(); } }
  function setFull(on) {
    full = on;
    $('player').classList.toggle('full', on); $('player').classList.toggle('windowed', !on);
    $('fsIcon').setAttribute('d', on ? ICON.exit : ICON.enter);
    $('fsLabel').textContent = on ? 'Exit full screen' : 'Full screen';
    try {   // the browser's own full screen too, where the TV allows it
      if (on && document.documentElement.requestFullscreen && !document.fullscreenElement) document.documentElement.requestFullscreen().catch(function () {});
      if (!on && document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(function () {});
    } catch (e) { /* not available */ }
    wake();
  }
  function togglePlay() { var v = $('video'); if (v.paused) v.play().catch(function () {}); else v.pause(); }
  function seek(by) {
    var v = $('video');
    if (!isFinite(v.duration) && !(current && current.live)) return;
    v.currentTime = Math.max(0, Math.min((v.duration || 1e9) - 1, v.currentTime + by));
  }
  function upNext() {
    var n = nextId();
    if (!n) { wake(true); return; }
    var left = 5;
    $('upnextTitle').textContent = (items[n.id] || {}).title || '';
    $('upnextSec').textContent = left;
    $('upnext').hidden = false;
    upTimer = setInterval(function () {
      left -= 1; $('upnextSec').textContent = left;
      if (left <= 0) { cancelUpNext(); play(n.id, n.list, n.index, n.name); }
    }, 1000);
  }
  function cancelUpNext() { clearInterval(upTimer); upTimer = null; $('upnext').hidden = true; }
  function buildMenus(v) {
    $('ccSel').innerHTML = '<option value="">Subtitles off</option>' + (v.subtitles || []).map(function (s, i) { return '<option value="' + i + '">' + esc(s.name) + '</option>'; }).join('');
    $('chapSel').innerHTML = '<option value="">Chapters</option>' + (v.chapters || []).map(function (c) { return '<option value="' + c.start + '">' + dur(c.start) + ' · ' + esc(c.title) + '</option>'; }).join('');
    $('chapSel').hidden = !(v.chapters || []).length;
    $('qSel').innerHTML = '<option value="-1">Auto quality</option>';
  }
  function fillQuality() {
    var levels = hls ? hls.levels : [];
    $('qSel').innerHTML = '<option value="-1">Auto quality</option>' + levels.map(function (l, i) { return '<option value="' + i + '">' + (l.height || '?') + 'p</option>'; }).join('');
  }
  function setCaptions(idx) {
    var video = $('video');
    while (video.firstChild) video.removeChild(video.firstChild);
    if (idx === '' || !current) return;
    var s = current.subtitles[+idx];
    var track = document.createElement('track');
    track.kind = 'subtitles'; track.srclang = s.lang; track.label = s.name; track.default = true;
    track.src = '/api/tv/captions?id=' + encodeURIComponent(current.id) + '&lang=' + encodeURIComponent(s.lang) + '&auto=' + (s.auto ? 1 : 0);
    video.appendChild(track);
    track.addEventListener('load', function () { track.track.mode = 'showing'; });
  }

  // ---- remote-control navigation. Rows: left/right walk the row, up/down jump rows keeping the
  // column. Only the few elements involved are measured, so a key press stays cheap on a TV.
  function cardsIn(box) { return Array.prototype.slice.call(box.querySelectorAll('.tv-card[data-id]')); }
  function focusCard(el) {
    if (!el) return;
    el.focus({preventScroll: true});
    if (!el.classList || !el.classList.contains('tv-card')) return;
    if (!inPlayer()) lastCard = el;
    var strip = el.parentNode;
    if (strip.classList.contains('tv-strip')) {   // keep the card inside its row, no animation
      var r = el.getBoundingClientRect(), sr = strip.getBoundingClientRect(), pad = sr.width * 0.04;
      if (r.left < sr.left + pad) strip.scrollLeft -= sr.left + pad - r.left;
      else if (r.right > sr.right - pad) strip.scrollLeft += r.right - (sr.right - pad);
    }
    clearTimeout(warmTimer);
    warmTimer = setTimeout(function () { if (document.activeElement === el) warm(el.dataset.id); }, 900);
    if (inPlayer()) return;
    var box = el.closest('.tv-row') || el;
    var br = box.getBoundingClientRect(), top = document.querySelector('.tv-top').getBoundingClientRect().bottom;
    if (br.top < top + 8) window.scrollBy(0, br.top - top - 8);
    else if (br.bottom > window.innerHeight - 8) window.scrollBy(0, br.bottom - window.innerHeight + 8);
  }
  function nearestX(list, x) {
    var best = null, bestD = Infinity;
    list.forEach(function (c) { var r = c.getBoundingClientRect(), d = Math.abs(r.left + r.width / 2 - x); if (d < bestD) { bestD = d; best = c; } });
    return best;
  }
  function spatial(dir, nodes, from) {
    var r0 = from && from.getBoundingClientRect ? from.getBoundingClientRect() : {left: 0, top: 0, width: 0, height: 0};
    var cx = r0.left + r0.width / 2, cy = r0.top + r0.height / 2, best = null, bestScore = Infinity;
    nodes.forEach(function (n) {
      if (n === from) return;
      var r = n.getBoundingClientRect(); if (!r.width) return;
      var dx = r.left + r.width / 2 - cx, dy = r.top + r.height / 2 - cy;
      var ok = dir === 'left' ? dx < -4 : dir === 'right' ? dx > 4 : dir === 'up' ? dy < -4 : dy > 4;
      var horiz = dir === 'left' || dir === 'right';
      if (horiz && Math.abs(dy) > Math.max(r0.height, r.height) * 0.6) return;   // left/right stay on their own row
      if (!ok) return;
      var score = (horiz ? Math.abs(dx) : Math.abs(dy)) + (horiz ? Math.abs(dy) : Math.abs(dx)) * 2.5;
      if (score < bestScore) { bestScore = score; best = n; }
    });
    return best;
  }
  function headerNodes() { return Array.prototype.slice.call(document.querySelectorAll('.tv-top [data-nav]')).filter(function (n) { return !n.hidden; }); }
  function moveHome(dir) {
    var from = document.activeElement;
    var isCard = from && from.classList && from.classList.contains('tv-card');
    if (isCard && from.parentNode.classList.contains('tv-strip')) {
      var strip = from.parentNode, cards = cardsIn(strip), i = cards.indexOf(from);
      if (dir === 'left' || dir === 'right') { focusCard(cards[i + (dir === 'right' ? 1 : -1)]); return; }
      var rowsList = Array.prototype.slice.call(document.querySelectorAll('#rows .tv-row')).filter(function (r) { return cardsIn(r).length; });
      var target = rowsList[rowsList.indexOf(from.closest('.tv-row')) + (dir === 'down' ? 1 : -1)];
      var x = from.getBoundingClientRect(); x = x.left + x.width / 2;
      if (target) { focusCard(nearestX(cardsIn(target), x)); return; }
      if (dir === 'up') { window.scrollTo(0, 0); (document.querySelector('.tv-tabs .on') || $('homeBtn')).focus(); }
      return;
    }
    if (isCard && from.parentNode.id === 'grid') {
      var g = cardsIn($('grid')), k = g.indexOf(from), cols = 0, t0 = g[0].offsetTop;
      while (cols < g.length && g[cols].offsetTop === t0) cols++;
      var j = dir === 'left' ? k - 1 : dir === 'right' ? k + 1 : dir === 'up' ? k - cols : k + cols;
      if (dir === 'down' && j >= g.length && Math.floor(k / cols) < Math.floor((g.length - 1) / cols)) j = g.length - 1;
      if (j >= 0 && j < g.length && (dir === 'up' || dir === 'down' || Math.floor(j / cols) === Math.floor(k / cols))) { focusCard(g[j]); return; }
      if (dir === 'up' && j < 0) { window.scrollTo(0, 0); (document.querySelector('.tv-tabs .on') || $('homeBtn')).focus(); }
      return;
    }
    // in the header: search, tabs; down goes back to the cards
    var nodes = headerNodes(), best = spatial(dir, nodes, from);
    if (best) { best.focus(); return; }
    if (dir === 'down') {
      var back = lastCard && document.body.contains(lastCard) && lastCard.offsetParent ? lastCard : document.querySelector('#rows:not([hidden]) .tv-card[data-id], #list:not([hidden]) .tv-card[data-id]');
      focusCard(back);
    }
  }
  function movePlayer(dir) {
    var from = document.activeElement;
    var inStrip = from && from.parentNode && from.parentNode.classList && from.parentNode.classList.contains('tv-strip');
    if (inStrip) {
      if (dir === 'left' || dir === 'right') { var cards = cardsIn(from.parentNode); focusCard(cards[cards.indexOf(from) + (dir === 'right' ? 1 : -1)]); }
      else if (dir === 'up') ($('tabQueue').classList.contains('on') ? $('tabQueue') : $('tabNext')).focus();
      return;
    }
    // the buttons only (about twenty): strip cards are entered from the tabs, so a key press stays cheap
    var nodes = Array.prototype.slice.call($('dock').querySelectorAll('[data-pnav]')).filter(function (n) { return !n.hidden; });
    if (!from || nodes.indexOf(from) < 0) { $('playBtn').focus(); return; }
    var best = spatial(dir, nodes, from);
    var tabs = [$('tabQueue'), $('tabNext')];
    if (best && tabs.indexOf(best) >= 0 && tabs.indexOf(from) < 0) best = $('tabQueue').classList.contains('on') ? $('tabQueue') : $('tabNext');
    if (best) { best.focus(); return; }
    if (dir === 'down') {
      var list = lowerCards(), now = $('queueStrip').hidden ? null : $('queueStrip').querySelector('.tv-card.now');
      focusCard(now || list[0]);
    }
  }
  document.addEventListener('keydown', function (e) {
    var k = e.keyCode, video = $('video');
    var onSelect = document.activeElement && document.activeElement.tagName === 'SELECT';
    if (!inPlayer()) {
      if (BACK.indexOf(k) >= 0) return;   // the TV browser handles Back on the home page
      if (onSelect && (k === 38 || k === 40)) return;
      if (DIRS[k]) { e.preventDefault(); moveHome(DIRS[k]); return; }
      if (k === 13 && document.activeElement && document.activeElement.dataset && document.activeElement.dataset.id) { e.preventDefault(); openFromCard(document.activeElement); }
      return;
    }
    if (!$('upnext').hidden) {   // the countdown before the next video
      if (BACK.indexOf(k) >= 0) { e.preventDefault(); cancelUpNext(); wake(true); $('playBtn').focus(); return; }
      if (k === 13) { e.preventDefault(); var n = nextId(); cancelUpNext(); if (n) play(n.id, n.list, n.index, n.name); return; }
    }
    if (BACK.indexOf(k) >= 0 && !(k === 8 && onSelect)) {
      e.preventDefault();
      if (full && dockShown() && !video.paused) { hideDock(); return; }
      closePlayer(); return;
    }
    if (PLAYPAUSE.indexOf(k) >= 0) { e.preventDefault(); togglePlay(); wake(); return; }
    if (FFWD.indexOf(k) >= 0 || REWIND.indexOf(k) >= 0) { e.preventDefault(); seek(FFWD.indexOf(k) >= 0 ? 30 : -30); wake(); return; }
    if (NEXTV.indexOf(k) >= 0) { e.preventDefault(); next(); return; }
    if (PREVV.indexOf(k) >= 0) { e.preventDefault(); prev(); return; }
    if (full && !dockShown()) {   // nothing on screen but the picture: quick keys
      e.preventDefault();
      if (k === 37 || k === 39) { seek(k === 39 ? 10 : -10); wake(); $('playBtn').focus(); return; }
      if (k === 13) { togglePlay(); wake(); $('playBtn').focus(); return; }
      wake(); $('playBtn').focus(); return;
    }
    wake();
    if (onSelect && (k === 38 || k === 40)) return;
    if (DIRS[k]) { e.preventDefault(); movePlayer(DIRS[k]); return; }
    var act = document.activeElement;
    if (k === 13 && act && act.dataset && act.dataset.id && act.closest('.tv-related')) { e.preventDefault(); playFromStrip(act); }
  });
  document.addEventListener('click', function (e) {
    var c = e.target.closest('.tv-card[data-id]');
    if (!c) return;
    if (c.closest('.tv-related')) playFromStrip(c);
    else openFromCard(c);
  });
  document.addEventListener('focusin', function (e) {
    if (!inPlayer()) return;
    var browsing = !!(e.target.closest && e.target.closest('.tv-related'));
    if (browsing && !$('dock').classList.contains('browse')) { $('dock').classList.add('browse'); if (!e.target.dataset.id) revealNow(); }
    else if (!browsing) $('dock').classList.remove('browse');
    if ($('dock').contains(e.target)) wake();
  });

  $('searchForm').addEventListener('submit', function (e) { e.preventDefault(); search($('q').value); });
  $('homeBtn').addEventListener('click', loadHome);
  $('historyBtn').addEventListener('click', function () { tab('historyBtn'); api('history').then(function (d) { show('History', d.items); }); });
  $('laterBtn').addEventListener('click', function () { tab('laterBtn'); api(account ? 'feed?name=later' : 'later').then(function (d) { show('Watch Later', d.items); }).catch(function (e) { status(e.message); }); });
  $('recBtn').addEventListener('click', function () { tab('recBtn'); status('Loading recommendations…'); api('feed?name=rec').then(function (d) { show('Recommended', d.items); }).catch(function (e) { status(e.message); }); });
  $('closeBtn').addEventListener('click', closePlayer);
  $('playBtn').addEventListener('click', togglePlay);
  $('backTen').addEventListener('click', function () { seek(-10); });
  $('fwdTen').addEventListener('click', function () { seek(10); });
  $('nextBtn').addEventListener('click', next);
  $('mixBtn').addEventListener('click', startMix);
  $('tabQueue').addEventListener('click', function () { showLower('queue'); });
  $('tabNext').addEventListener('click', function () { showLower('next'); });
  $('tabQueue').addEventListener('focus', function () { showLower('queue'); });
  $('tabNext').addEventListener('focus', function () { showLower('next'); });
  $('prevBtn').addEventListener('click', prev);
  $('fsBtn').addEventListener('click', function () { setFull(!full); $('fsBtn').focus(); });
  $('subBtn').addEventListener('click', function () {
    if (!current || !current.channel_id) return;
    var add = $('subBtn').textContent === 'Subscribe';
    api('subscribe', {id: current.channel_id, name: current.channel, add: add}).then(function (d) { subs = d.subscriptions; $('subBtn').textContent = add ? 'Unsubscribe' : 'Subscribe'; });
  });
  $('laterAdd').addEventListener('click', function () { if (current) api('later', {item: current}).then(function () { $('laterAdd').textContent = 'Saved to Watch Later'; }); });
  $('channelBtn').addEventListener('click', function () { if (current && current.channel_id) { var id = current.channel_id, name = current.channel; closePlayer(); openChannel(id, name); } });
  $('qSel').addEventListener('change', function () { if (hls) hls.currentLevel = +this.value; });
  $('speedSel').addEventListener('change', function () { $('video').playbackRate = +this.value; });
  $('ccSel').addEventListener('change', function () { setCaptions(this.value); });
  $('chapSel').addEventListener('change', function () { if (this.value !== '') $('video').currentTime = +this.value; });
  var video = $('video');
  video.addEventListener('waiting', function () { spinner('Loading…'); });
  video.addEventListener('playing', function () { spinner(null); status(''); syncPlay(); wake(); });
  video.addEventListener('pause', function () { syncPlay(); wake(true); });
  video.addEventListener('play', syncPlay);
  video.addEventListener('timeupdate', function () {
    var b = video.buffered, end = b && b.length ? b.end(b.length - 1) : 0;
    setProgress(video.currentTime, isFinite(video.duration) ? video.duration : 0, end);
  });
  video.addEventListener('ended', function () { remember(); syncPlay(); upNext(); });
  api('account').then(function (d) { account = !!d.connected; $('recBtn').hidden = !account; }).catch(function () {}).then(loadHome);
})();
