/* TV YouTube page: remote-control navigation, search, subscriptions, channels, and a player with
 * quality, speed, subtitles, chapters, resume and history. Everything personal (subscriptions,
 * history, Watch Later) is kept on the board, not with Google. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var BACK = [8, 27, 461, 10009, 166];   // Backspace, Escape and the TV remotes' Back keys
  var current = null, hls = null, infoTimer = null, saveTimer = null, subs = [];

  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function dur(s) { if (!s && s !== 0) return ''; s = Math.round(s); var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return (h ? h + ':' + (m < 10 ? '0' : '') : '') + m + ':' + (x < 10 ? '0' : '') + x; }
  function api(path, body) {
    return fetch('/api/tv/' + path, body ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)} : {})
      .then(function (r) { return r.json().then(function (d) { if (!r.ok || d.ok === false) throw new Error(d.error || ('error ' + r.status)); return d; }); });
  }
  function status(text) { $('status').textContent = text || ''; }

  // ---- lists
  function show(title, items, note) {
    $('rowTitle').textContent = title;
    status(note || (items.length ? '' : 'Nothing here yet.'));
    $('grid').innerHTML = items.map(function (v) {
      var progress = v.position && v.duration ? '<i class="bar" style="width:' + Math.min(100, v.position / v.duration * 100).toFixed(0) + '%"></i>' : '';
      return '<article class="tv-card" tabindex="0" data-nav data-id="' + esc(v.id) + '"><div class="thumb"><img loading="lazy" alt="" src="' + esc(v.thumb) + '">' +
        (v.duration ? '<span class="d">' + dur(v.duration) + '</span>' : '') + progress + '</div><div class="meta"><div class="t">' + esc(v.title) + '</div><div class="c">' + esc(v.channel || '') + '</div></div></article>';
    }).join('');
    var first = $('grid').querySelector('[data-nav]');
    if (first && document.activeElement === document.body) first.focus();
  }
  var account = false;
  function loadHome() {
    status('Loading…');
    if (account) {   // signed in: your own YouTube subscriptions feed
      Promise.all([api('feed?name=subs'), api('history')]).then(function (r) {
        var resume = (r[1].items || []).filter(function (v) { return v.position && v.duration && v.position < v.duration - 30; }).slice(0, 8);
        show(resume.length ? 'Continue watching · Your subscriptions' : 'Your subscriptions', resume.concat(r[0].items || []));
      }).catch(function (e) { status(e.message); });
      return;
    }
    Promise.all([api('home'), api('history')]).then(function (r) {
      subs = r[0].subscriptions || [];
      var resume = (r[1].items || []).filter(function (v) { return v.position && v.duration && v.position < v.duration - 30; }).slice(0, 8);
      var items = resume.concat(r[0].items || []);
      show(resume.length ? 'Continue watching · Subscriptions' : 'Subscriptions', items,
        items.length ? '' : 'Search for something, open a video and choose "Subscribe" to fill this page.');
    }).catch(function (e) { status(e.message); });
  }
  function search(q) {
    if (!q.trim()) return;
    status('Searching…');
    api('search?q=' + encodeURIComponent(q)).then(function (d) { show('Results for "' + q + '"', d.items); }).catch(function (e) { status(e.message); });
  }
  function openChannel(id, name) {
    status('Loading channel…');
    api('channel?id=' + encodeURIComponent(id)).then(function (d) { show(name || 'Channel', d.items); }).catch(function (e) { status(e.message); });
  }

  // ---- player
  function play(id) {
    status('Opening…');
    api('video?id=' + encodeURIComponent(id)).then(function (v) {
      if (!v.hls) throw new Error('No playable stream for this video.');
      current = v;
      $('player').hidden = false;
      $('vTitle').textContent = v.title || '';
      $('vChannel').textContent = (v.channel || '') + (v.live ? ' · LIVE' : '');
      var isSub = subs.some(function (s) { return s.id === v.channel_id; });
      $('subBtn').textContent = isSub ? 'Unsubscribe' : 'Subscribe';
      buildMenus(v);
      var video = $('video');
      if (hls) { hls.destroy(); hls = null; }
      if (window.Hls && window.Hls.isSupported()) {
        hls = new window.Hls({maxBufferLength: 30});
        hls.loadSource(v.hls);
        hls.attachMedia(video);
        hls.on(window.Hls.Events.MANIFEST_PARSED, function () { fillQuality(); start(); });
        hls.on(window.Hls.Events.ERROR, function (_e, data) { if (data.fatal) { status('Playback error: ' + data.details); } });
      } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = v.hls; video.addEventListener('loadedmetadata', start, {once: true});
      } else { throw new Error('This browser cannot play HLS video.'); }
      $('subBtn').focus();
      wake();
      status('');
    }).catch(function (e) { status(e.message); });
  }
  function start() {
    var video = $('video');
    api('history').then(function (h) {
      var seen = (h.items || []).filter(function (x) { return x.id === current.id; })[0];
      if (seen && seen.position && (!seen.duration || seen.position < seen.duration - 30)) video.currentTime = seen.position;
    }).catch(function () {}).then(function () { video.play().catch(function () {}); });
    clearInterval(saveTimer);
    saveTimer = setInterval(remember, 15000);
  }
  function remember() {
    var video = $('video');
    if (!current || !isFinite(video.currentTime)) return;
    api('history', {item: {id: current.id, title: current.title, channel: current.channel, channel_id: current.channel_id,
                           position: video.currentTime, duration: video.duration || current.duration}}).catch(function () {});
  }
  function closePlayer() {
    remember();
    clearInterval(saveTimer);
    var video = $('video');
    video.pause();
    if (hls) { hls.destroy(); hls = null; }
    video.removeAttribute('src'); video.load();
    $('player').hidden = true;
    var card = current && $('grid').querySelector('[data-id="' + current.id + '"]');
    current = null;
    (card || $('q')).focus();
  }
  function wake() {
    $('info').classList.remove('hide');
    clearTimeout(infoTimer);
    infoTimer = setTimeout(function () { if (!$('video').paused) $('info').classList.add('hide'); }, 5000);
  }
  function buildMenus(v) {
    $('ccSel').innerHTML = '<option value="">Subtitles off</option>' + (v.subtitles || []).map(function (s, i) { return '<option value="' + i + '">' + esc(s.name) + '</option>'; }).join('');
    $('chapSel').innerHTML = '<option value="">Chapters</option>' + (v.chapters || []).map(function (c) { return '<option value="' + c.start + '">' + dur(c.start) + ' · ' + esc(c.title) + '</option>'; }).join('');
    $('chapSel').hidden = !(v.chapters || []).length;
    var video = $('video');
    while (video.firstChild) video.removeChild(video.firstChild);
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

  // ---- remote-control navigation: move focus to the nearest element in the arrow's direction
  function move(dir) {
    var scope = $('player').hidden ? document : $('info');
    var nodes = Array.prototype.slice.call(scope.querySelectorAll($('player').hidden ? '[data-nav]' : '[data-pnav]')).filter(function (n) { return n.offsetParent !== null; });
    var from = document.activeElement, r0 = from && from.getBoundingClientRect ? from.getBoundingClientRect() : {left: 0, top: 0, width: 0, height: 0};
    var cx = r0.left + r0.width / 2, cy = r0.top + r0.height / 2, best = null, bestScore = Infinity;
    nodes.forEach(function (n) {
      if (n === from) return;
      var r = n.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2, dx = x - cx, dy = y - cy;
      var ok = dir === 'left' ? dx < -4 : dir === 'right' ? dx > 4 : dir === 'up' ? dy < -4 : dy > 4;
      if (!ok) return;
      var main = (dir === 'left' || dir === 'right') ? Math.abs(dx) : Math.abs(dy), side = (dir === 'left' || dir === 'right') ? Math.abs(dy) : Math.abs(dx);
      var score = main + side * 2.5;
      if (score < bestScore) { bestScore = score; best = n; }
    });
    if (best) { best.focus(); best.scrollIntoView({block: 'nearest', behavior: 'smooth'}); }
  }
  document.addEventListener('keydown', function (e) {
    var k = e.keyCode, inPlayer = !$('player').hidden, video = $('video');
    if (BACK.indexOf(k) >= 0 && !(k === 8 && document.activeElement === $('q'))) {
      if (inPlayer) { e.preventDefault(); closePlayer(); }
      return;
    }
    if (inPlayer) {
      wake();
      var onControl = document.activeElement && document.activeElement.tagName === 'SELECT';
      if (!onControl && (k === 37 || k === 39) && $('info').classList.contains('hide')) { e.preventDefault(); video.currentTime += k === 39 ? 10 : -10; return; }
      if (!onControl && k === 13 && document.activeElement === document.body) { e.preventDefault(); if (video.paused) video.play(); else video.pause(); return; }
      if (k === 179 || k === 415 || k === 19) { e.preventDefault(); if (video.paused) video.play(); else video.pause(); return; }
    }
    if (document.activeElement && document.activeElement.tagName === 'SELECT' && (k === 38 || k === 40)) return;
    var dirs = {37: 'left', 38: 'up', 39: 'right', 40: 'down'};
    if (dirs[k]) { e.preventDefault(); move(dirs[k]); return; }
    if (k === 13 && document.activeElement && document.activeElement.dataset && document.activeElement.dataset.id) { e.preventDefault(); play(document.activeElement.dataset.id); }
  });
  $('grid').addEventListener('click', function (e) { var c = e.target.closest('[data-id]'); if (c) play(c.dataset.id); });
  $('searchForm').addEventListener('submit', function (e) { e.preventDefault(); search($('q').value); });
  $('homeBtn').addEventListener('click', loadHome);
  $('historyBtn').addEventListener('click', function () { api('history').then(function (d) { show('History', d.items); }); });
  $('laterBtn').addEventListener('click', function () { api(account ? 'feed?name=later' : 'later').then(function (d) { show('Watch Later', d.items); }).catch(function (e) { status(e.message); }); });
  $('recBtn').addEventListener('click', function () { status('Loading recommendations…'); api('feed?name=rec').then(function (d) { show('Recommended', d.items); }).catch(function (e) { status(e.message); }); });
  $('closeBtn').addEventListener('click', closePlayer);
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
  $('video').addEventListener('pause', wake);
  $('video').addEventListener('ended', function () { remember(); wake(); });
  // Try to add this page to the TV home screen. On VIDAA this is an undocumented browser call
  // (Hisense_installApp); newer firmware often accepts it but adds no icon, so we report honestly
  // and never claim success we did not see. Nothing third-party runs: this is our own page.
  var deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); deferredPrompt = e; });
  function installSays(msg) { status(msg); }
  $('installBtn').addEventListener('click', function () {
    var url = location.origin + '/tv';
    var name = 'YouTube (no ads)';
    var icon = location.origin + '/assets/ui/tv-icon.png';
    // 1) VIDAA's own install call, under the names seen across firmware versions
    var vidaa = window.Hisense_installApp || window.Hisense_installAp || (window.vidaa && window.vidaa.installApp);
    if (typeof vidaa === 'function') {
      try {
        // signatures differ by firmware; try the common ones, stop on the first that does not throw
        var tries = [[name, url, icon], ['sbc-youtube', name, url, icon], [url, name, icon], [url]];
        for (var i = 0; i < tries.length; i++) { try { vidaa.apply(window, tries[i]); installSays('Asked the TV to add the icon. If it did not appear on the home screen, your firmware blocks it; keep using this as a bookmark.'); return; } catch (e) {} }
        installSays('The TV refused every install request; keep using this as a bookmark.');
      } catch (e) { installSays('The TV refused the install; keep using this as a bookmark.'); }
      return;
    }
    // 2) the ordinary web-app install prompt (some browsers)
    if (deferredPrompt) { deferredPrompt.prompt(); installSays('Confirm the install in the prompt.'); deferredPrompt = null; return; }
    // 3) nothing available
    installSays('This TV has no app-install function in its browser. Add /tv as a bookmark or favourite instead, and open it full screen.');
  });

  api('account').then(function (d) { account = !!d.connected; $('recBtn').hidden = !account; }).catch(function () {}).then(loadHome);
})();
