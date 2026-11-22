/* SBC Control Center slideshow engine.
 *
 * One engine drives both the page background (dimmed behind the dashboard) and the
 * full-screen standby (no dashboard, just the wallpapers and a clock). Wallpapers come from
 * /assets/wallpapers/index.json, the list the server keeps of the board's wallpaper folder;
 * without it the engine shows the single built-in background.
 *
 *   const show = new SbcSlideshow(document.getElementById('backdrop'), {interval: 300000});
 *   show.start(); show.setInterval(30000); show.next(); show.stop();
 *
 * Two layers cross-fade; the next picture is fully downloaded and decoded before it is shown,
 * so a slow TV browser never flashes a half-drawn image. Order is shuffled once per pass and
 * remembered per browser, so a reload does not restart at the same picture.
 */
(function () {
  'use strict';
  var FALLBACK = ['/assets/ui-background.png'];
  var STORE = 'sbc-slideshow-pos';

  function shuffle(list) {
    var a = list.slice();
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return a;
  }

  function preload(url) {
    return new Promise(function (resolve, reject) {
      var img = new Image();
      img.onload = function () {
        if (img.decode) { img.decode().then(function () { resolve(url); }, function () { resolve(url); }); }
        else { resolve(url); }
      };
      img.onerror = function () { reject(new Error('could not load ' + url)); };
      img.src = url;
    });
  }

  function SbcSlideshow(host, options) {
    options = options || {};
    this.host = host;
    this.interval = Math.max(5000, options.interval || 300000);
    this.list = [];
    this.order = [];
    this.pos = 0;
    this.timer = null;
    this.busy = false;
    this.layers = [document.createElement('div'), document.createElement('div')];
    this.front = 0;
    for (var i = 0; i < 2; i++) {
      this.layers[i].className = 'sbc-slide';
      host.appendChild(this.layers[i]);
    }
  }

  SbcSlideshow.prototype.load = function () {
    var self = this;
    return fetch('/assets/wallpapers/index.json', {credentials: 'same-origin', cache: 'no-cache'})
      .then(function (r) { return r.ok ? r.json() : {images: []}; })
      .catch(function () { return {images: []}; })
      .then(function (data) {
        var images = (data && Array.isArray(data.images)) ? data.images : [];
        self.list = images.filter(function (n) { return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(jpe?g|webp|png)$/.test(n); })
          .map(function (n) { return '/assets/wallpapers/' + n; });
        if (!self.list.length) self.list = FALLBACK.slice();
        self.order = shuffle(self.list);
        try {
          var saved = parseInt(localStorage.getItem(STORE) || '0', 10);
          self.pos = isFinite(saved) ? saved % self.order.length : 0;
        } catch (e) { self.pos = 0; }
        return self.list.length;
      });
  };

  SbcSlideshow.prototype.show = function (url) {
    var back = this.layers[1 - this.front];
    var front = this.layers[this.front];
    back.style.backgroundImage = 'url("' + url.replace(/"/g, '%22') + '")';
    back.classList.add('on');
    front.classList.remove('on');
    this.front = 1 - this.front;
  };

  SbcSlideshow.prototype.next = function () {
    var self = this;
    if (self.busy || !self.order.length) return Promise.resolve();
    self.busy = true;
    var tries = 0;
    function attempt() {
      if (self.pos >= self.order.length) { self.order = shuffle(self.list); self.pos = 0; }
      var url = self.order[self.pos++];
      try { localStorage.setItem(STORE, String(self.pos)); } catch (e) { /* storage may be off */ }
      return preload(url).then(function () { self.show(url); }, function () {
        if (++tries < 5) return attempt();
      });
    }
    return attempt().then(function () { self.busy = false; }, function () { self.busy = false; });
  };

  SbcSlideshow.prototype.start = function () {
    var self = this;
    self.stop();
    var first = self.layers[self.front].style.backgroundImage ? Promise.resolve() : self.next();
    return first.then(function () {
      if (self.list.length > 1) self.timer = setInterval(function () { self.next(); }, self.interval);
    });
  };

  SbcSlideshow.prototype.stop = function () {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  };

  SbcSlideshow.prototype.setInterval = function (ms) {
    this.interval = Math.max(5000, ms);
    if (this.timer) this.start();
  };

  window.SbcSlideshow = SbcSlideshow;
})();
