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
 * Pictures that do not fit are resized automatically (fit 'auto', the default): one whose shape is
 * close to the screen's fills it (a little cropped at the edges); one much taller or wider (a
 * portrait pin on a TV, an ultra-wide wallpaper) is shown whole, centred over a blurred copy of
 * itself, so nothing important is cut off. 'cover' and 'contain-blur' force one or the other.
 *
 * Two layers cross-fade; the next picture is fully downloaded and decoded before it is shown,
 * so a slow TV browser never flashes a half-drawn image. As on the ArxOS lock screen, the
 * picture follows the clock: the order is a fixed shuffle of the list and the slot is the
 * current time divided by the interval, so every screen with the same interval shows the same
 * picture at the same moment, and a reload carries on where the slideshow is.
 */
(function () {
  'use strict';
  var FALLBACK = ['/assets/ui-background.png'];

  // the same shuffle on every screen: seeded from the list itself
  function seededShuffle(list) {
    var seed = 2166136261;
    for (var k = 0; k < list.length; k++) {
      for (var c = 0; c < list[k].length; c++) { seed ^= list[k].charCodeAt(c); seed = Math.imul(seed, 16777619) >>> 0; }
    }
    function rand() {
      seed = (seed + 0x6D2B79F5) >>> 0;
      var t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }
    var a = list.slice().sort();
    for (var i = a.length - 1; i > 0; i--) {
      var j = Math.floor(rand() * (i + 1));
      var x = a[i]; a[i] = a[j]; a[j] = x;
    }
    return a;
  }

  // how far a picture's shape may differ from the screen's before it is shown whole instead of filling
  var FIT_TOLERANCE = 1.3;

  function preload(url) {
    return new Promise(function (resolve, reject) {
      var img = new Image();
      img.onload = function () {
        var size = {url: url, w: img.naturalWidth || 0, h: img.naturalHeight || 0};
        if (img.decode) { img.decode().then(function () { resolve(size); }, function () { resolve(size); }); }
        else { resolve(size); }
      };
      img.onerror = function () { reject(new Error('could not load ' + url)); };
      img.src = url;
    });
  }

  function SbcSlideshow(host, options) {
    options = options || {};
    this.host = host;
    this.interval = Math.max(5000, options.interval || 300000);
    // 'wallpapers' (the dashboard's) or 'moodboard' (the Pinterest board, for the living room)
    this.collection = /^(wallpapers|moodboard)$/.test(options.collection || '') ? options.collection : 'wallpapers';
    // 'cover' fills the screen; 'contain-blur' shows the whole picture over a blurred copy of itself
    this.fit = options.fit === 'contain-blur' || options.fit === 'cover' ? options.fit : 'auto';
    this.fallback = options.fallback !== false;
    this.list = [];
    this.order = [];
    this.slot = -1;
    this.offset = 0;
    this.timer = null;
    this.busy = false;
    this.layers = [document.createElement('div'), document.createElement('div')];
    this.front = 0;
    for (var i = 0; i < 2; i++) {
      // every layer can show a picture either way: a blurred copy behind, the picture in front
      this.layers[i].className = 'sbc-slide fit';
      var blur = document.createElement('div'); blur.className = 'sbc-blur';
      var fg = document.createElement('div'); fg.className = 'sbc-fg';
      this.layers[i].appendChild(blur); this.layers[i].appendChild(fg);
      host.appendChild(this.layers[i]);
    }
    this.shown = [null, null];
    var self = this;
    window.addEventListener('resize', function () {   // a rotated phone or a resized window: decide again
      for (var k = 0; k < 2; k++) if (self.shown[k]) self.layers[k].classList.toggle('contain', self.wantsWhole(self.shown[k]));
    });
  }

  SbcSlideshow.prototype.load = function () {
    var self = this;
    return fetch('/assets/' + self.collection + '/index.json', {credentials: 'same-origin', cache: 'no-cache'})
      .then(function (r) { return r.ok ? r.json() : {images: []}; })
      .catch(function () { return {images: []}; })
      .then(function (data) {
        var images = (data && Array.isArray(data.images)) ? data.images : [];
        self.list = images.filter(function (n) { return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(jpe?g|webp|png)$/.test(n); })
          .map(function (n) { return '/assets/' + self.collection + '/' + n; });
        if (!self.list.length && !self.fallback) return 0;
        if (!self.list.length) self.list = FALLBACK.slice();
        self.order = seededShuffle(self.list);
        return self.list.length;
      });
  };

  // whole picture (over its blurred copy) or filling the screen, for this picture on this screen
  SbcSlideshow.prototype.wantsWhole = function (size) {
    if (this.fit !== 'auto') return this.fit === 'contain-blur';
    var screen = (this.host.clientWidth || window.innerWidth) / Math.max(1, this.host.clientHeight || window.innerHeight);
    if (!size || !size.w || !size.h || !screen) return false;
    var ratio = (size.w / size.h) / screen;
    return ratio > FIT_TOLERANCE || ratio < 1 / FIT_TOLERANCE;
  };

  SbcSlideshow.prototype.show = function (size) {
    var idx = 1 - this.front;
    var back = this.layers[idx];
    var front = this.layers[this.front];
    var css = 'url("' + size.url.replace(/"/g, '%22') + '")';
    back.firstChild.style.backgroundImage = css;
    back.lastChild.style.backgroundImage = css;
    back.classList.toggle('contain', this.wantsWhole(size));
    this.shown[idx] = size;
    back.classList.add('on');
    front.classList.remove('on');
    this.front = 1 - this.front;
  };

  SbcSlideshow.prototype.currentSlot = function () {
    return Math.floor(Date.now() / this.interval);
  };

  // show the picture for the current time slot (a picture that fails to load is skipped)
  SbcSlideshow.prototype.sync = function (force) {
    var self = this;
    var slot = self.currentSlot();
    if (self.busy || !self.order.length || (slot === self.slot && !force)) return Promise.resolve();
    self.busy = true;
    var tries = 0;
    function attempt() {
      var url = self.order[(slot + self.offset) % self.order.length];
      return preload(url).then(function (size) { self.slot = slot; self.show(size); }, function () {
        self.offset++;
        if (++tries < 5) return attempt();
      });
    }
    return attempt().then(function () { self.busy = false; }, function () { self.busy = false; });
  };

  // step ahead by one picture now (and stay one ahead of the clock from then on)
  SbcSlideshow.prototype.next = function () {
    this.offset++;
    return this.sync(true);
  };

  SbcSlideshow.prototype.start = function () {
    var self = this;
    self.stop();
    return self.sync(true).then(function () {
      if (self.list.length > 1) self.timer = setInterval(function () { self.sync(false); }, Math.min(5000, self.interval));
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
