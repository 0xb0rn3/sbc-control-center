/* Living-room overlay: greeting, clock, date and a quote that changes every 45 seconds.
 * Like the pictures, the quote follows the clock, so every screen shows the same one.
 *   SbcLivingRoom.mount(container, {label: 'name shown under the date'})  returns {stop()} */
(function () {
  'use strict';
  var QUOTE_MS = 45000;
  function greeting(h) { return h < 5 ? 'Good night' : h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : h < 21 ? 'Good evening' : 'Good night'; }
  function el(tag, cls, parent) { var e = document.createElement(tag); if (cls) e.className = cls; parent.appendChild(e); return e; }

  function mount(container, options) {
    options = options || {};
    var root = el('div', 'lr', container);
    var greet = el('div', 'lr-greet', root);
    var clock = el('div', 'lr-clock', root);
    var time = el('div', 'lr-time', clock);
    var date = el('div', 'lr-date', clock);
    if (options.label) el('div', 'lr-label', clock).textContent = options.label;
    var fig = el('figure', 'lr-quote', root);
    var quote = el('blockquote', '', fig);
    var who = el('figcaption', '', fig);
    var quotes = (window.SBC_QUOTES || []).filter(function (x) { return x && x.q; });
    var shown = -1;

    function tick() {
      var now = new Date();
      var hm = now.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
      if (time.textContent !== hm) time.textContent = hm;   // repaint only when the minute changes
      var d = now.toLocaleDateString([], {weekday: 'long', day: 'numeric', month: 'long'});
      if (date.textContent !== d) date.textContent = d;
      var g = greeting(now.getHours());
      if (greet.textContent !== g) greet.textContent = g;
      if (!quotes.length) return;
      var slot = Math.floor(Date.now() / QUOTE_MS) % quotes.length;
      if (slot === shown) return;
      var first = shown < 0;
      shown = slot;
      function put() { quote.textContent = '“' + quotes[slot].q + '”'; who.textContent = quotes[slot].a || ''; fig.classList.remove('fade'); }
      if (first) { put(); return; }
      fig.classList.add('fade');
      setTimeout(put, 1200);
    }
    tick();
    var timer = setInterval(tick, 1000);
    return { stop: function () { clearInterval(timer); if (root.parentNode) root.parentNode.removeChild(root); } };
  }
  window.SbcLivingRoom = { mount: mount };
})();
