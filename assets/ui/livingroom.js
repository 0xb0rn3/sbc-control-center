/* Living-room overlay: a time-of-day greeting, clock, date and a quote that changes every
 * 45 seconds. Like the pictures, the quote follows the clock, so every screen shows the same one.
 *   SbcLivingRoom.mount(container, {name: 'greeted by name', label: 'shown under the date'})
 * returns {stop()} */
(function () {
  'use strict';
  var QUOTE_MS = 45000;
  function greeting(h) { return h < 5 ? 'Good night' : h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : h < 21 ? 'Good evening' : 'Good night'; }
  function el(tag, cls, parent) { var e = document.createElement(tag); if (cls) e.className = cls; parent.appendChild(e); return e; }

  function mount(container, options) {
    options = options || {};
    var root = el('div', 'lr', container);
    var clock = el('div', 'lr-clock', root);
    var greet = el('div', 'lr-greet', clock);
    var time = el('div', 'lr-time', clock);
    var date = el('div', 'lr-date', clock);
    if (options.label) el('div', 'lr-label', clock).textContent = options.label;
    var fig = el('figure', 'lr-quote', root);
    var orig = el('div', 'lr-orig', fig);
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
      var g = greeting(now.getHours()) + (options.name ? ', ' + options.name : '');
      if (greet.textContent !== g) greet.textContent = g;
      if (!quotes.length) return;
      var slot = Math.floor(Date.now() / QUOTE_MS) % quotes.length;
      if (slot === shown) return;
      var first = shown < 0;
      shown = slot;
      function put() {
        var item = quotes[slot];
        // the original in its own script and direction, then the English, then where it comes from
        orig.textContent = item.o || '';
        orig.hidden = !item.o;
        if (item.l) orig.setAttribute('lang', item.l); else orig.removeAttribute('lang');
        orig.setAttribute('dir', /^(ar|fa|he|ur)\b/.test(item.l || '') ? 'rtl' : 'auto');
        quote.textContent = item.o ? item.q : '\u201c' + item.q + '\u201d';
        quote.className = item.o ? 'translation' : '';
        who.textContent = item.a || '';
        fig.classList.remove('fade');
      }
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
