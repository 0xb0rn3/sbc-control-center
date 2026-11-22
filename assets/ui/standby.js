/* The sign-in-free standby page (/standby): wallpapers and the time, nothing else.
 * ?interval=SECONDS sets how often the picture changes (10 to 3600, default 30). */
(function () {
  'use strict';
  var q = /[?&]interval=([0-9]{1,4})/.exec(location.search);
  var seconds = q ? Math.min(3600, Math.max(10, parseInt(q[1], 10))) : 30;
  var show = new window.SbcSlideshow(document.getElementById('backdrop'), {interval: seconds * 1000});
  show.load().then(function () { show.start(); });
  function tick() {
    var now = new Date();
    document.getElementById('time').textContent = now.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
    document.getElementById('date').textContent = now.toLocaleDateString([], {weekday: 'long', day: 'numeric', month: 'long'});
  }
  tick();
  setInterval(tick, 1000);
})();
