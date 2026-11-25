/* Sign-in-free living-room page: rotating pictures plus the full ambient dashboard. */
(function () {
  'use strict';
  var q = /[?&]interval=([0-9]{1,4})/.exec(location.search);
  var seconds = q ? Math.min(3600, Math.max(10, parseInt(q[1], 10))) : 30;
  var host = document.getElementById('backdrop');
  var wantWalls = /[?&]pictures=wallpapers/.test(location.search);
  var board = new window.SbcSlideshow(host, {interval: seconds * 1000, collection: 'moodboard', fallback: false});
  (wantWalls ? Promise.resolve(0) : board.load()).then(function (count) {
    if (count > 0) { board.start(); return; }
    while (host.firstChild) host.removeChild(host.firstChild);
    var walls = new window.SbcSlideshow(host, {interval: seconds * 1000});
    walls.load().then(function () { walls.start(); });
  });
  window.SbcAmbientDashboard.mount(document.getElementById('overlay'), {
    label: document.body.getAttribute('data-label') || ''
  });
})();
