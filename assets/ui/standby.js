/* The sign-in-free living-room page (/living-room, also /standby): wallpapers, clock, greeting
 * and quotes, nothing else. ?interval=SECONDS sets how often the picture changes (10 to 3600,
 * default 30). */
(function () {
  'use strict';
  var q = /[?&]interval=([0-9]{1,4})/.exec(location.search);
  var seconds = q ? Math.min(3600, Math.max(10, parseInt(q[1], 10))) : 30;
  // the mood board when it has pictures (unless ?pictures=wallpapers), the wallpapers otherwise
  var host = document.getElementById('backdrop');
  var wantWalls = /[?&]pictures=wallpapers/.test(location.search);
  var board = new window.SbcSlideshow(host, {interval: seconds * 1000, collection: 'moodboard', fit: 'contain-blur', fallback: false});
  (wantWalls ? Promise.resolve(0) : board.load()).then(function (count) {
    if (count > 0) { board.start(); return; }
    while (host.firstChild) host.removeChild(host.firstChild);
    var walls = new window.SbcSlideshow(host, {interval: seconds * 1000});
    walls.load().then(function () { walls.start(); });
  });
  window.SbcLivingRoom.mount(document.getElementById('overlay'), {label: document.body.getAttribute('data-label') || '', name: document.body.getAttribute('data-name') || ''});
})();
