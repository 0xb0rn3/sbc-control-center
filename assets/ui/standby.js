/* The sign-in-free living-room page (/living-room, also /standby): wallpapers, clock, greeting
 * and quotes, nothing else. ?interval=SECONDS sets how often the picture changes (10 to 3600,
 * default 30). */
(function () {
  'use strict';
  var q = /[?&]interval=([0-9]{1,4})/.exec(location.search);
  var seconds = q ? Math.min(3600, Math.max(10, parseInt(q[1], 10))) : 30;
  var show = new window.SbcSlideshow(document.getElementById('backdrop'), {interval: seconds * 1000});
  show.load().then(function () { show.start(); });
  window.SbcLivingRoom.mount(document.getElementById('overlay'), {label: document.body.getAttribute('data-label') || '', name: document.body.getAttribute('data-name') || ''});
})();
