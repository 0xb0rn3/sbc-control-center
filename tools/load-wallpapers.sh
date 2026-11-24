#!/usr/bin/env bash
# load-wallpapers.sh FOLDER root@BOARD [APP_DIR]
# Resizes every JPEG/PNG/WebP in FOLDER for a 1080p screen (covering 1920x1080, never upscaled),
# strips all metadata (camera, GPS, editing history), names each file by its content hash and
# copies the set to APP_DIR/assets/wallpapers on the board, replacing what was there. The
# slideshow (dashboard background and /standby) picks the new set up within five minutes.
# Needs ImageMagick 7 (magick) and rsync here, rsync on the board.
set -euo pipefail
src=${1:?usage: load-wallpapers.sh FOLDER root@BOARD [APP_DIR]}; board=${2:?board, e.g. root@192.168.1.10}
app=${3:-/opt/sbc-control-center}
command -v magick >/dev/null || { echo "ImageMagick 7 (magick) is needed" >&2; exit 1; }
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
find "$src" -maxdepth 1 -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.webp' \) -print0 |
  xargs -0 -P "$(nproc)" -I{} sh -c 'h=$(sha256sum "$1" | cut -c1-12)
    magick "$1[0]" -auto-orient -resize "1920x1080^>" -strip -interlace JPEG -sampling-factor 4:2:0 -quality 80 "$2/w-$h.jpg" \
      || echo "skipped: $1" >&2' _ {} "$out"
n=$(find "$out" -name 'w-*.jpg' | wc -l)
[ "$n" -gt 0 ] || { echo "no pictures found in $src" >&2; exit 1; }
echo "$n wallpapers, $(du -sh "$out" | cut -f1); copying to $board:$app/assets/wallpapers"
ssh "$board" "install -d -m 0755 '$app/assets/wallpapers'"
rsync -rt --delete --chmod=D755,F644 --exclude README.txt "$out/" "$board:$app/assets/wallpapers/"
echo "done"
