#!/bin/sh
# Usage: ./build.sh            build "Claude Switcher.app" in this folder
#        ./build.sh install    build, copy to /Applications, open at login, launch
set -e
cd "$(dirname "$0")"
APP="Claude Switcher.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O main.swift -o "$APP/Contents/MacOS/ClaudeSwitcher"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Claude Switcher</string>
  <key>CFBundleIdentifier</key><string>dev.claudeswitcher.app</string>
  <key>CFBundleExecutable</key><string>ClaudeSwitcher</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
codesign --force -s - "$APP"
echo "Built $PWD/$APP"

if [ "$1" = "install" ]; then
  pkill -f "Claude Switcher.app/Contents/MacOS/ClaudeSwitcher" 2>/dev/null || true
  rm -rf "/Applications/$APP"
  cp -R "$APP" /Applications/
  "/Applications/$APP/Contents/MacOS/ClaudeSwitcher" --register-login || echo "Couldn't add to Login Items; use the sunrise toggle in the app."
  open "/Applications/$APP"
  echo "Installed to /Applications and launched."
fi
