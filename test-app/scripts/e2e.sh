#!/usr/bin/env bash
# One-command local e2e. macOS only (iOS needs Xcode; Android needs the Android SDK).
#   npm run e2e:ios       # boots an iOS 26 simulator and runs the core specs
#   npm run e2e:android   # boots an Android emulator and runs the core specs
# Add E2E_HARDWARE=1 on a physical device to also run the crypto/storage specs.
set -euo pipefail

PLATFORM="${1:-ios}"
cd "$(dirname "$0")/.."          # test-app
ROOT="$(cd .. && pwd)"           # plugin

step() { printf '\n=== %s ===\n' "$1"; }

step "build the plugin (dist/)"
( cd "$ROOT" && npm run build )

step "test-app deps + web build"
rm -rf node_modules/capacitor-pq-secure-storage   # force a fresh copy of the file: dep
npm install
npm run build

if [ "$PLATFORM" = "ios" ]; then
  step "add/refresh the iOS app"
  [ -d ios ] || npx cap add ios || true

  step "ensure the Appium xcuitest driver"
  npx appium driver list --installed 2>&1 | grep -q xcuitest || npx appium driver install xcuitest

  step "build the app for the simulator"
  if [ -f ios/App/Podfile ]; then
    # Capacitor 7: CocoaPods. cap add generates the Podfile at iOS 14; the plugin floor is 15
    npx cap copy ios
    sed -i '' "s/platform :ios, '14.0'/platform :ios, '15.0'/" ios/App/Podfile
    ( cd ios/App && pod install )
    build_target=(-workspace ios/App/App.xcworkspace)
  else
    # Capacitor 8: Swift Package Manager (no Podfile); cap sync resolves the plugin package
    npx cap sync ios
    build_target=(-project ios/App/App.xcodeproj)
  fi
  xcodebuild "${build_target[@]}" -scheme App -sdk iphonesimulator \
    -configuration Debug -derivedDataPath ios/build CODE_SIGNING_ALLOWED=NO build

  step "pick a simulator"
  udid=$(xcrun simctl list devices booted -j | jq -r '[.devices[][] | select(.name|test("iPhone"))][0].udid // empty')
  if [ -z "$udid" ]; then
    udid=$(xcrun simctl list devices available -j \
      | jq -r '[.devices | to_entries[] | select(.key|test("iOS")) | .value[] | select(.name|test("iPhone"))][0].udid')
    [ -n "$udid" ] || { echo "no iOS simulator found"; exit 1; }
    xcrun simctl boot "$udid" || true
  fi

  step "run the e2e"
  export IOS_APP_PATH="$PWD/ios/build/Build/Products/Debug-iphonesimulator/App.app"
  export IOS_UDID="$udid"
  E2E_PLATFORM=ios npx wdio run ./wdio.conf.ts

elif [ "$PLATFORM" = "android" ]; then
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  export ANDROID_SDK_ROOT="$ANDROID_HOME"
  export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
  # capacitor-android 7 needs JDK 21; force it even if the shell has an older JAVA_HOME
  JAVA21="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
  [ -n "$JAVA21" ] && export JAVA_HOME="$JAVA21"

  step "add/refresh the Android app"
  [ -d android ] || npx cap add android
  npx cap sync android

  step "build the debug APK"
  ( cd android && ./gradlew assembleDebug )

  step "ensure the Appium uiautomator2 driver"
  npx appium driver list --installed 2>&1 | grep -q uiautomator2 || npx appium driver install uiautomator2

  step "ensure an emulator is running"
  if ! adb devices | grep -qw device; then
    avd=$(emulator -list-avds | head -1)
    [ -n "$avd" ] || { echo "no AVD found; create one in Android Studio first"; exit 1; }
    echo "booting $avd ..."
    nohup emulator -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot >/tmp/pq-emulator.log 2>&1 &
    adb wait-for-device
    until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
  fi

  step "run the e2e"
  export ANDROID_APK_PATH="$PWD/android/app/build/outputs/apk/debug/app-debug.apk"
  E2E_PLATFORM=android npx wdio run ./wdio.conf.ts

else
  echo "usage: e2e.sh [ios|android]"; exit 1
fi
