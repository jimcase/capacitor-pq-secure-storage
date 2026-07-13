// Appium + WebdriverIO e2e for the test-app. Drives the app on a real iOS/Android target,
// switches into the Capacitor webview to tap buttons and read #log.
//
// One-time setup:
//   npm install
//   npx appium driver install xcuitest      # iOS
//   npx appium driver install uiautomator2   # Android
//
// Build the app for the target, then point the config at the artifact via env vars:
//   iOS (simulator, needs Xcode 26 for the iOS 26 SDK):
//     npm run build && npx cap add ios      # first time; later just `npx cap sync ios`
//     # the plugin floor is iOS 15, bump the generated Podfile (Capacitor defaults to 14):
//     sed -i '' "s/platform :ios, '14.0'/platform :ios, '15.0'/" ios/App/Podfile
//     (cd ios/App && pod install)
//     xcodebuild -workspace ios/App/App.xcworkspace -scheme App -sdk iphonesimulator \
//       -configuration Debug -derivedDataPath ios/build CODE_SIGNING_ALLOWED=NO build
//     IOS_APP_PATH="$PWD/ios/build/Build/Products/Debug-iphonesimulator/App.app" \
//       IOS_DEVICE="iPhone 17 Pro" IOS_VERSION="26.2" npm run e2e:ios
//   Android (emulator):
//     npm run build && npx cap add android
//     (cd android && ./gradlew assembleDebug)
//     ANDROID_AVD=Pixel_7_API_35 \
//       ANDROID_APK_PATH=android/app/build/outputs/apk/debug/app-debug.apk npm run e2e:android
//
// Verified on the iOS 26.2 simulator (Xcode 26.2): the "core" specs pass. iOS storage/crypto is
// all Secure Enclave-backed, so it fails on a simulator; those "hardware" specs skip unless
// E2E_HARDWARE=1 on a physical device (on Android the Keystore storage also works on an emulator).

const platform = process.env.E2E_PLATFORM ?? 'ios';

const iosCaps = {
  platformName: 'iOS',
  'appium:automationName': 'XCUITest',
  'appium:deviceName': process.env.IOS_DEVICE ?? 'iPhone 17 Pro',
  'appium:platformVersion': process.env.IOS_VERSION ?? '26.2',
  'appium:app': process.env.IOS_APP_PATH,
  'appium:autoAcceptAlerts': false,
  'appium:webviewConnectTimeout': 30000,
  // Capacitor's iOS executable is "App", so the remote debugger lists the webview under the
  // process "process-App", not the app bundle id. Match it so getContexts finds the WEBVIEW.
  'appium:additionalWebviewBundleIds': ['process-App', 'com.pq.securestorage.testapp'],
  // first run compiles WebDriverAgent, so give it room
  'appium:wdaLaunchTimeout': 240000,
  'appium:wdaConnectionTimeout': 240000,
  // CI passes a concrete simulator udid; locally deviceName/platformVersion is enough
  ...(process.env.IOS_UDID ? { 'appium:udid': process.env.IOS_UDID } : {}),
} as WebdriverIO.Capabilities;

const androidCaps = {
  platformName: 'Android',
  'appium:automationName': 'UiAutomator2',
  'appium:avd': process.env.ANDROID_AVD,
  'appium:app': process.env.ANDROID_APK_PATH,
  'appium:appPackage': 'com.pq.securestorage.testapp',
  'appium:appActivity': '.MainActivity',
  'appium:autoGrantPermissions': true,
} as WebdriverIO.Capabilities;

export const config: WebdriverIO.Config = {
  runner: 'local',
  tsConfigPath: './tsconfig.e2e.json',
  specs: ['./test/e2e/**/*.e2e.ts'],
  maxInstances: 1,
  capabilities: [platform === 'android' ? androidCaps : iosCaps],
  logLevel: 'warn',
  framework: 'mocha',
  reporters: ['spec'],
  // allow uiautomator2 to auto-download the chromedriver it needs for the Android WebView context.
  // appium 3 wants the scoped '<automationName>:<feature>' name, as a string (the service
  // JSON-stringifies arrays, which appium can't parse).
  services: [['appium', { args: { allowInsecure: 'uiautomator2:chromedriver_autodownload' } }]],
  // session creation can be slow while WebDriverAgent builds and the simulator boots
  connectionRetryTimeout: 360000,
  connectionRetryCount: 1,
  mochaOpts: {
    ui: 'bdd',
    timeout: 180000,
  },
};
