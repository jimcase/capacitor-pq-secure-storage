// Appium + WebdriverIO e2e for the test-app. Drives the app on a real iOS/Android target,
// switches into the Capacitor webview to tap buttons and read #log.
//
// One-time setup (Appium 2 keeps drivers out of node_modules):
//   npm install
//   npx appium driver install xcuitest      # iOS
//   npx appium driver install uiautomator2   # Android
//
// Build the app for the target, then point the config at the artifact via env vars:
//   iOS (simulator):
//     npm run build && npx cap sync ios
//     xcodebuild -workspace ios/App/App.xcworkspace -scheme App \
//       -sdk iphonesimulator -configuration Debug -derivedDataPath ios/build build
//     IOS_APP_PATH=ios/build/Build/Products/Debug-iphonesimulator/App.app npm run e2e:ios
//   Android (emulator):
//     npm run build && npx cap sync android
//     (cd android && ./gradlew assembleDebug)
//     ANDROID_AVD=Pixel_7_API_35 \
//       ANDROID_APK_PATH=android/app/build/outputs/apk/debug/app-debug.apk npm run e2e:android
//
// The hardware crypto (SEP ML-DSA, StrongBox, biometrics) only runs on a physical device.
// On a simulator/emulator the "core" specs pass (bridge + Keychain storage); the "hardware"
// specs skip unless you set E2E_HARDWARE=1 on a real device.

const platform = process.env.E2E_PLATFORM ?? 'ios';

const iosCaps = {
  platformName: 'iOS',
  'appium:automationName': 'XCUITest',
  'appium:deviceName': process.env.IOS_DEVICE ?? 'iPhone 17 Pro',
  'appium:platformVersion': process.env.IOS_VERSION ?? '26.2',
  'appium:app': process.env.IOS_APP_PATH,
  'appium:autoAcceptAlerts': false,
  'appium:webviewConnectTimeout': 15000,
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
  services: ['appium'],
  mochaOpts: {
    ui: 'bdd',
    timeout: 180000,
  },
};
