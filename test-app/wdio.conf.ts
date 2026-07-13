// Appium + WebdriverIO e2e for the test-app. Drives the app on a real iOS/Android target,
// switches into the Capacitor webview to tap buttons and read #log.
//
// Just run (macOS; the scripts build the app, boot a sim/emulator, and run these specs):
//   npm run e2e:ios
//   npm run e2e:android
// First run only, install the Appium drivers: `npx appium driver install xcuitest uiautomator2`.
// To re-run the specs without rebuilding, use `npm run wdio:ios` / `wdio:android` after a build.
//
// The "core" specs pass on a simulator/emulator (bridge + capabilities + absent-item queries). On
// iOS all storage/crypto is Secure Enclave-backed, so those "hardware" specs skip unless
// E2E_HARDWARE=1 on a physical device; on an Android emulator E2E_HARDWARE also runs the storage,
// at-rest, and ML-KEM specs (only ML-DSA signing needs a real device).

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
