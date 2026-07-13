import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.capacitorpqsecurestorage.testapp',
  appName: 'PQ Test App',
  webDir: 'dist',
  // mark the WKWebView / Android WebView inspectable so Appium can see the WEBVIEW context
  ios: { webContentsDebuggingEnabled: true },
  android: { webContentsDebuggingEnabled: true },
};

export default config;
