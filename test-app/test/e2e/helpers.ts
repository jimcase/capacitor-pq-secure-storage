import { browser, $ } from '@wdio/globals';

// getContexts() returns string[] on older Appium, or detailed objects on newer. Normalize to ids.
function contextId(c: unknown): string {
  return typeof c === 'string' ? c : ((c as { id?: string })?.id ?? '');
}

export async function switchToWebview(): Promise<void> {
  let seen: string[] = [];
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    seen = (await browser.getContexts()).map(contextId);
    const web = seen.find((id) => id.includes('WEBVIEW'));
    if (web) {
      await browser.switchContext(web);
      return;
    }
    await browser.pause(1000);
  }
  throw new Error(`Capacitor webview context never appeared; contexts seen: [${seen.join(', ')}]`);
}

export async function switchToNative(): Promise<void> {
  await browser.switchContext('NATIVE_APP');
}

// Tap a button by its exact visible text, then wait for #log to change (ops are async).
export async function tap(label: string): Promise<string> {
  const log = await $('#log');
  const before = await log.getText();
  await $(`button=${label}`).click();
  await browser.waitUntil(async () => (await log.getText()) !== before, {
    timeout: 20000,
    timeoutMsg: `no #log update after tapping "${label}"`,
  });
  return log.getText();
}

// Satisfy a biometric prompt. iOS Simulator + Android emulator only; a real device prompt
// cannot be automated (by design). Enroll once in a before hook, then match per prompt.
export async function enrollBiometric(): Promise<void> {
  const caps = browser.capabilities as { platformName?: string };
  if (String(caps.platformName).toLowerCase() === 'ios') {
    await browser.execute('mobile: enrollBiometric', { isEnabled: true });
  }
}

export async function matchBiometric(): Promise<void> {
  const caps = browser.capabilities as { platformName?: string };
  if (String(caps.platformName).toLowerCase() === 'ios') {
    await browser.execute('mobile: sendBiometricMatch', { type: 'faceId', match: true });
  } else {
    // Android emulator: `adb -e emu finger touch 1` is driven outside WDIO; see wdio.conf.ts notes.
    await browser.execute('mobile: fingerprint', { fingerprintId: 1 });
  }
}
