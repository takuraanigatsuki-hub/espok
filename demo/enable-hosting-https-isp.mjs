/**
 * ISPmanager: enable "Redirect HTTP-requests to HTTPS" for epsok.ru
 * Env: ISP_PASS
 */
import { chromium } from 'playwright';
import { execSync } from 'child_process';

const ISP_PASS = process.env.ISP_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const HOST = process.env.FTP_HOST || 'server299.hosting.reg.ru';

if (!ISP_PASS) {
  console.error('Set ISP_PASS');
  process.exit(1);
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

try {
  await page.goto(`https://${HOST}:1500/ispmgr`, { waitUntil: 'networkidle', timeout: 120000 });
  await page.locator('input[type=text]').first().fill('u3548413');
  await page.locator('input[type=password]').first().fill(ISP_PASS);
  await page.locator('button').filter({ hasText: /log in/i }).first().click();
  await page.waitForTimeout(8000);

  await page.goto(`https://${HOST}:1500/ispmgr#/form?func=webdomain.edit&elid=${DOMAIN}`, {
    waitUntil: 'networkidle',
    timeout: 120000,
  });
  await page.waitForTimeout(5000);

  const redirectLabel = page.getByText('Redirect HTTP-requests to HTTPS', { exact: true });
  const isChecked = await page.evaluate(() => {
    const label = [...document.querySelectorAll('label')].find(l =>
      (l.textContent || '').includes('Redirect HTTP-requests to HTTPS')
    );
    return label?.querySelector('input[type=checkbox]')?.checked;
  });

  if (!isChecked) {
    await redirectLabel.click({ force: true });
    await page.waitForTimeout(500);
  }

  const nowChecked = await page.evaluate(() => {
    const label = [...document.querySelectorAll('label')].find(l =>
      (l.textContent || '').includes('Redirect HTTP-requests to HTTPS')
    );
    return label?.querySelector('input[type=checkbox]')?.checked;
  });
  console.log('Redirect checked before save:', nowChecked);
  if (!nowChecked) throw new Error('Checkbox not checked');

  await page.locator('button').filter({ hasText: /^Save$/ }).click({ force: true });
  await page.waitForTimeout(10000);

  const bodyAfter = await page.locator('body').innerText();
  if (/error|failed|ошибк/i.test(bodyAfter)) {
    console.log('Page after save:', bodyAfter.replace(/\s+/g, ' ').slice(0, 400));
  }

  // Reload form and verify persistence
  await page.goto(`https://${HOST}:1500/ispmgr#/form?func=webdomain.edit&elid=${DOMAIN}`, {
    waitUntil: 'networkidle',
    timeout: 120000,
  });
  await page.waitForTimeout(5000);

  const persisted = await page.evaluate(() => {
    const label = [...document.querySelectorAll('label')].find(l =>
      (l.textContent || '').includes('Redirect HTTP-requests to HTTPS')
    );
    return label?.querySelector('input[type=checkbox]')?.checked;
  });
  console.log('Redirect persisted:', persisted);

  const headers = execSync('curl.exe -sI "http://epsok.ru/"', { encoding: 'utf8' });
  console.log(headers.split('\n').filter(l => /^(HTTP|Location)/i.test(l)).join('\n'));
} catch (e) {
  console.error('Error:', e.message);
  process.exit(1);
} finally {
  await browser.close();
}
