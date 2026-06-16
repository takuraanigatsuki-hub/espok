/**
 * REG.RU shared hosting: upload .htaccess (HTTPS redirect) + enable Let's Encrypt.
 * Env: REG_RU_USER, REG_RU_PASS, optional ESP_OK_DOMAIN=epsok.ru
 */
import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USER = process.env.REG_RU_USER || 'ce120031609';
const PASS = process.env.REG_RU_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const HTACCESS = path.join(__dirname, 'public', '.htaccess');

if (!PASS) {
  console.error('Set REG_RU_PASS');
  process.exit(1);
}

async function loginRegRu(page) {
  await page.goto('https://www.reg.ru/user/account/', { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.waitForTimeout(2000);
  const pwd = page.locator('input[type="password"]:visible').first();
  if (await pwd.count()) {
    const login = page.locator('input[type="text"]:visible, input[type="email"]:visible').first();
    await login.fill(USER);
    await pwd.fill(PASS);
    const submit = page.locator('button:has-text("Войти"), button[type="submit"]:visible').first();
    await submit.click({ timeout: 15000 });
    await page.waitForTimeout(10000);
  }
  const body = await page.locator('body').innerText();
  if (/captcha|SmartCaptcha/i.test(body)) {
    throw new Error('CAPTCHA на login.reg.ru');
  }
}

async function tryEnableSslInCard(page) {
  const urls = [
    `https://www.reg.ru/user/account/#/card/${DOMAIN}/hosting/ssl/`,
    `https://www.reg.ru/user/account/#/card/${DOMAIN}/ssl/`,
    `https://www.reg.ru/user/account/#/hosting/`,
  ];
  for (const url of urls) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120000 });
    await page.waitForTimeout(4000);
    const body = await page.locator('body').innerText();
    console.log('SSL page:', url, '→', body.replace(/\s+/g, ' ').slice(0, 200));
    const btn = page.locator(
      'button:has-text("Let"), button:has-text("SSL"), a:has-text("Let"), a:has-text("Выпустить"), button:has-text("Включить"), a:has-text("Включить")'
    ).first();
    if (await btn.count()) {
      await btn.click({ timeout: 8000 }).catch(() => {});
      await page.waitForTimeout(8000);
      console.log('SSL: нажата кнопка выпуска/включения');
      return true;
    }
    if (/активен|установлен|действует|Let's Encrypt/i.test(body)) {
      console.log('SSL: похоже, уже включён');
      return true;
    }
  }
  return false;
}

async function uploadHtaccessIsp(page) {
  await page.goto('https://server176.hosting.reg.ru:1500/ispmgr', { waitUntil: 'domcontentloaded', timeout: 120000 }).catch(() => {});
  await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr', { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.waitForTimeout(2000);
  if (await page.locator('#username').count()) {
    await page.fill('#username', USER);
    await page.fill('#password', PASS);
    await page.click('#submit');
    await page.waitForTimeout(5000);
  }

  // File manager → www/epsok.ru
  await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr?startpage=file', { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.waitForTimeout(3000);

  for (const part of ['www', DOMAIN]) {
    const link = page.locator(`a:has-text("${part}")`).first();
    if (await link.count()) {
      await link.click();
      await page.waitForTimeout(2000);
    }
  }

  // Upload or edit .htaccess
  const upload = page.locator('input[type="file"]').first();
  if (await upload.count()) {
    await upload.setInputFiles(HTACCESS);
    await page.waitForTimeout(2000);
    await page.locator('button:has-text("Ok"), button:has-text("Загрузить"), button:has-text("Upload")').first().click({ timeout: 5000 }).catch(() => {});
    await page.waitForTimeout(5000);
    console.log('ISPmanager: загружен .htaccess');
    return true;
  }

  const ht = page.locator('a:has-text(".htaccess")').first();
  if (await ht.count()) {
    await ht.click();
    await page.waitForTimeout(2000);
    const edit = page.locator('a:has-text("Edit"), button:has-text("Edit"), a:has-text("Редактировать")').first();
    if (await edit.count()) {
      await edit.click();
      await page.waitForTimeout(2000);
      const ta = page.locator('textarea:visible').first();
      if (await ta.count()) {
        await ta.fill(fs.readFileSync(HTACCESS, 'utf8'));
        await page.locator('button:has-text("Ok"), button:has-text("Сохранить")').first().click();
        await page.waitForTimeout(3000);
        console.log('ISPmanager: обновлён .htaccess через редактор');
        return true;
      }
    }
  }

  return false;
}

async function uploadHtaccessFtp() {
  const hosts = ['u3548413.hosting.reg.ru', 'server176.hosting.reg.ru'];
  const users = ['u3548413', USER];
  const remote = `/www/${DOMAIN}/.htaccess`;
  const local = HTACCESS.replace(/\\/g, '/');
  for (const host of hosts) {
    for (const user of users) {
      const url = `ftp://${encodeURIComponent(user)}:${encodeURIComponent(PASS)}@${host}${remote}`;
      try {
        const { execSync } = await import('child_process');
        execSync(`curl.exe --ftp-create-dirs -T "${local}" "${url}"`, { stdio: 'pipe', timeout: 30000 });
        console.log(`FTP OK: ${user}@${host} → ${remote}`);
        return true;
      } catch (e) {
        console.log(`FTP fail ${user}@${host}:`, e.stderr?.toString() || e.message);
      }
    }
  }
  return false;
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

try {
  console.log('1) Вход REG.RU…');
  await loginRegRu(page);

  console.log('2) SSL Lets Encrypt…');
  await tryEnableSslInCard(page);

  console.log('3) Загрузка .htaccess…');
  let uploaded = await uploadHtaccessFtp().catch(() => false);
  if (!uploaded) uploaded = await uploadHtaccessIsp(page);

  if (!uploaded) throw new Error('Не удалось загрузить .htaccess (FTP и ISPmanager)');

  console.log('4) Проверка редиректа…');
  await page.waitForTimeout(5000);
  const res = await page.goto(`http://${DOMAIN}/`, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => null);
  const finalUrl = page.url();
  console.log('HTTP →', finalUrl, res?.status());

  console.log('\nГотово. Откройте https://' + DOMAIN + '/ и обновите Ctrl+F5');
} catch (e) {
  console.error('Ошибка:', e.message || e);
  process.exit(1);
} finally {
  await browser.close();
}
