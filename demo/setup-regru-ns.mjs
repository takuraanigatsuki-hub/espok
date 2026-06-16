import { chromium } from 'playwright';

const USER = process.env.REG_RU_USER || 'ce120031609';
const PASS = process.env.REG_RU_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const IP = process.env.ESP_OK_HOST || '80.78.245.66';

if (!PASS) {
  console.error('Set REG_RU_PASS');
  process.exit(1);
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

try {
  await page.goto('https://login.reg.ru/', { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.waitForTimeout(3000);

  if (await page.locator('input[type="password"]:visible').count()) {
    await page.locator('input[type="text"]:visible, input[type="email"]:visible').first().fill(USER);
    await page.locator('input[type="password"]:visible').fill(PASS);
    await page.locator('button[type="submit"]:visible').first().click();
    await page.waitForTimeout(12000);
  }

  const afterLogin = await page.locator('body').innerText();
  if (/captcha|SmartCaptcha/i.test(afterLogin)) {
    console.error('CAPTCHA: войдите вручную на login.reg.ru');
    process.exit(2);
  }

  await page.goto(`https://www.reg.ru/user/account/#/card/${DOMAIN}/dns/`, { waitUntil: 'networkidle', timeout: 120000 });
  await page.waitForTimeout(5000);

  let body = await page.locator('body').innerText();
  console.log('DNS page excerpt:', body.replace(/\s+/g, ' ').slice(0, 400));

  if (body.includes(IP)) {
    console.log('A-запись уже указывает на VPS');
  } else {
    const add = page.locator('button:has-text("Добавить"), a:has-text("Добавить запись")').first();
    if (await add.count()) await add.click();
    await page.waitForTimeout(2000);

    for (const sel of ['select:visible', '[role="combobox"]:visible']) {
      const el = page.locator(sel).first();
      if (await el.count()) {
        try { await el.selectOption({ label: 'A' }); } catch { /* */ }
      }
    }

    for (const sub of ['@', 'www']) {
      const inputs = page.locator('input:visible');
      for (let i = 0; i < await inputs.count(); i++) {
        const ph = ((await inputs.nth(i).getAttribute('placeholder')) || '').toLowerCase();
        const name = ((await inputs.nth(i).getAttribute('name')) || '').toLowerCase();
        if (ph.includes('поддомен') || name.includes('subdomain') || name === 'name') {
          await inputs.nth(i).fill(sub === '@' ? '@' : 'www');
        }
        if (ph.includes('ip') || ph.includes('адрес') || name.includes('content')) {
          await inputs.nth(i).fill(IP);
        }
      }
      await page.locator('button:has-text("Сохранить"), button:has-text("Добавить"), button:has-text("Готово")').first().click({ timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(3000);
      console.log(`A ${sub} → ${IP}`);
    }
  }

  await page.goto(`https://www.reg.ru/user/account/#/card/${DOMAIN}/nservers/`, { waitUntil: 'networkidle', timeout: 120000 });
  await page.waitForTimeout(3000);
  body = await page.locator('body').innerText();

  if (!body.includes('ns5.hosting.reg.ru')) {
    const radios = page.locator('label:has-text("ns5"), label:has-text("хостинга"), input[type="radio"]');
    if (await radios.count()) await radios.first().click().catch(() => {});
    const nsInputs = page.locator('input:visible');
    if (await nsInputs.count() >= 2) {
      await nsInputs.nth(0).fill('ns5.hosting.reg.ru').catch(() => {});
      await nsInputs.nth(1).fill('ns6.hosting.reg.ru').catch(() => {});
    }
    await page.locator('button:has-text("Сохранить"), button:has-text("Применить")').first().click({ timeout: 5000 }).catch(() => {});
    await page.waitForTimeout(5000);
    console.log('NS: запрос смены на ns5/ns6 отправлен');
  } else {
    console.log('NS: ns5/ns6 уже указаны');
  }

  console.log('DONE');
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
} finally {
  await browser.close();
}
