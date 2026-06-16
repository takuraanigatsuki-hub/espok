import { chromium } from 'playwright';

const USER = process.env.REG_RU_USER || 'ce120031609';
const PASS = process.env.REG_RU_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const IP = process.env.ESP_OK_HOST || '80.78.245.66';

if (!PASS) {
  console.error('Set REG_RU_PASS');
  process.exit(1);
}

async function loginIsp(page) {
  await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr?theme=orion', { waitUntil: 'domcontentloaded' });
  if (await page.locator('#username').count()) {
    await page.fill('#username', USER);
    await page.fill('#password', PASS);
    await page.click('#submit');
    await page.waitForTimeout(5000);
  }
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

try {
  await loginIsp(page);
  await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr?startpage=domain', { waitUntil: 'networkidle', timeout: 120000 });
  await page.waitForTimeout(4000);

  if (!(await page.locator(`text=${DOMAIN}`).count())) {
    await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr?startform=domain.edit', { waitUntil: 'networkidle' });
    await page.waitForTimeout(2000);
    await page.locator('input[name="name"]:visible').fill(DOMAIN);
    await page.locator('input[name="ip"]:visible').fill(IP);
    await page.locator('input[name="maildomain"]').uncheck().catch(() => {});
    await page.locator('button:has-text("Ok")').click();
    await page.waitForTimeout(8000);
  }

  await page.goto('https://dnsadmin.hosting.reg.ru/manager/ispmgr?startpage=domain', { waitUntil: 'networkidle' });
  await page.locator(`text=${DOMAIN}`).first().click();
  await page.waitForTimeout(1000);
  await page.locator('a').filter({ hasText: /^Records$/ }).first().click();
  await page.waitForTimeout(6000);

  let body = await page.locator('body').innerText();
  console.log('Records:', body.replace(/\s+/g, ' ').slice(0, 2000));

  for (const sub of ['@', 'www']) {
    if (body.includes(IP) && (sub === '@' || body.includes('www'))) {
      console.log(`Check ${sub}: may exist`);
    }
    await page.locator('a[data-func="domain.record.edit"], .toolbar a:has-text("Add")').first().click();
    await page.waitForTimeout(2000);
    const typeSel = page.locator('select[name="rtype"]').first();
    if (await typeSel.count()) await typeSel.selectOption('A').catch(() => {});
    const nameInput = page.locator('input[name="name"]').first();
    if (await nameInput.count()) await nameInput.fill(sub);
    const ipInput = page.locator('input[name="ip"]').first();
    if (await ipInput.count()) await ipInput.fill(IP);
    await page.locator('button:has-text("Ok")').click();
    await page.waitForTimeout(8000);
    body = await page.locator('body').innerText();
    console.log(`After ${sub}:`, body.includes(IP) ? 'OK' : 'check failed');
  }

  console.log('ISPmanager DNS zone ready on ns5/ns6');
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
} finally {
  await browser.close();
}
