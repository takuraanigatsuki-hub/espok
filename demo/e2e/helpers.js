// @ts-check

/** @typedef {import('@playwright/test').Page} Page */

const DEMO_USER = process.env.EPSOK_USER || 'ivanov.sp';
const DEMO_PASS = process.env.EPSOK_PASS || 'epsok2028';
const DEMO_CASE = process.env.EPSOK_CASE || 'ЕПСОК-2028-004521';

/**
 * @param {Page} page
 */
async function login(page, username = DEMO_USER, password = DEMO_PASS) {
  await page.goto('/');
  await page.waitForSelector('#login-screen', { state: 'visible' });
  await page.locator('#login-user').fill(username);
  await page.locator('#login-pass').fill(password);
  await page.locator('#login-submit-btn').click();
  await expectAppShell(page);
}

/**
 * @param {Page} page
 */
async function expectAppShell(page) {
  await page.waitForFunction(() => document.documentElement.dataset.auth === 'app');
  await page.locator('#app-root').waitFor({ state: 'visible' });
  await page.locator('#login-screen').waitFor({ state: 'hidden' });
}

/**
 * @param {Page} page
 */
async function logout(page) {
  await page.locator('#user-info-btn').click();
  await page.getByRole('button', { name: 'Выйти' }).click();
  await page.waitForFunction(() => document.documentElement.dataset.auth === 'login');
  await page.locator('#login-screen').waitFor({ state: 'visible' });
}

/**
 * @param {Page} page
 * @param {string} viewId
 */
async function goToView(page, viewId) {
  const usedApi = await page.evaluate((v) => {
    if (typeof showView !== 'function') return false;
    showView(v);
    return true;
  }, viewId);
  if (!usedApi) {
    const isMobile = await page.evaluate(() => window.matchMedia('(max-width: 900px)').matches);
    if (isMobile) {
      const sidebar = page.locator('#app-sidebar');
      const open = await sidebar.evaluate((el) => el.classList.contains('sidebar-mobile-open'));
      if (!open) await page.locator('#mobile-nav-toggle').click();
    }
    await page.locator(`.nav-item[data-view="${viewId}"]`).click({ force: isMobile });
    if (isMobile) {
      await page.locator('#sidebar-backdrop').click({ force: true }).catch(() => {});
    }
  }
  await page.locator(`#view-${viewId}.active`).waitFor({ state: 'visible' });
}

/**
 * @param {Page} page
 * @param {string} caseId
 */
async function openCase(page, caseId = DEMO_CASE) {
  const opened = await page.evaluate((id) => {
    if (typeof window.openCase === 'function') {
      window.openCase(id);
      return true;
    }
    return false;
  }, caseId);
  if (!opened) {
    await goToView(page, 'cases');
    const needle = caseId.replace(/^ЕПСОК-/, '').slice(-6);
    const search = page.locator('#cases-registry-search');
    if (await search.count()) await search.fill(needle);
    const rowBtn = page.locator('#cases-table-body').getByRole('button', { name: caseId, exact: true });
    if (await rowBtn.count()) {
      await rowBtn.first().click();
    } else {
      await page.locator('#global-search-input').fill(needle);
      await page.locator('.global-search-item').first().waitFor({ state: 'visible' });
      await page.locator('.global-search-item').first().click();
    }
  }
  await page.locator('#view-case.active').waitFor({ state: 'visible' });
  await page.locator('#case-detail-root .case-id', { hasText: caseId }).waitFor({ state: 'visible' });
}

module.exports = {
  DEMO_USER,
  DEMO_PASS,
  DEMO_CASE,
  login,
  logout,
  expectAppShell,
  goToView,
  openCase
};
