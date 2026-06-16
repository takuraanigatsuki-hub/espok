// @ts-check
const { test, expect } = require('@playwright/test');
const { login, goToView, openCase } = require('./helpers');

const VIEWPORTS = [
  { name: 'desktop-xl', width: 1440, height: 900 },
  { name: 'laptop', width: 1280, height: 800 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 390, height: 844 },
  { name: 'mobile-sm', width: 360, height: 640 }
];

const APP_VIEWS = ['dashboard', 'cases', 'requests', 'deadlines', 'mail', 'agencies', 'osint', 'help'];

async function assertNoHorizontalOverflow(page, label) {
  const metrics = await page.evaluate(() => {
    const doc = document.documentElement;
    const body = document.body;
    const offenders = [];
    document.querySelectorAll('.view.active, .header, .sidebar, .login-screen, .modal-panel:not(.hidden)').forEach((el) => {
      if (el.scrollWidth > el.clientWidth + 2) {
        offenders.push(`${el.id || el.className}`.slice(0, 80));
      }
    });
    return {
      docOverflow: doc.scrollWidth > doc.clientWidth + 2,
      bodyOverflow: body.scrollWidth > body.clientWidth + 2,
      offenders: offenders.slice(0, 5)
    };
  });
  expect(metrics.docOverflow, `${label}: document overflow ${JSON.stringify(metrics)}`).toBe(false);
  expect(metrics.bodyOverflow, `${label}: body overflow ${JSON.stringify(metrics)}`).toBe(false);
}

test.describe('Адаптивность ЕПСОК', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try {
        localStorage.clear();
        sessionStorage.clear();
      } catch { /* noop */ }
    });
  });

  for (const vp of VIEWPORTS) {
    test(`нет горизонтального переполнения · ${vp.name}`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await login(page);

      for (const viewId of APP_VIEWS) {
        const nav = page.locator(`.nav-item[data-view="${viewId}"]`);
        if (await nav.count() && await nav.isVisible()) {
          await goToView(page, viewId);
          await assertNoHorizontalOverflow(page, `${vp.name}/${viewId}`);
        }
      }

      if (vp.width >= 768) {
        await openCase(page);
        await assertNoHorizontalOverflow(page, `${vp.name}/case-detail`);
      }
    });

    test(`сайдбар · ${vp.name}`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await login(page);

      if (vp.width <= 900) {
        await page.locator('#mobile-nav-toggle').click();
        await expect(page.locator('#app-sidebar')).toHaveClass(/sidebar-mobile-open/);
        const labels = page.locator('#app-sidebar .nav-label');
        await expect(labels.first()).toBeVisible();
        await assertNoHorizontalOverflow(page, `${vp.name}/mobile-nav`);
        await page.locator('#sidebar-backdrop').click({ force: true });
      } else {
        await page.locator('#sidebar-collapse-btn').click();
        await expect(page.locator('#app-sidebar')).toHaveClass(/sidebar-collapsed/);
        await expect(page.locator('#app-sidebar .nav-label').first()).toBeHidden();
        await assertNoHorizontalOverflow(page, `${vp.name}/collapsed`);
      }
    });
  }

  test('экран входа на узком телефоне', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 568 });
    await page.goto('/');
    await assertNoHorizontalOverflow(page, 'login-320');
    await expect(page.locator('#login-screen')).toBeVisible();
  });
});
