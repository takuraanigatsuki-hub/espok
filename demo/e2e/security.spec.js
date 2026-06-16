// @ts-check
const { test, expect } = require('@playwright/test');
const { login } = require('./helpers');

test.describe('ЕПСОК security e2e', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try {
        localStorage.clear();
        sessionStorage.clear();
      } catch { /* noop */ }
    });
  });

  test('security headers на index.html', async ({ page }) => {
    const response = await page.goto('/');
    expect(response?.ok()).toBeTruthy();

    const headers = response?.headers() || {};
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['content-security-policy']).toContain("default-src 'self'");
  });

  test('санитизация вредоносного hash не открывает произвольный view', async ({ page }) => {
    await login(page);
    await page.goto('/#view=<script>alert(1)</script>&case=foo"bar');

    await expect(page.locator('#view-dashboard.active')).toBeVisible();
    await page.evaluate(() => {
      const alerts = [];
      window.alert = (m) => alerts.push(m);
      return alerts.length;
    }).then((n) => expect(n).toBe(0));
  });

  test('privacy veil при смене вкладки', async ({ page, context }) => {
    await login(page);
    const second = await context.newPage();
    await second.goto('/');

    await expect(page.locator('#privacy-veil')).toBeHidden();
    await page.evaluate(() => Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true }));
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));

    await expect(page.locator('#privacy-veil')).toBeVisible();
    await second.close();
  });

  test('ivanov не может эскалироваться в тех. админа', async ({ page }) => {
    await login(page, 'ivanov.sp');
    await page.evaluate(() => {
      if (typeof selectDemoPersona === 'function') selectDemoPersona('TECH_ADMIN');
    });
    const personaId = await page.evaluate(() => getActivePersona().id);
    expect(personaId).toBe('INV_MVD');
    await expect(page.locator('.nav-admin')).toBeHidden();
  });

  test('sidorov не видит смену роли в меню', async ({ page }) => {
    await login(page, 'sidorov.av');
    await page.locator('#user-info-btn').click();
    await expect(page.getByRole('button', { name: 'Сменить роль' })).toBeHidden();
    await expect(page.locator('.demo-badge-btn')).toBeHidden();
  });
});
