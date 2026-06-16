// @ts-check
const { test, expect } = require('@playwright/test');
const { login, logout, goToView, openCase, DEMO_CASE, DEMO_PASS } = require('./helpers');

test.describe('ЕПСОК MVP e2e', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try {
        localStorage.clear();
        sessionStorage.clear();
      } catch { /* noop */ }
    });
  });

  test('экран входа и успешный логин следователя', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#login-screen')).toBeVisible();
    await expect(page.locator('#app-root')).toBeHidden();

    await page.locator('#login-user').fill('ivanov.sp');
    await page.locator('#login-pass').fill(DEMO_PASS);
    await page.locator('#login-submit-btn').click();

    await page.waitForFunction(() => document.documentElement.dataset.auth === 'app');
    await expect(page.locator('#view-dashboard.active')).toBeVisible();
    await expect(page.locator('#dash-investigator-kpi')).not.toBeEmpty();
  });

  test('неверный пароль показывает ошибку', async ({ page }) => {
    await page.goto('/');
    await page.locator('#login-user').fill('ivanov.sp');
    await page.locator('#login-pass').fill('wrong-password');
    await page.locator('#login-submit-btn').click();

    const err = page.locator('#login-error');
    await expect(err).toBeVisible();
    await expect(err).toContainText(/неверн/i);
    await expect(page.locator('#app-root')).toBeHidden();
  });

  test('реестр дел → карточка дела', async ({ page }) => {
    await login(page);
    await openCase(page, DEMO_CASE);

    await expect(page.locator('#case-detail-root .case-id')).toHaveText(DEMO_CASE);
    await expect(page.getByRole('button', { name: 'Справка (TXT)' })).toBeVisible();
  });

  test('экспорт справки по делу (TXT)', async ({ page }) => {
    await login(page);
    await openCase(page, DEMO_CASE);

    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Справка (TXT)' }).click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/EPSOK-.*spravka\.txt$/i);
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('глобальный поиск открывает дело', async ({ page }) => {
    await login(page);
    await page.locator('#global-search-input').click();
    await page.locator('#global-search-input').fill('004521');
    await page.locator('.global-search-item').first().waitFor({ state: 'visible' });
    await page.locator('.global-search-item').first().click();

    await expect(page.locator('#view-case.active')).toBeVisible();
    await expect(page.locator('#case-detail-root')).toContainText('004521');
  });

  test('навигация по разделам из бокового меню', async ({ page }) => {
    await login(page);

    await goToView(page, 'requests');
    await expect(page.locator('#view-requests.active')).toBeVisible();

    await goToView(page, 'deadlines');
    await expect(page.locator('#view-deadlines.active')).toBeVisible();

    await goToView(page, 'dashboard');
    await expect(page.locator('#view-dashboard.active')).toBeVisible();
  });

  test('выход возвращает на экран входа', async ({ page }) => {
    await login(page);
    await logout(page);
    await expect(page.locator('#login-screen')).toBeVisible();
    await expect(page.locator('#app-root')).toBeHidden();
  });

  test('быстрая блокировка (lockNow)', async ({ page }) => {
    await login(page);
    await page.locator('#user-info-btn').click();
    await page.getByRole('button', { name: 'Заблокировать' }).click();

    await page.waitForFunction(() => document.documentElement.dataset.auth === 'login');
    await expect(page.locator('#login-screen')).toBeVisible();
  });
});
