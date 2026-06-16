// @ts-check
const { defineConfig, devices } = require('@playwright/test');

const PORT = process.env.EPSOK_PORT || 3000;
const BASE_URL = process.env.EPSOK_BASE_URL || `http://127.0.0.1:${PORT}`;

module.exports = defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 45_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure'
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } }
  ],
  webServer: process.env.EPSOK_BASE_URL
    ? undefined
    : {
        command: `npx serve public -p ${PORT} -c serve.json`,
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000
      }
});
