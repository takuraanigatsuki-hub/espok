/**
 * Запись видеопрезентации ЕПСОК в MP4/WebM
 * Запуск: npm run record:video
 */
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync, mkdirSync } from 'fs';

const __dir = dirname(fileURLToPath(import.meta.url));
const HTML = join(__dir, 'epsok-video', 'index.html');
const OUT_DIR = join(__dir, 'output');
const OUT_WEBM = join(OUT_DIR, 'EPSOK-Demo-Video.webm');
const OUT_MP4 = join(OUT_DIR, 'EPSOK-Demo-Video.mp4');

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

const url = `file:///${HTML.replace(/\\/g, '/')}`;

console.log('Запись видео:', url);

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1920, height: 1080 },
  recordVideo: { dir: OUT_DIR, size: { width: 1920, height: 1080 } }
});
const page = await context.newPage();
page.setDefaultTimeout(120000);
await page.goto(url, { waitUntil: 'load', timeout: 60000 });
await page.waitForFunction(() => document.body.dataset.done === 'true', { timeout: 120000 });
await page.waitForTimeout(1000);

await context.close();
await browser.close();

// Playwright saves webm with random name in OUT_DIR
import { readdirSync, renameSync, unlinkSync } from 'fs';
const webms = readdirSync(OUT_DIR).filter(f => f.endsWith('.webm') && f !== 'EPSOK-Demo-Video.webm');
if (webms.length) {
  const src = join(OUT_DIR, webms[webms.length - 1]);
  if (existsSync(OUT_WEBM)) unlinkSync(OUT_WEBM);
  renameSync(src, OUT_WEBM);
  console.log('✓ WebM:', OUT_WEBM);
}

// Try ffmpeg for MP4
import { spawnSync } from 'child_process';
const ff = spawnSync('ffmpeg', [
  '-y', '-i', OUT_WEBM,
  '-c:v', 'libx264', '-preset', 'medium', '-crf', '22',
  '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
  OUT_MP4
], { stdio: 'pipe' });

if (ff.status === 0) {
  console.log('✓ MP4:', OUT_MP4);
} else {
  console.log('ℹ ffmpeg недоступен — используйте WebM или установите ffmpeg для MP4');
}

console.log('Готово.');
