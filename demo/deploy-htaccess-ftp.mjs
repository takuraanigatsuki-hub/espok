/**
 * Upload .htaccess to REG.RU hosting via FTP (no browser).
 * Env: FTP_PASS or REG_RU_FTP_PASS
 */
import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PASS = process.env.FTP_PASS || process.env.REG_RU_FTP_PASS;
const USER = process.env.FTP_USER || 'u3548413';
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const LOCAL = path.join(__dirname, 'public', '.htaccess');

if (!PASS) {
  console.error('Set FTP_PASS or REG_RU_FTP_PASS');
  process.exit(1);
}

const hosts = [process.env.FTP_HOST || 'server299.hosting.reg.ru', '31.31.197.50'];
const remotes = [`/www/${DOMAIN}/.htaccess`, `/data/www/${DOMAIN}/.htaccess`];
const localWin = LOCAL.replace(/\\/g, '/');
const passEnc = encodeURIComponent(PASS);

for (const host of hosts) {
  for (const remote of remotes) {
    const url = `ftp://${encodeURIComponent(USER)}:${passEnc}@${host}${remote}`;
    try {
      execSync(`curl.exe -sS --ftp-create-dirs -T "${localWin}" "${url}"`, { stdio: 'pipe', timeout: 60000 });
      console.log(`OK: ${USER}@${host}${remote}`);
      process.exit(0);
    } catch (e) {
      const err = e.stderr?.toString() || e.message;
      console.log(`fail ${USER}@${host}${remote}:`, err.slice(0, 140));
    }
  }
}

console.error('FTP upload failed on all paths');
process.exit(1);
