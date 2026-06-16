/**
 * Full upload demo/public → REG.RU hosting via FTP.
 * Env: FTP_PASS or REG_RU_FTP_PASS
 * Optional: FTP_USER, FTP_HOST, ESP_OK_DOMAIN
 */
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PASS = process.env.FTP_PASS || process.env.REG_RU_FTP_PASS;
const USER = process.env.FTP_USER || 'u3548413';
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const LOCAL_DIR = path.join(__dirname, 'public');
const SKIP = new Set(['.htpasswd', '.htpasswd.example']);

if (!PASS) {
  console.error('Set FTP_PASS or REG_RU_FTP_PASS');
  process.exit(1);
}

const hosts = [process.env.FTP_HOST || 'server299.hosting.reg.ru', '31.31.197.50'];
const remoteRoots = [`/www/${DOMAIN}`, `/data/www/${DOMAIN}`];
const passEnc = encodeURIComponent(PASS);

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const files = walk(LOCAL_DIR);
let uploaded = 0;

for (const host of hosts) {
  for (const root of remoteRoots) {
    let ok = 0;
    for (const local of files) {
      const rel = path.relative(LOCAL_DIR, local).split(path.sep).join('/');
      const remote = `${root}/${rel}`;
      const localWin = local.replace(/\\/g, '/');
      const url = `ftp://${encodeURIComponent(USER)}:${passEnc}@${host}${remote}`;
      try {
        execSync(`curl.exe -sS --ftp-create-dirs -T "${localWin}" "${url}"`, { stdio: 'pipe', timeout: 120000 });
        ok++;
        uploaded++;
        process.stdout.write(`  ↑ ${rel}\n`);
      } catch (e) {
        const err = e.stderr?.toString() || e.message;
        console.error(`fail ${rel} @ ${host}:`, err.slice(0, 120));
        break;
      }
    }
    if (ok === files.length) {
      console.log(`\nOK: ${ok} files → ${USER}@${host}${root}`);
      process.exit(0);
    }
  }
}

console.error(`FTP upload incomplete (${uploaded}/${files.length * remoteRoots.length * hosts.length} attempts)`);
process.exit(1);
