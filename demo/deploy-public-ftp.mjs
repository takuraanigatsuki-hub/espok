/**
 * Full upload demo/public → REG.RU hosting via FTP.
 * Env: FTP_PASS or REG_RU_FTP_PASS
 * Optional: FTP_USER, FTP_HOST
 */
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PASS = process.env.FTP_PASS || process.env.REG_RU_FTP_PASS;
const USER = process.env.FTP_USER || 'u3548413';
const LOCAL_DIR = path.join(__dirname, 'public');
const SKIP = new Set(['.htpasswd', '.htpasswd.example']);
const CURL = process.platform === 'win32' ? 'curl.exe' : 'curl';

if (!PASS) {
  console.error('Set FTP_PASS or REG_RU_FTP_PASS');
  process.exit(1);
}

const hosts = [process.env.FTP_HOST || '31.31.197.50', 'server299.hosting.reg.ru'];
const remoteRoots = ['/'];
const passEnc = encodeURIComponent(PASS);
const baseUrl = (host) => `ftp://${encodeURIComponent(USER)}:${passEnc}@${host}`;

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

function uploadFile(host, remote, localPath) {
  const localSize = fs.statSync(localPath).size;
  if (localSize === 0) {
    throw new Error(`Refusing to upload empty local file: ${localPath}`);
  }
  const url = `${baseUrl(host)}${remote}`;
  // Remove corrupted zero-byte leftovers before upload
  execSync(`${CURL} -sS --quote "DELE ${remote}" "${baseUrl(host)}/"`, { stdio: 'pipe', timeout: 60000 });
  execSync(
    `${CURL} -sS --ftp-create-dirs --connect-timeout 30 --max-time 300 -T "${localPath}" "${url}"`,
    { stdio: 'pipe', timeout: 360000 }
  );
}

const files = walk(LOCAL_DIR);
let uploaded = 0;

for (const host of hosts) {
  for (const root of remoteRoots) {
    let ok = 0;
    for (const local of files) {
      const rel = path.relative(LOCAL_DIR, local).split(path.sep).join('/');
      const remote = `${root}/${rel}`.replace(/\/+/g, '/');
      const localPath = local.replace(/\\/g, '/');
      try {
        uploadFile(host, remote, localPath);
        ok++;
        uploaded++;
        process.stdout.write(`  ↑ ${rel} (${fs.statSync(localPath).size} B)\n`);
      } catch (e) {
        const err = e.stderr?.toString() || e.message;
        console.error(`fail ${rel} @ ${host}:`, err.slice(0, 200));
        break;
      }
    }
    if (ok === files.length) {
      console.log(`\nOK: ${ok} files → ${USER}@${host}${root}`);
      process.exit(0);
    }
  }
}

console.error(`FTP upload incomplete (${uploaded}/${files.length} uploaded before failure)`);
process.exit(1);
