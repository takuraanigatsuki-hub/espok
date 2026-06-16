import { execSync, spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const TARGET_IP = process.env.ESP_OK_HOST || '80.78.245.66';
const MAX_WAIT_MS = Number(process.env.ESP_OK_DNS_WAIT_MS || 30 * 60 * 1000);
const INTERVAL_MS = 30_000;

function resolveIp() {
  try {
    const out = execSync(`nslookup ${DOMAIN} 8.8.8.8`, { encoding: 'utf8', timeout: 15_000 });
    const block = out.split(/Name:\s+/i).find(p => p.toLowerCase().startsWith(DOMAIN.toLowerCase()));
    if (block) {
      const m = block.match(/Address:\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (m) return m[1];
    }
    const all = [...out.matchAll(/Address:\s+(\d+\.\d+\.\d+\.\d+)/gi)].map(x => x[1]);
    return all.length ? all[all.length - 1] : null;
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  const start = Date.now();
  console.log(`Ожидание DNS: ${DOMAIN} → ${TARGET_IP} (до ${MAX_WAIT_MS / 60000} мин)…`);
  console.log('Пока смените NS в REG.RU: ns5.hosting.reg.ru, ns6.hosting.reg.ru\n');

  while (Date.now() - start < MAX_WAIT_MS) {
    const ip = resolveIp();
    const elapsed = Math.round((Date.now() - start) / 1000);
    if (ip === TARGET_IP) {
      console.log(`\nDNS готов (${elapsed}s): ${DOMAIN} → ${ip}`);
      await new Promise((resolve, reject) => {
        const child = spawn('node', ['setup-epsok-domain.mjs'], {
          cwd: __dirname,
          stdio: 'inherit',
          env: process.env,
          shell: true
        });
        child.on('close', code => (code ? reject(new Error(`setup exit ${code}`)) : resolve()));
      });
      return;
    }
    console.log(`[${elapsed}s] ${DOMAIN} → ${ip || 'нет A-записи'} (нужно ${TARGET_IP})`);
    await sleep(INTERVAL_MS);
  }

  console.error('\nТаймаут: DNS ещё не указывает на VPS. Смените NS и запустите снова: node wait-dns-and-https.mjs');
  process.exit(1);
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
