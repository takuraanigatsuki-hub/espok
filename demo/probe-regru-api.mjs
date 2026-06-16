/**
 * REG.RU API: проверка доступа, список услуг, попытка включить SSL.
 */
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const USER = process.env.REG_RU_USER || 'ce120031609';
const PASS = process.env.REG_RU_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';

if (!PASS) {
  console.error('Set REG_RU_PASS');
  process.exit(1);
}

function api(func, input = {}) {
  const payload = { username: USER, password: PASS, output_content_type: 'plain', ...input };
  const tmp = path.join(os.tmpdir(), `regru-${Date.now()}.json`);
  fs.writeFileSync(tmp, JSON.stringify(payload));
  try {
    const out = execSync(
      `curl.exe -s -X POST "https://api.reg.ru/api/regru2/${func}" -d "input_format=json" -d "output_format=json" --data-urlencode "input_data@${tmp}"`,
      { encoding: 'utf8', timeout: 60000 }
    );
    return out.trim();
  } finally {
    fs.unlinkSync(tmp);
  }
}

console.log('1) API login…');
console.log(api('nop'));

console.log('\n2) Услуги домена…');
console.log(api('domain/get_services', { domains: [{ dname: DOMAIN }] }));

console.log('\n3) Список SSL (если есть)…');
for (const fn of ['service/get_list', 'ssl/get_prices', 'service/order']) {
  try {
    const r = api(fn, fn === 'service/get_list' ? { servtype: 'srv_hosting_ispmgr' } : {});
    console.log(fn + ':', r.slice(0, 400));
  } catch (e) {
    console.log(fn + ' error:', e.message);
  }
}

console.log('\nГотово. Если API OK — включите Let\'s Encrypt в панели хостинга или добавьте IP в whitelist API.');
