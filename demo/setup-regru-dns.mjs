import { Client } from 'ssh2';

const USER = process.env.REG_RU_USER || 'ce120031609';
const PASS = process.env.REG_RU_PASS;
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const IP = process.env.ESP_OK_HOST || '80.78.245.66';
const SSH_PASS = process.env.ESP_OK_DEPLOY_PASS;

if (!PASS || !SSH_PASS) {
  console.error('Set REG_RU_PASS and ESP_OK_DEPLOY_PASS');
  process.exit(1);
}

function exec(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      stream.on('data', d => { out += d; process.stdout.write(d); });
      stream.stderr.on('data', d => process.stderr.write(d));
      stream.on('close', code => resolve({ code, out }));
    });
  });
}

async function apiFromVps(conn, func, input) {
  const json = JSON.stringify({ username: USER, password: PASS, output_content_type: 'plain', ...input });
  const b64 = Buffer.from(json).toString('base64');
  const { out } = await exec(
    conn,
    `echo '${b64}' | base64 -d > /tmp/regru-req.json && curl -s -X POST 'https://api.reg.ru/api/regru2/${func}' --data-urlencode "input_data@/tmp/regru-req.json" -d 'input_format=json' && rm -f /tmp/regru-req.json`
  );
  return out.trim();
}

const conn = new Client();
conn.on('ready', async () => {
  try {
    console.log('1) A-записи @ и www на текущих NS…');
    for (const sub of ['@', 'www']) {
      const r = await apiFromVps(conn, 'zone/add_alias', {
        domains: [{ dname: DOMAIN }],
        subdomain: sub,
        ipaddr: IP,
      });
      console.log(`   ${sub}:`, r);
    }

    console.log('\n2) Смена NS на ns5/ns6…');
    const nss = await apiFromVps(conn, 'domain/update_nss', {
      domains: [{ dname: DOMAIN }],
      nss: 'ns5.hosting.reg.ru ns6.hosting.reg.ru',
    });
    console.log('   NS:', nss);

    console.log('\n3) Проверка с VPS…');
    await exec(conn, `sleep 3; getent hosts ${DOMAIN} || true`);
    await exec(conn, `dig +short ${DOMAIN} @8.8.8.8 2>/dev/null || nslookup ${DOMAIN} 8.8.8.8 | tail -3`);

    conn.end();
  } catch (e) {
    console.error(e.message || e);
    conn.end();
    process.exit(1);
  }
});

conn.connect({ host: IP, port: 22, username: 'root', password: SSH_PASS, readyTimeout: 30000 });
