import { Client } from 'ssh2';

const HOST = process.env.ESP_OK_HOST || '80.78.245.66';
const DOMAIN = process.env.ESP_OK_DOMAIN || 'epsok.ru';
const PASS = process.env.ESP_OK_DEPLOY_PASS;
const REMOTE_DIR = '/var/www/epsok';

if (!PASS) {
  console.error('Set ESP_OK_DEPLOY_PASS');
  process.exit(1);
}

function exec(conn, cmd, { allowFail = false } = {}) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      stream.on('data', d => { out += d; process.stdout.write(d); });
      stream.stderr.on('data', d => process.stderr.write(d));
      stream.on('close', code => {
        if (code !== 0 && !allowFail) reject(new Error(`exit ${code}`));
        else resolve(out);
      });
    });
  });
}

const conn = new Client();
conn.on('ready', async () => {
  try {
    console.log('DNS check…');
    const dns = await exec(conn, `getent ahostsv4 ${DOMAIN} | awk '{print $1}' | head -1`, { allowFail: true });
    const ip = dns.trim();
    console.log(`${DOMAIN} → ${ip || 'unknown'} (need ${HOST})`);

    if (ip !== HOST) {
      console.log('\nDNS ещё на REG.RU хостинге. Для HTTPS на VPS смените A-запись @ и www →', HOST);
      console.log('После смены DNS запустите: ESP_OK_DEPLOY_PASS=… node enable-https-vps.mjs');
      conn.end();
      return;
    }

    console.log('Installing certbot…');
    const aptEnv = 'export DEBIAN_FRONTEND=noninteractive';
    await exec(conn, `${aptEnv}; apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx`, { allowFail: true });

    console.log('Requesting certificate…');
    await exec(
      conn,
      `${aptEnv}; certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email --redirect`,
      { allowFail: true }
    );

    await exec(conn, `curl -sI http://${DOMAIN}/ | head -8`, { allowFail: true });
    await exec(conn, `curl -skI https://${DOMAIN}/ | head -8`, { allowFail: true });
    console.log('\nГотово: https://' + DOMAIN + '/');
    conn.end();
  } catch (e) {
    console.error(e.message || e);
    conn.end();
    process.exit(1);
  }
});

conn.connect({ host: HOST, port: 22, username: 'root', password: PASS, readyTimeout: 30000 });
