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
        if (code !== 0 && !allowFail) reject(new Error(`Failed (${code}): ${cmd}`));
        else resolve(out);
      });
    });
  });
}

const nginxConf = `server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${REMOTE_DIR};
    index index.html;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~* \\.(js|css|svg|png|jpg|woff2?)$ {
        expires 1h;
        add_header Cache-Control "public";
    }
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root ${REMOTE_DIR};
    index index.html;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
`;

const conn = new Client();
conn.on('ready', async () => {
  try {
    const aptEnv = 'export DEBIAN_FRONTEND=noninteractive';
    const aptOpts = '-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"';

    console.log(`Configuring nginx for ${DOMAIN}…`);
    await exec(conn, `cat > /etc/nginx/sites-available/epsok << 'NGINXEOF'\n${nginxConf}\nNGINXEOF`);
    await exec(conn, 'ln -sf /etc/nginx/sites-available/epsok /etc/nginx/sites-enabled/epsok');
    await exec(conn, 'rm -f /etc/nginx/sites-enabled/default');
    await exec(conn, 'nginx -t && systemctl reload nginx');

    console.log('Checking DNS…');
    const dns = await exec(conn, `getent hosts ${DOMAIN} 2>/dev/null || true`, { allowFail: true });
    const ipOk = dns.includes(HOST);

    if (!ipOk) {
      console.log(`\nDNS: ${DOMAIN} ещё не указывает на ${HOST}.`);
      console.log('В REG.RU после регистрации домена добавьте A-записи:');
      console.log(`  @   → ${HOST}`);
      console.log(`  www → ${HOST}`);
      console.log(`\nЗатем снова: ESP_OK_DOMAIN=${DOMAIN} node setup-epsok-domain.mjs`);
      conn.end();
      return;
    }

    console.log('DNS OK. Installing certbot…');
    await exec(conn, `${aptEnv}; apt-get update -qq`);
    await exec(conn, `${aptEnv}; apt-get install -y -qq ${aptOpts} certbot python3-certbot-nginx`);

    console.log('Requesting HTTPS certificate…');
    await exec(
      conn,
      `${aptEnv}; certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email --redirect`,
      { allowFail: true }
    );

    await exec(conn, `curl -sI http://${DOMAIN}/ | head -5 || true`, { allowFail: true });
    await exec(conn, `curl -skI https://${DOMAIN}/ | head -5 || true`, { allowFail: true });

    console.log(`\nГотово: http://${DOMAIN}/ и https://${DOMAIN}/`);
    conn.end();
  } catch (e) {
    console.error(e.message || e);
    conn.end();
    process.exit(1);
  }
});

conn.connect({ host: HOST, port: 22, username: 'root', password: PASS, readyTimeout: 30000 });
