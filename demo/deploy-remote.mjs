import { Client } from 'ssh2';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOST = process.env.ESP_OK_HOST || '80.78.245.66';
const USER = process.env.ESP_OK_USER || 'root';
const PASS = process.env.ESP_OK_DEPLOY_PASS;
const LOCAL_DIR = path.join(__dirname, 'public');
const REMOTE_DIR = '/var/www/epsok';

if (!PASS) {
  console.error('Set ESP_OK_DEPLOY_PASS environment variable.');
  process.exit(1);
}

function exec(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      let errOut = '';
      stream.on('data', d => { out += d; process.stdout.write(d); });
      stream.stderr.on('data', d => { errOut += d; process.stderr.write(d); });
      stream.on('close', code => {
        if (code !== 0) reject(new Error(`Command failed (${code}): ${cmd}\n${errOut}`));
        else resolve(out);
      });
    });
  });
}

function sftpMkdir(sftp, dir) {
  return new Promise((resolve, reject) => {
    sftp.mkdir(dir, err => {
      if (err && err.code !== 4) reject(err);
      else resolve();
    });
  });
}

async function uploadDir(sftp, localDir, remoteDir) {
  await sftpMkdir(sftp, remoteDir);
  for (const entry of fs.readdirSync(localDir, { withFileTypes: true })) {
    const localPath = path.join(localDir, entry.name);
    const remotePath = `${remoteDir}/${entry.name}`;
    if (entry.isDirectory()) {
      await uploadDir(sftp, localPath, remotePath);
    } else {
      await new Promise((resolve, reject) => {
        sftp.fastPut(localPath, remotePath, err => (err ? reject(err) : resolve()));
      });
      console.log(`  ↑ ${entry.name}`);
    }
  }
}

const nginxConf = `server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
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
`;

const conn = new Client();

conn.on('ready', async () => {
  try {
    console.log('Connected. Installing nginx if needed…');
    const aptEnv = 'export DEBIAN_FRONTEND=noninteractive';
    const aptOpts = '-o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"';
    await exec(conn, `${aptEnv}; apt-get update -qq`);
    await exec(conn, `${aptEnv}; dpkg --configure -a ${aptOpts} 2>/dev/null || true`);
    await exec(conn, `${aptEnv}; apt-get install -y -qq ${aptOpts} nginx`);
    await exec(conn, 'command -v nginx >/dev/null || (echo "nginx missing" && exit 1)');
    await exec(conn, `mkdir -p ${REMOTE_DIR} && rm -rf ${REMOTE_DIR}/*`);

    console.log('Uploading demo files…');
    await new Promise((resolve, reject) => {
      conn.sftp(async (err, sftp) => {
        if (err) return reject(err);
        try {
          await uploadDir(sftp, LOCAL_DIR, REMOTE_DIR);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });

    console.log('Configuring nginx…');
    await exec(conn, `cat > /etc/nginx/sites-available/epsok << 'NGINXEOF'\n${nginxConf}\nNGINXEOF`);
    await exec(conn, 'ln -sf /etc/nginx/sites-available/epsok /etc/nginx/sites-enabled/epsok');
    await exec(conn, 'rm -f /etc/nginx/sites-enabled/default');
    await exec(conn, 'systemctl stop caddy 2>/dev/null || true');
    await exec(conn, 'systemctl disable caddy 2>/dev/null || true');
    await exec(conn, 'nginx -t && systemctl enable nginx && systemctl restart nginx');
    await exec(conn, `chmod -R a+rX ${REMOTE_DIR}`);

    console.log(`\nDone. Demo: http://${HOST}/`);
    conn.end();
  } catch (e) {
    console.error(e.message || e);
    conn.end();
    process.exit(1);
  }
});

conn.on('error', err => {
  console.error('SSH error:', err.message);
  process.exit(1);
});

conn.connect({
  host: HOST,
  port: 22,
  username: USER,
  password: PASS,
  readyTimeout: 30000
});
