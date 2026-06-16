import { Client } from 'ssh2';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOST = process.env.ESP_OK_HOST || '80.78.245.66';
const DOMAIN = process.env.ESP_OK_DOMAIN || '80-78-245-66.cloudvps.regruhosting.ru';
const PASS = process.env.ESP_OK_DEPLOY_PASS;
const LOCAL_DIR = path.join(__dirname, 'public');
const REMOTE_DIR = '/var/www/epsok';

if (!PASS) {
  console.error('Set ESP_OK_DEPLOY_PASS');
  process.exit(1);
}

function exec(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      stream.on('data', d => process.stdout.write(d));
      stream.stderr.on('data', d => process.stderr.write(d));
      stream.on('close', code => (code !== 0 ? reject(new Error(cmd)) : resolve()));
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
    if (entry.isDirectory()) await uploadDir(sftp, localPath, remotePath);
    else await new Promise((res, rej) => sftp.fastPut(localPath, remotePath, e => (e ? rej(e) : res())));
  }
}

const caddyfile = `${DOMAIN} {
    root * ${REMOTE_DIR}
    file_server
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
    }
}

:8080 {
    root * ${REMOTE_DIR}
    file_server
    encode gzip
}
`;

const conn = new Client();
conn.on('ready', async () => {
  try {
    console.log('Uploading site files…');
    await exec(conn, `mkdir -p ${REMOTE_DIR} && rm -rf ${REMOTE_DIR}/*`);
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

    console.log('Configuring Caddy for domain + :8080…');
    await exec(conn, `cat > /etc/caddy/Caddyfile << 'EOF'\n${caddyfile}\nEOF`);
    await exec(conn, 'systemctl stop nginx 2>/dev/null || true');
    await exec(conn, 'systemctl disable nginx 2>/dev/null || true');
    await exec(conn, 'systemctl enable caddy');
    await exec(conn, 'systemctl restart caddy || true');
    await exec(conn, 'sleep 2; systemctl is-active caddy || true');
    await exec(conn, `curl -sI http://127.0.0.1:8080/ | head -3 || true`);
    await exec(conn, `curl -skI https://127.0.0.1/ -H "Host: ${DOMAIN}" | head -5 || true`);
    console.log(`\nГотово.\n  HTTP:  http://${DOMAIN}:8080/\n  HTTPS: https://${DOMAIN}/ (если DNS указывает на ${HOST} и порты 80/443 открыты)`);
    conn.end();
  } catch (e) {
    console.error(e.message || e);
    conn.end();
    process.exit(1);
  }
});
conn.connect({ host: HOST, port: 22, username: 'root', password: PASS, readyTimeout: 30000 });
