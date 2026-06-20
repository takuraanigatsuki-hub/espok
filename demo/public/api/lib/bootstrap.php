<?php
declare(strict_types=1);

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

function epsok_config(): array
{
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $defaults = [
        'db' => [
            'host' => getenv('EPSOK_DB_HOST') ?: 'localhost',
            'name' => getenv('EPSOK_DB_NAME') ?: '',
            'user' => getenv('EPSOK_DB_USER') ?: '',
            'pass' => getenv('EPSOK_DB_PASS') ?: '',
            'charset' => 'utf8mb4',
        ],
        'setup_token' => getenv('EPSOK_SETUP_TOKEN') ?: '',
        'bootstrap_admin' => [
            'username' => 'siteadmin',
            'password' => 'ChangeMe-SiteAdmin-2028!',
            'display_name' => 'Администратор сайта',
        ],
    ];
    $local = __DIR__ . '/../config.local.php';
    if (is_file($local)) {
        $loaded = require $local;
        if (is_array($loaded)) {
            $cfg = array_replace_recursive($defaults, $loaded);
            return $cfg;
        }
    }
    $cfg = $defaults;
    return $cfg;
}

function epsok_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $db = epsok_config()['db'];
    if ($db['name'] === '' || $db['user'] === '') {
        throw new RuntimeException('Database is not configured. Copy config.local.php.example to config.local.php');
    }
    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=%s',
        $db['host'],
        $db['name'],
        $db['charset'] ?? 'utf8mb4'
    );
    $pdo = new PDO($dsn, $db['user'], $db['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function epsok_json(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function epsok_read_json_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function epsok_start_admin_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_name('EPSOK_ADMIN');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function epsok_admin_user(): ?array
{
    epsok_start_admin_session();
    if (empty($_SESSION['admin_user_id']) || empty($_SESSION['admin_username'])) {
        return null;
    }
    return [
        'id' => (int) $_SESSION['admin_user_id'],
        'username' => (string) $_SESSION['admin_username'],
        'displayName' => (string) ($_SESSION['admin_display_name'] ?? ''),
    ];
}

function epsok_require_admin(): array
{
    $admin = epsok_admin_user();
    if (!$admin) {
        epsok_json(['ok' => false, 'error' => 'Unauthorized'], 401);
    }
    return $admin;
}

function epsok_audit(string $action, ?string $target = null, ?array $meta = null): void
{
    try {
        $pdo = epsok_db();
        $admin = epsok_admin_user();
        $stmt = $pdo->prepare(
            'INSERT INTO epsok_admin_audit (actor_username, action, target_ref, meta_json, ip_address)
             VALUES (:actor, :action, :target, :meta, :ip)'
        );
        $stmt->execute([
            ':actor' => $admin['username'] ?? 'system',
            ':action' => $action,
            ':target' => $target,
            ':meta' => $meta ? json_encode($meta, JSON_UNESCAPED_UNICODE) : null,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? null,
        ]);
    } catch (Throwable $e) {
        // audit must not break main flow
    }
}

function epsok_user_row_to_public(array $row): array
{
    return [
        'id' => (int) $row['id'],
        'username' => $row['username'],
        'personaId' => $row['persona_id'],
        'displayName' => $row['display_name'],
        'contourLabel' => $row['contour_label'],
        'canSwitchPersona' => (bool) $row['can_switch_persona'],
        'isActive' => (bool) $row['is_active'],
        'isSuperadmin' => (bool) ($row['is_superadmin'] ?? 0),
        'createdAt' => $row['created_at'] ?? null,
        'updatedAt' => $row['updated_at'] ?? null,
    ];
}

function epsok_user_row_to_auth(array $row): array
{
    return [
        'username' => $row['username'],
        'personaId' => $row['persona_id'],
        'displayName' => $row['display_name'],
        'contourLabel' => $row['contour_label'] ?? '',
        'canSwitchPersona' => (bool) $row['can_switch_persona'],
    ];
}

function epsok_validate_username(string $username): ?string
{
    $username = strtolower(trim($username));
    if ($username === '' || strlen($username) > 128) {
        return null;
    }
    if (!preg_match('/^[a-z0-9._-]+$/', $username)) {
        return null;
    }
    return $username;
}

function epsok_validate_persona_id(string $personaId): bool
{
    static $allowed = [
        'INV_MVD', 'INV_LEAD_MVD', 'INV_SK', 'OPS_MVD', 'PROSEC', 'ANALYST',
        'TECH_ADMIN', 'FUNC_ADMIN', 'BETA_TAKURA', 'EXEC_MVD', 'EXEC_FNS',
        'EXEC_RFM', 'EXEC_FTS', 'EXEC_FSIN', 'EXEC_FSSP', 'EXEC_CBR', 'EXEC_ROSREESTR',
        'COURT', 'INV_FSB',
    ];
    return in_array($personaId, $allowed, true);
}

function epsok_install_schema(PDO $pdo): void
{
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS epsok_users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  persona_id VARCHAR(32) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  contour_label VARCHAR(255) DEFAULT NULL,
  can_switch_persona TINYINT(1) NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  is_superadmin TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_epsok_users_username (username),
  KEY idx_epsok_users_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
SQL);

    $cols = $pdo->query("SHOW COLUMNS FROM epsok_users LIKE 'is_superadmin'")->fetch();
    if (!$cols) {
        $pdo->exec('ALTER TABLE epsok_users ADD COLUMN is_superadmin TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active');
    }

    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS epsok_admin_audit (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  actor_username VARCHAR(128) NOT NULL,
  action VARCHAR(64) NOT NULL,
  target_ref VARCHAR(256) DEFAULT NULL,
  meta_json JSON DEFAULT NULL,
  ip_address VARCHAR(45) DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_admin_audit_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
SQL);
}

function epsok_seed_demo_users(PDO $pdo): void
{
    $demoPassword = password_hash('epsok2028', PASSWORD_BCRYPT);
    $rows = [
        ['ivanov.sp', 'INV_MVD', 'Иванов С.П.', 'Следственный комитет · Краснодарский край', 1, 0],
        ['sidorov.av', 'TECH_ADMIN', 'Сидоров А.В.', 'Тех. контур · ЦОД', 0, 0],
        ['kozlov.va', 'FUNC_ADMIN', 'Козлов В.А.', 'ИТ контур · МВД России', 0, 0],
        ['takura.anigatsuki', 'BETA_TAKURA', 'Такура', 'Бета-контур · высший уровень доступа', 1, 0],
    ];
    $stmt = $pdo->prepare(
        'INSERT INTO epsok_users (username, password_hash, persona_id, display_name, contour_label, can_switch_persona, is_active, is_superadmin)
         VALUES (:u, :p, :persona, :name, :contour, :sw, 1, :sa)
         ON DUPLICATE KEY UPDATE
           password_hash = VALUES(password_hash),
           persona_id = VALUES(persona_id),
           display_name = VALUES(display_name),
           contour_label = VALUES(contour_label),
           can_switch_persona = VALUES(can_switch_persona),
           is_active = 1'
    );
    foreach ($rows as [$u, $persona, $name, $contour, $sw, $sa]) {
        $stmt->execute([
            ':u' => $u,
            ':p' => $demoPassword,
            ':persona' => $persona,
            ':name' => $name,
            ':contour' => $contour,
            ':sw' => $sw,
            ':sa' => $sa,
        ]);
    }
}
