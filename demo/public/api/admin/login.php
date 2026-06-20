<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    epsok_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$body = epsok_read_json_body();
$username = epsok_validate_username((string) ($body['username'] ?? ''));
$password = (string) ($body['password'] ?? '');

if (!$username || $password === '') {
    epsok_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
}

try {
    $pdo = epsok_db();
    $stmt = $pdo->prepare(
        'SELECT id, username, password_hash, display_name, is_active, is_superadmin
         FROM epsok_users WHERE username = :u LIMIT 1'
    );
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch();
    if (!$row || !(int) $row['is_active'] || !(int) $row['is_superadmin']) {
        epsok_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
    }
    if (!password_verify($password, $row['password_hash'])) {
        epsok_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
    }

    epsok_start_admin_session();
    session_regenerate_id(true);
    $_SESSION['admin_user_id'] = (int) $row['id'];
    $_SESSION['admin_username'] = (string) $row['username'];
    $_SESSION['admin_display_name'] = (string) $row['display_name'];

    epsok_audit('admin.login', $row['username']);

    epsok_json([
        'ok' => true,
        'admin' => [
            'username' => $row['username'],
            'displayName' => $row['display_name'],
        ],
    ]);
} catch (Throwable $e) {
    epsok_json(['ok' => false, 'error' => 'Admin auth unavailable'], 503);
}
