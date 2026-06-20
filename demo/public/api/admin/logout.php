<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    epsok_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$admin = epsok_require_admin();
epsok_audit('admin.logout', $admin['username']);

epsok_start_admin_session();
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'] ?? '', $p['secure'], $p['httponly']);
}
session_destroy();

epsok_json(['ok' => true]);
