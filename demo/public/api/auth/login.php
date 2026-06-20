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
        'SELECT id, username, password_hash, persona_id, display_name, contour_label, can_switch_persona, is_active
         FROM epsok_users WHERE username = :u LIMIT 1'
    );
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch();
    if (!$row || !(int) $row['is_active']) {
        epsok_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
    }
    if (!password_verify($password, $row['password_hash'])) {
        epsok_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
    }
    epsok_json([
        'ok' => true,
        'user' => epsok_user_row_to_auth($row),
    ]);
} catch (Throwable $e) {
    epsok_json(['ok' => false, 'error' => 'Auth service unavailable', 'fallback' => true], 503);
}
