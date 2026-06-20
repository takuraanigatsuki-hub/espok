<?php
declare(strict_types=1);

/**
 * Одноразовая установка схемы БД и начальных пользователей.
 * Вызов: GET /api/setup.php?token=YOUR_SETUP_TOKEN
 * После успешного запуска удалите или смените setup_token в config.local.php
 */
require_once __DIR__ . '/lib/bootstrap.php';

$cfg = epsok_config();
$token = (string) ($_GET['token'] ?? '');
$expected = (string) ($cfg['setup_token'] ?? '');

if ($expected === '' || $expected === 'change-me-before-deploy') {
    epsok_json([
        'ok' => false,
        'error' => 'Configure setup_token in config.local.php before running setup',
    ], 403);
}

if (!hash_equals($expected, $token)) {
    epsok_json(['ok' => false, 'error' => 'Invalid setup token'], 403);
}

try {
    $pdo = epsok_db();
    epsok_install_schema($pdo);
    epsok_seed_demo_users($pdo);

    $bootstrap = $cfg['bootstrap_admin'] ?? [];
    $adminUser = epsok_validate_username((string) ($bootstrap['username'] ?? 'siteadmin'));
    $adminPass = (string) ($bootstrap['password'] ?? '');
    if ($adminUser && strlen($adminPass) >= 8) {
        $hash = password_hash($adminPass, PASSWORD_BCRYPT);
        $stmt = $pdo->prepare(
            'INSERT INTO epsok_users (username, password_hash, persona_id, display_name, contour_label, can_switch_persona, is_active, is_superadmin)
             VALUES (:u, :p, :persona, :name, :contour, 0, 1, 1)
             ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), is_superadmin = 1, is_active = 1'
        );
        $stmt->execute([
            ':u' => $adminUser,
            ':p' => $hash,
            ':persona' => 'TECH_ADMIN',
            ':name' => (string) ($bootstrap['display_name'] ?? 'Администратор сайта'),
            ':contour' => 'Site Admin · консоль управления',
        ]);
    }

    epsok_json([
        'ok' => true,
        'message' => 'Schema installed, demo users seeded, siteadmin created/updated',
        'console' => '/console/',
        'next' => 'Remove or rotate setup_token, then login at /console/',
    ]);
} catch (Throwable $e) {
    epsok_json(['ok' => false, 'error' => $e->getMessage()], 500);
}
