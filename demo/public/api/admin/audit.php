<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib/bootstrap.php';

epsok_require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    epsok_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

try {
    $pdo = epsok_db();
    $limit = min(200, max(1, (int) ($_GET['limit'] ?? 50)));
    $stmt = $pdo->prepare(
        'SELECT id, actor_username, action, target_ref, meta_json, ip_address, created_at
         FROM epsok_admin_audit ORDER BY id DESC LIMIT :lim'
    );
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();
    epsok_json(['ok' => true, 'entries' => $rows]);
} catch (Throwable $e) {
    epsok_json(['ok' => false, 'error' => 'Audit unavailable'], 503);
}
