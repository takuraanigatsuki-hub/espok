<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib/bootstrap.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET' && ($_GET['action'] ?? '') === 'me') {
    $admin = epsok_admin_user();
    if (!$admin) {
        epsok_json(['ok' => false, 'authenticated' => false], 401);
    }
    epsok_json(['ok' => true, 'authenticated' => true, 'admin' => $admin]);
}

epsok_require_admin();

try {
    $pdo = epsok_db();
} catch (Throwable $e) {
    epsok_json(['ok' => false, 'error' => 'Database unavailable'], 503);
}

if ($method === 'GET') {
    $rows = $pdo->query(
        'SELECT id, username, persona_id, display_name, contour_label, can_switch_persona, is_active, is_superadmin, created_at, updated_at
         FROM epsok_users ORDER BY username ASC'
    )->fetchAll();
    epsok_json([
        'ok' => true,
        'users' => array_map('epsok_user_row_to_public', $rows),
    ]);
}

if ($method === 'POST') {
    $body = epsok_read_json_body();
    $username = epsok_validate_username((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');
    $personaId = trim((string) ($body['personaId'] ?? ''));
    $displayName = trim((string) ($body['displayName'] ?? ''));
    $contourLabel = trim((string) ($body['contourLabel'] ?? ''));
    $canSwitch = !empty($body['canSwitchPersona']) ? 1 : 0;
    $isActive = array_key_exists('isActive', $body) ? (!empty($body['isActive']) ? 1 : 0) : 1;
    $isSuperadmin = !empty($body['isSuperadmin']) ? 1 : 0;

    if (!$username || strlen($password) < 8) {
        epsok_json(['ok' => false, 'error' => 'Username and password (min 8 chars) required'], 400);
    }
    if (!$displayName || !epsok_validate_persona_id($personaId)) {
        epsok_json(['ok' => false, 'error' => 'Invalid display name or persona'], 400);
    }

    $hash = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare(
        'INSERT INTO epsok_users (username, password_hash, persona_id, display_name, contour_label, can_switch_persona, is_active, is_superadmin)
         VALUES (:u, :p, :persona, :name, :contour, :sw, :active, :sa)'
    );
    try {
        $stmt->execute([
            ':u' => $username,
            ':p' => $hash,
            ':persona' => $personaId,
            ':name' => $displayName,
            ':contour' => $contourLabel !== '' ? $contourLabel : null,
            ':sw' => $canSwitch,
            ':active' => $isActive,
            ':sa' => $isSuperadmin,
        ]);
    } catch (PDOException $e) {
        if ((int) ($e->errorInfo[1] ?? 0) === 1062) {
            epsok_json(['ok' => false, 'error' => 'Username already exists'], 409);
        }
        throw $e;
    }

    $id = (int) $pdo->lastInsertId();
    epsok_audit('user.create', $username, ['personaId' => $personaId, 'isSuperadmin' => (bool) $isSuperadmin]);

    $fetch = $pdo->prepare('SELECT * FROM epsok_users WHERE id = :id');
    $fetch->execute([':id' => $id]);
    $row = $fetch->fetch();
    epsok_json(['ok' => true, 'user' => epsok_user_row_to_public($row)], 201);
}

if ($method === 'PATCH') {
    $id = (int) ($_GET['id'] ?? 0);
    if ($id <= 0) {
        epsok_json(['ok' => false, 'error' => 'Missing user id'], 400);
    }
    $body = epsok_read_json_body();
    $fields = [];
    $params = [':id' => $id];

    if (isset($body['displayName'])) {
        $displayName = trim((string) $body['displayName']);
        if ($displayName === '') {
            epsok_json(['ok' => false, 'error' => 'Display name required'], 400);
        }
        $fields[] = 'display_name = :name';
        $params[':name'] = $displayName;
    }
    if (isset($body['contourLabel'])) {
        $fields[] = 'contour_label = :contour';
        $params[':contour'] = trim((string) $body['contourLabel']) ?: null;
    }
    if (isset($body['personaId'])) {
        $personaId = trim((string) $body['personaId']);
        if (!epsok_validate_persona_id($personaId)) {
            epsok_json(['ok' => false, 'error' => 'Invalid persona'], 400);
        }
        $fields[] = 'persona_id = :persona';
        $params[':persona'] = $personaId;
    }
    if (array_key_exists('canSwitchPersona', $body)) {
        $fields[] = 'can_switch_persona = :sw';
        $params[':sw'] = !empty($body['canSwitchPersona']) ? 1 : 0;
    }
    if (array_key_exists('isActive', $body)) {
        $fields[] = 'is_active = :active';
        $params[':active'] = !empty($body['isActive']) ? 1 : 0;
    }
    if (array_key_exists('isSuperadmin', $body)) {
        $fields[] = 'is_superadmin = :sa';
        $params[':sa'] = !empty($body['isSuperadmin']) ? 1 : 0;
    }
    if (!empty($body['password'])) {
        if (strlen((string) $body['password']) < 8) {
            epsok_json(['ok' => false, 'error' => 'Password min 8 chars'], 400);
        }
        $fields[] = 'password_hash = :pass';
        $params[':pass'] = password_hash((string) $body['password'], PASSWORD_BCRYPT);
    }

    if (!$fields) {
        epsok_json(['ok' => false, 'error' => 'Nothing to update'], 400);
    }

    $sql = 'UPDATE epsok_users SET ' . implode(', ', $fields) . ' WHERE id = :id';
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    epsok_audit('user.update', (string) $id, array_keys($body));

    $row = $pdo->prepare('SELECT * FROM epsok_users WHERE id = :id');
    $row->execute([':id' => $id]);
    $user = $row->fetch();
    if (!$user) {
        epsok_json(['ok' => false, 'error' => 'User not found'], 404);
    }
    epsok_json(['ok' => true, 'user' => epsok_user_row_to_public($user)]);
}

if ($method === 'DELETE') {
    $id = (int) ($_GET['id'] ?? 0);
    if ($id <= 0) {
        epsok_json(['ok' => false, 'error' => 'Missing user id'], 400);
    }
    $admin = epsok_admin_user();
    if ($admin && (int) $admin['id'] === $id) {
        epsok_json(['ok' => false, 'error' => 'Cannot delete yourself'], 400);
    }
    $stmt = $pdo->prepare('UPDATE epsok_users SET is_active = 0 WHERE id = :id');
    $stmt->execute([':id' => $id]);
    epsok_audit('user.deactivate', (string) $id);
    epsok_json(['ok' => true]);
}

epsok_json(['ok' => false, 'error' => 'Method not allowed'], 405);
