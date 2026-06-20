#!/usr/bin/env python3
"""Install EPSOK DB schema via REG.RU phpMyAdmin (no site Basic Auth needed)."""
from __future__ import annotations

import json
import re
import sys
import urllib.parse

import requests

PMA_BASE = 'https://server299.hosting.reg.ru/phpmyadmin/'
DB_USER = 'u3548413_default'
DB_PASS = 'PG150oIjn0IsfXRf'
DB_NAME = 'u3548413_default'

DEMO_HASH = '$2b$10$uwPBv4UUSYRaiDJZjew.4OLrWYsK5od9pOeeFE/erlR39FxdHH28q'
ADMIN_HASH = '$2b$10$WVUoU4QW/GE1X2AkGDhqHuLGoAdcYgPQVV3VJBh.dL/6917.qbrTm'

SQL = f"""
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @has_superadmin := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'epsok_users'
    AND COLUMN_NAME = 'is_superadmin'
);
SET @sql := IF(
  @has_superadmin = 0,
  'ALTER TABLE epsok_users ADD COLUMN is_superadmin TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

INSERT INTO epsok_users (username, password_hash, persona_id, display_name, contour_label, can_switch_persona, is_active, is_superadmin)
VALUES
  ('ivanov.sp', '{DEMO_HASH}', 'INV_MVD', 'Иванов С.П.', 'Следственный комитет · Краснодарский край', 1, 1, 0),
  ('sidorov.av', '{DEMO_HASH}', 'TECH_ADMIN', 'Сидоров А.В.', 'Тех. контур · ЦОД', 0, 1, 0),
  ('kozlov.va', '{DEMO_HASH}', 'FUNC_ADMIN', 'Козлов В.А.', 'ИТ контур · МВД России', 0, 1, 0),
  ('takura.anigatsuki', '{DEMO_HASH}', 'BETA_TAKURA', 'Такура', 'Бета-контур · высший уровень доступа', 1, 1, 0),
  ('siteadmin', '{ADMIN_HASH}', 'TECH_ADMIN', 'Администратор сайта', 'Site Admin · консоль управления', 0, 1, 1)
ON DUPLICATE KEY UPDATE
  password_hash = VALUES(password_hash),
  persona_id = VALUES(persona_id),
  display_name = VALUES(display_name),
  contour_label = VALUES(contour_label),
  can_switch_persona = VALUES(can_switch_persona),
  is_active = 1,
  is_superadmin = VALUES(is_superadmin);
"""


def hidden_fields(html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in re.finditer(r'<input[^>]+type="hidden"[^>]*>', html, re.I):
        tag = match.group(0)
        name = re.search(r'name="([^"]+)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name:
            fields[name.group(1)] = value.group(1) if value else ''
    return fields


def login(session: requests.Session) -> None:
    resp = session.get(PMA_BASE, timeout=30)
    resp.raise_for_status()
    data = hidden_fields(resp.text)
    data.update({
        'pma_username': DB_USER,
        'pma_password': DB_PASS,
        'server': '1',
    })
    resp = session.post(PMA_BASE + 'index.php', data=data, timeout=30, allow_redirects=True)
    resp.raise_for_status()
    if 'logout' not in resp.text.lower():
        raise RuntimeError('phpMyAdmin login failed')


def run_sql(session: requests.Session) -> None:
    resp = session.get(PMA_BASE + 'index.php?route=/database/sql&db=' + DB_NAME, timeout=30)
    resp.raise_for_status()
    token = hidden_fields(resp.text).get('token', '')
    data = {
        'token': token,
        'is_bootstrap': '1',
        'db': DB_NAME,
        'sql_query': SQL,
        'ajax_request': 'true',
    }
    resp = session.post(
        PMA_BASE + 'index.php?route=/import',
        data=data,
        timeout=120,
        headers={'X-Requested-With': 'XMLHttpRequest'},
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get('success') is not True:
        raise RuntimeError('SQL import failed: ' + json.dumps(payload, ensure_ascii=False)[:500])


def verify(session: requests.Session) -> int:
    resp = session.get(PMA_BASE + 'index.php?route=/database/sql&db=' + DB_NAME, timeout=30)
    resp.raise_for_status()
    token = hidden_fields(resp.text).get('token', '')
    data = {
        'token': token,
        'is_bootstrap': '1',
        'db': DB_NAME,
        'sql_query': 'SELECT username FROM epsok_users ORDER BY username;',
        'ajax_request': 'true',
    }
    resp = session.post(
        PMA_BASE + 'index.php?route=/import',
        data=data,
        timeout=60,
        headers={'X-Requested-With': 'XMLHttpRequest'},
    )
    resp.raise_for_status()
    payload = resp.json()
    message = payload.get('message', '')
    match = re.search(r'\((\d+)\s+total', message)
    if match:
        return int(match.group(1))
    return len(re.findall(r'class="data grid_edit click2 not_null text pre_wrap"', message))


def main() -> int:
    session = requests.Session()
    session.verify = False
    login(session)
    run_sql(session)
    count = verify(session)
    print(json.dumps({'ok': True, 'users': count}, ensure_ascii=False))
    return 0 if count >= 5 else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
