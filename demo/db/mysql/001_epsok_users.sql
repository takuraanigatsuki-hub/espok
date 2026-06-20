-- EPSOK demo users (MySQL / MariaDB on REG.RU hosting)

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
