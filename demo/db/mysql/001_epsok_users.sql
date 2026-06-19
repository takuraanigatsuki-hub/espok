-- EPSOK demo users (MySQL / MariaDB on REG.RU hosting)
-- Password for all demo accounts: epsok2028 (bcrypt hash generated at deploy time)

DROP TABLE IF EXISTS epsok_users;

CREATE TABLE epsok_users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  persona_id VARCHAR(32) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  contour_label VARCHAR(255) DEFAULT NULL,
  can_switch_persona TINYINT(1) NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_epsok_users_username (username),
  KEY idx_epsok_users_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Re-seed via demo/db/seed-users.mjs (generates bcrypt hashes)
