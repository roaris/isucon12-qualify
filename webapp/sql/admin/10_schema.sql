DROP TABLE IF EXISTS `tenant`;
DROP TABLE IF EXISTS `id_generator`;
DROP TABLE IF EXISTS `access_log`;

CREATE TABLE `tenant` (
  `id` BIGINT UNSIGNED NOT NULL,
  `name` VARCHAR(256) NOT NULL,
  `display_name` VARCHAR(256) NOT NULL,
  `created_at` DATETIME(6) NOT NULL,
  `updated_at` DATETIME(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE `id_generator` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stub` CHAR(1) NOT NULL DEFAULT '',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `stub` (`stub`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE `access_log` (
  `id` BIGINT UNSIGNED NOT NULL,
  `player_name` VARCHAR(256) NOT NULL,
  `tenant_id` BIGINT UNSIGNED NOT NULL,
  `competition_id` BIGINT UNSIGNED NOT NULL,
  `created_at` DATETIME(6) NOT NULL,
  `updated_at` DATETIME(6) NOT NULL,
  PRIMARY KEY (`player_name`, `competition_id`)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;