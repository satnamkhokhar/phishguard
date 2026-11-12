CREATE DATABASE IF NOT EXISTS phishguard_db;
USE phishguard_db;
CREATE TABLE `scans` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `url` varchar(2048) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `risk_score` int NOT NULL,
  `classification` varchar(30) NOT NULL,
  `summary` text NOT NULL,
  `indicators` json NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_scans_user_created` (`user_id`,`created_at`),
  CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;