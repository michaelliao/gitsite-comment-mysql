-- generate schema for gitsite-comment:

CREATE DATABASE comment;
USE comment;

CREATE TABLE `users` (
  `id` varchar(50) NOT NULL,
  `role` bigint NOT NULL,
  `name` varchar(100) NOT NULL,
  `image` varchar(1000) NOT NULL,
  `salt` varchar(32) NOT NULL,
  `locked_at` bigint NOT NULL,
  `updated_at` bigint NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `pages` (
  `id` varchar(32) NOT NULL,
  `updated_at` bigint NOT NULL,
  `pathname` varchar(1000) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `comments` (
  `id` bigint NOT NULL,
  `page_id` varchar(32) NOT NULL,
  `user_id` varchar(50) NOT NULL,
  `user_name` varchar(100) NOT NULL,
  `user_image` varchar(1000) NOT NULL,
  `replies_count` bigint NOT NULL,
  `created_at` bigint NOT NULL,
  `updated_at` bigint NOT NULL,
  `content` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `IDX_PID_UPDATED` (`page_id`, `updated_at` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `replies` (
  `id` bigint NOT NULL,
  `comment_id` bigint NOT NULL,
  `user_id` varchar(50) NOT NULL,
  `user_name` varchar(100) NOT NULL,
  `user_image` varchar(1000) NOT NULL,
  `created_at` bigint NOT NULL,
  `content` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `IDX_CID_CREATED` (`comment_id`, `created_at` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
