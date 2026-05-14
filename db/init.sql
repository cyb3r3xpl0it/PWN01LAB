CREATE DATABASE IF NOT EXISTS vulnlab;
USE vulnlab;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(100) NOT NULL,
  email VARCHAR(100),
  role VARCHAR(20) DEFAULT 'user',
  secret VARCHAR(100)
);

INSERT INTO users (username, password, email, role, secret) VALUES
  ('admin',    'supersecret123',  'admin@corp.com',  'admin', 'FLAG{sqli_bypass_master}'),
  ('jsmith',   'password123',     'jsmith@corp.com', 'user',  NULL),
  ('mlee',     'qwerty456',       'mlee@corp.com',   'user',  NULL),
  ('rbrown',   'letmein789',      'rbrown@corp.com', 'user',  NULL),
  ('victim',   'mypassword',      'victim@corp.com', 'user',  NULL);

CREATE TABLE messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50),
  content TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE emails (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  email VARCHAR(100),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO emails (user_id, email) VALUES
  (1, 'admin@corp.com'),
  (2, 'jsmith@corp.com'),
  (3, 'mlee@corp.com'),
  (4, 'rbrown@corp.com'),
  (5, 'victim@corp.com');
