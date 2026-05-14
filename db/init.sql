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

-- Race condition: cupones de un solo uso
CREATE TABLE coupons (
  id INT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(50) UNIQUE NOT NULL,
  discount INT NOT NULL,
  used TINYINT DEFAULT 0,
  used_by INT,
  used_at TIMESTAMP NULL
);

INSERT INTO coupons (code, discount) VALUES
  ('RACE100', 100),
  ('SAVE50',  50);

-- Password reset: tokens predecibles sin expiración
CREATE TABLE password_resets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Business logic: productos y órdenes
CREATE TABLE products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  stock INT DEFAULT 100
);

INSERT INTO products (name, price) VALUES
  ('VulnLab Pro License', 99.99),
  ('Security Course',     49.99),
  ('Pentest Toolkit',    199.99);

CREATE TABLE orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  product_id INT,
  quantity INT,
  unit_price DECIMAL(10,2),
  total DECIMAL(10,2),
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
