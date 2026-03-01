<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

function start_session(): void {
  if (session_status() !== PHP_SESSION_ACTIVE) session_start();
}

function current_user(): ?array {
  start_session();
  return $_SESSION['user'] ?? null;
}

function require_login(): void {
  if (!current_user()) {
    header('Location: /SMG/login');
    exit;
  }
}

function require_role(array $roles): void {
  $u = current_user();
  if (!$u || !in_array($u['role'], $roles, true)) {
    http_response_code(403);
    echo "Forbidden";
    exit;
  }
}

function login_user(array $user): void {
  start_session();
  $_SESSION['user'] = [
    'id' => (int)$user['id'],
    'email' => $user['email'],
    'name' => $user['name'],
    'role' => $user['role'],
  ];
}

function logout_user(): void {
  start_session();
  $_SESSION = [];
  session_destroy();
}

function find_user_by_email(string $email): ?array {
  $stmt = db()->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
  $stmt->execute([':email' => $email]);
  $row = $stmt->fetch();
  return $row ?: null;
}
