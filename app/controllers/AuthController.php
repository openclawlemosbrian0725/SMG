<?php
declare(strict_types=1);

final class AuthController {
  public static function showLogin(): void {
    $error = $_GET['error'] ?? null;
    require __DIR__ . '/../views/login.php';
  }

  public static function doLogin(): void {
    $email = trim($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if ($email === '' || $password === '') {
      header('Location: /SMG/login?error=Missing+credentials');
      exit;
    }

    $user = find_user_by_email($email);
    if (!$user || !password_verify($password, $user['password_hash'])) {
      header('Location: /SMG/login?error=Invalid+email+or+password');
      exit;
    }

    // MFA UI exists; not enforced in v1 per requirements
    login_user($user);

    header('Location: /SMG/');
    exit;
  }

  public static function logout(): void {
    logout_user();
    header('Location: /SMG/login');
    exit;
  }
}
