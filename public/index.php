<?php
declare(strict_types=1);

require_once __DIR__ . '/../app/auth.php';
require_once __DIR__ . '/../app/router.php';

require_once __DIR__ . '/../app/controllers/AuthController.php';
require_once __DIR__ . '/../app/controllers/OwnerController.php';
require_once __DIR__ . '/../app/controllers/TenantController.php';
require_once __DIR__ . '/../app/controllers/VendorController.php';

// Normalize path for subfolder deployment (/SMG)
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$base = '/SMG';
if (str_starts_with($path, $base)) {
  $path = substr($path, strlen($base));
  if ($path === '') $path = '/';
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Routes
route('GET', '/', function () {
  $u = current_user();
  if (!$u) { header('Location: /SMG/login'); exit; }
  if ($u['role'] === 'OWNER' || $u['role'] === 'PROPERTY_MANAGER') { header('Location: /SMG/owner'); exit; }
  if ($u['role'] === 'TENANT') { header('Location: /SMG/tenant'); exit; }
  if ($u['role'] === 'VENDOR') { header('Location: /SMG/vendor'); exit; }
  header('Location: /SMG/login'); exit;
});

route('GET', '/login', 'AuthController::showLogin');
route('POST', '/login', 'AuthController::doLogin');
route('POST', '/logout', 'AuthController::logout');

route('GET', '/owner', 'OwnerController::dashboard');
route('POST', '/owner/action', 'OwnerController::action');

route('GET', '/tenant', 'TenantController::dashboard');
route('GET', '/vendor', 'VendorController::dashboard');

dispatch($method, $path);
