<?php
declare(strict_types=1);

require_once __DIR__ . '/../auth.php';

final class TenantController {
  public static function dashboard(): void {
    require_login();
    require_role(['TENANT']);
    require __DIR__ . '/../views/tenant.php';
  }
}
