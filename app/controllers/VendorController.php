<?php
declare(strict_types=1);

require_once __DIR__ . '/../auth.php';

final class VendorController {
  public static function dashboard(): void {
    require_login();
    require_role(['VENDOR']);
    require __DIR__ . '/../views/vendor.php';
  }
}
