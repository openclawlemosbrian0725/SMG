<?php
declare(strict_types=1);

return [
  'app_name' => 'Santiago Management Group',
  'base_path' => dirname(__DIR__),
  'db_path' => dirname(__DIR__) . '/data/smg.sqlite',
  'mfa_enforced' => false, // UI may show MFA; not enforced in v1
  'debug' => true,
];
