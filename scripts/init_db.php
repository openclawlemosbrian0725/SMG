<?php
declare(strict_types=1);

require_once __DIR__ . '/../app/db.php';

$config = require __DIR__ . '/../app/config.php';
$dbPath = $config['db_path'];

@mkdir(dirname($dbPath), 0775, true);

$pdo = db();

// Dev-friendly reset
$pdo->exec("DROP TABLE IF EXISTS payments;");
$pdo->exec("DROP TABLE IF EXISTS work_orders;");
$pdo->exec("DROP TABLE IF EXISTS maintenance_requests;");
$pdo->exec("DROP TABLE IF EXISTS leases;");
$pdo->exec("DROP TABLE IF EXISTS tenancies;");
$pdo->exec("DROP TABLE IF EXISTS units;");
$pdo->exec("DROP TABLE IF EXISTS properties;");
$pdo->exec("DROP TABLE IF EXISTS vendors;");
$pdo->exec("DROP TABLE IF EXISTS users;");

$pdo->exec("
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('OWNER','PROPERTY_MANAGER','TENANT','VENDOR')),
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
");

$pdo->exec("
CREATE TABLE properties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  created_at TEXT NOT NULL
);
");

$pdo->exec("
CREATE TABLE units (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  property_id INTEGER NOT NULL,
  unit_label TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('VACANT','OCCUPIED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(property_id) REFERENCES properties(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE tenancies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id INTEGER NOT NULL,
  tenant_user_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','ENDED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE,
  FOREIGN KEY(tenant_user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE leases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenancy_id INTEGER NOT NULL,
  rent_amount REAL NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','EXPIRED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(tenancy_id) REFERENCES tenancies(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE maintenance_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id INTEGER NOT NULL,
  created_by_user_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  priority TEXT NOT NULL CHECK(priority IN ('LOW','MEDIUM','HIGH')),
  status TEXT NOT NULL CHECK(status IN ('OPEN','SCHEDULED','IN_PROGRESS','COMPLETED','CLOSED')),
  description TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE,
  FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE vendors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_user_id INTEGER NOT NULL,
  trade TEXT NOT NULL,
  service_areas TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(vendor_user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE work_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  maintenance_request_id INTEGER NOT NULL,
  vendor_id INTEGER NOT NULL,
  scheduled_at TEXT NULL,
  status TEXT NOT NULL CHECK(status IN ('ASSIGNED','ACCEPTED','IN_PROGRESS','COMPLETED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(maintenance_request_id) REFERENCES maintenance_requests(id) ON DELETE CASCADE,
  FOREIGN KEY(vendor_id) REFERENCES vendors(id) ON DELETE CASCADE
);
");

$pdo->exec("
CREATE TABLE payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lease_id INTEGER NOT NULL,
  tenant_user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  method TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PAID','PENDING','OVERDUE')),
  paid_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(lease_id) REFERENCES leases(id) ON DELETE CASCADE,
  FOREIGN KEY(tenant_user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

function mkpass(string $plain): string { return password_hash($plain, PASSWORD_DEFAULT); }

$now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');

// Seed users (demo)
$users = [
  ['owner@smg.local',  'Brian Owner',  'OWNER'],
  ['pm@smg.local',     'Pat Manager',  'PROPERTY_MANAGER'],
  ['tenant@smg.local', 'Taylor Tenant','TENANT'],
  ['vendor@smg.local', 'Victor Vendor','VENDOR'],
];

$stmt = $pdo->prepare("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)");
foreach ($users as $u) {
  $stmt->execute([$u[0], $u[1], $u[2], mkpass('Password123!'), $now]);
}

// Seed 1 property + 4 units (matches mock visuals idea)
$pdo->prepare("INSERT INTO properties(name,address,created_at) VALUES(?,?,?)")
    ->execute(['Santiago Building', '123 Example St, Providence, RI', $now]);
$propertyId = (int)$pdo->lastInsertId();

$unitLabels = ['1A','2B','3C','4D'];
$unitStmt = $pdo->prepare("INSERT INTO units(property_id,unit_label,status,created_at) VALUES(?,?,?,?)");
foreach ($unitLabels as $i => $label) {
  $status = ($i < 3) ? 'OCCUPIED' : 'VACANT';
  $unitStmt->execute([$propertyId, $label, $status, $now]);
}

// Seed one tenancy+lease for tenant on unit 1A
$tenantId = (int)$pdo->query("SELECT id FROM users WHERE role='TENANT' LIMIT 1")->fetch()['id'];
$unit1A = (int)$pdo->query("SELECT id FROM units WHERE unit_label='1A' LIMIT 1")->fetch()['id'];

$pdo->prepare("INSERT INTO tenancies(unit_id,tenant_user_id,status,created_at) VALUES(?,?,?,?)")
    ->execute([$unit1A, $tenantId, 'ACTIVE', $now]);
$tenancyId = (int)$pdo->lastInsertId();

$pdo->prepare("INSERT INTO leases(tenancy_id,rent_amount,start_date,end_date,status,created_at) VALUES(?,?,?,?,?,?)")
    ->execute([$tenancyId, 1850.00, '2026-01-01', '2026-12-31', 'ACTIVE', $now]);
$leaseId = (int)$pdo->lastInsertId();

// Seed maintenance request (visible to owner+pm; vendor only after assignment later)
$pdo->prepare("INSERT INTO maintenance_requests(unit_id,created_by_user_id,category,priority,status,description,created_at)
              VALUES(?,?,?,?,?,?,?)")
    ->execute([$unit1A, $tenantId, 'Plumbing', 'HIGH', 'OPEN', 'Kitchen sink leaking — needs urgent attention.', $now]);

// Seed vendor profile
$vendorUserId = (int)$pdo->query("SELECT id FROM users WHERE role='VENDOR' LIMIT 1")->fetch()['id'];
$pdo->prepare("INSERT INTO vendors(vendor_user_id,trade,service_areas,created_at) VALUES(?,?,?,?)")
    ->execute([$vendorUserId, 'General Maintenance', 'Providence, Cranston, Pawtucket', $now]);

// Seed a paid payment this month
$paidAt = (new DateTimeImmutable('first day of this month'))->format('Y-m-d 09:00:00');
$pdo->prepare("INSERT INTO payments(lease_id,tenant_user_id,amount,method,status,paid_at,created_at)
              VALUES(?,?,?,?,?,?,?)")
    ->execute([$leaseId, $tenantId, 1850.00, 'MANUAL', 'PAID', $paidAt, $now]);

echo "Initialized DB at: {$dbPath}\n";
echo "Login: owner@smg.local / Password123!\n";
