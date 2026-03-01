<?php
/**
 * init_db.php
 * One-time initializer for SMG (SQLite).
 *
 * Usage:
 *   php -S 0.0.0.0:8080
 *   http://localhost:8080/init_db.php
 *
 * Creates / writes: ./smg.sqlite
 * Seeds demo users:
 *   owner@smg.local   / Password123!
 *   tenant@smg.local  / Password123!
 *   vendor@smg.local  / Password123!
 *
 * Prints TOTP secrets + otpauth:// URIs for authenticator apps (Google Authenticator, Authy, 1Password, etc.).
 */

declare(strict_types=1);

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function db_path(): string {
  return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'smg.sqlite';
}

function pdo(): PDO {
  $pdo = new PDO('sqlite:' . db_path(), null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  $pdo->exec('PRAGMA foreign_keys = ON;');
  return $pdo;
}

// --- TOTP helpers (Base32) ---
function base32_encode(string $data): string {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $bits = '';
  for ($i=0; $i<strlen($data); $i++) $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
  $chunks = str_split($bits, 5);
  $out = '';
  foreach ($chunks as $chunk) {
    if (strlen($chunk) < 5) $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
    $out .= $alphabet[bindec($chunk)];
  }
  // pad to multiple of 8 with =
  $pad = (8 - (strlen($out) % 8)) % 8;
  return $out . str_repeat('=', $pad);
}
function random_totp_secret(): string {
  // 20 bytes -> 32 base32 chars (typical)
  return rtrim(base32_encode(random_bytes(20)), '=');
}

$pdo = pdo();

// Drop existing? keep simple: if ?reset=1 drop and recreate.
$reset = isset($_GET['reset']) && $_GET['reset'] === '1';
if ($reset) {
  $pdo->exec("DROP TABLE IF EXISTS payouts;");
  $pdo->exec("DROP TABLE IF EXISTS invoices;");
  $pdo->exec("DROP TABLE IF EXISTS jobs;");
  $pdo->exec("DROP TABLE IF EXISTS payment_methods;");
  $pdo->exec("DROP TABLE IF EXISTS payments;");
  $pdo->exec("DROP TABLE IF EXISTS maintenance_requests;");
  $pdo->exec("DROP TABLE IF EXISTS leases;");
  $pdo->exec("DROP TABLE IF EXISTS units;");
  $pdo->exec("DROP TABLE IF EXISTS properties;");
  $pdo->exec("DROP TABLE IF EXISTS users;");
}

// Schema
$pdo->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL CHECK(role IN ('OWNER','TENANT','VENDOR')),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  totp_secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS properties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS units (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  property_id INTEGER NOT NULL,
  unit_label TEXT NOT NULL,
  bedrooms INTEGER DEFAULT 0,
  bathrooms REAL DEFAULT 0,
  sqft INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(property_id) REFERENCES properties(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS leases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id INTEGER NOT NULL,
  tenant_id INTEGER NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  rent_cents INTEGER NOT NULL,
  deposit_cents INTEGER NOT NULL DEFAULT 0,
  due_day INTEGER NOT NULL DEFAULT 1,
  grace_days INTEGER NOT NULL DEFAULT 5,
  late_fee_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','ENDED')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(unit_id) REFERENCES units(id) ON DELETE CASCADE,
  FOREIGN KEY(tenant_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS maintenance_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lease_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'Normal' CHECK(priority IN ('Normal','Urgent')),
  status TEXT NOT NULL DEFAULT 'In Review' CHECK(status IN ('In Review','Scheduled','Completed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(lease_id) REFERENCES leases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lease_id INTEGER NOT NULL,
  payer_user_id INTEGER NOT NULL,
  amount_cents INTEGER NOT NULL,
  memo TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Processed' CHECK(status IN ('Pending','Processed','Failed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(lease_id) REFERENCES leases(id) ON DELETE CASCADE,
  FOREIGN KEY(payer_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payment_methods (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  method_type TEXT NOT NULL CHECK(method_type IN ('Card','Bank','Zelle','Check')),
  label TEXT NOT NULL,
  last4 TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  maintenance_id INTEGER NOT NULL,
  vendor_id INTEGER,
  scheduled_for TEXT DEFAULT NULL,
  status TEXT NOT NULL DEFAULT 'Assigned' CHECK(status IN ('Assigned','In Progress','Completed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(maintenance_id) REFERENCES maintenance_requests(id) ON DELETE CASCADE,
  FOREIGN KEY(vendor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  line_items_json TEXT NOT NULL DEFAULT '[]',
  total_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Submitted','Paid')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_id INTEGER NOT NULL,
  invoice_id INTEGER NOT NULL,
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Paid')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(vendor_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
);
");

// Seed users if missing
$users = [
  ['OWNER',  'owner@smg.local',  'Brian Owner',  'Password123!'],
  ['TENANT', 'tenant@smg.local', 'Maria Gonzalez','Password123!'],
  ['VENDOR', 'vendor@smg.local', "Mike's Plumbing",'Password123!'],
];

$created = [];
foreach ($users as [$role, $email, $name, $pass]) {
  $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
  $stmt->execute([$email]);
  $existing = $stmt->fetchColumn();
  if ($existing) continue;

  $secret = random_totp_secret();
  $hash = password_hash($pass, PASSWORD_DEFAULT);

  $ins = $pdo->prepare("INSERT INTO users(role,email,password_hash,full_name,totp_secret) VALUES(?,?,?,?,?)");
  $ins->execute([$role, $email, $hash, $name, $secret]);
  $id = (int)$pdo->lastInsertId();

  $created[] = ['id'=>$id,'role'=>$role,'email'=>$email,'name'=>$name,'pass'=>$pass,'secret'=>$secret];
}

// Seed minimal property/unit/lease if not exists
$ownerId = (int)($pdo->query("SELECT id FROM users WHERE role='OWNER' ORDER BY id ASC LIMIT 1")->fetchColumn() ?: 0);
$tenantId = (int)($pdo->query("SELECT id FROM users WHERE role='TENANT' ORDER BY id ASC LIMIT 1")->fetchColumn() ?: 0);
$vendorId = (int)($pdo->query("SELECT id FROM users WHERE role='VENDOR' ORDER BY id ASC LIMIT 1")->fetchColumn() ?: 0);

if ($ownerId && $tenantId) {
  $propCount = (int)$pdo->query("SELECT COUNT(*) FROM properties")->fetchColumn();
  if ($propCount === 0) {
    $pdo->prepare("INSERT INTO properties(owner_id,name,address) VALUES(?,?,?)")
        ->execute([$ownerId,'89 Gallup St','89 Gallup St, Providence RI 02905']);
    $propId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO units(property_id,unit_label,bedrooms,bathrooms,sqft) VALUES(?,?,?,?,?)")
        ->execute([$propId,'1A',2,1,780]);
    $unitId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO leases(unit_id,tenant_id,start_date,end_date,rent_cents,deposit_cents,due_day,grace_days,late_fee_cents,status)
                   VALUES(?,?,?,?,?,?,?,?,?,?)")
        ->execute([$unitId,$tenantId,'2024-09-01','2025-08-31',185000,185000,1,5,7500,'ACTIVE']);
    $leaseId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO maintenance_requests(lease_id,title,description,priority,status) VALUES(?,?,?,?,?)")
        ->execute([$leaseId,'Leaking faucet — kitchen sink','Leaking faucet in kitchen sink reported by tenant.','Urgent','In Review']);
    $maintId = (int)$pdo->lastInsertId();

    $pdo->prepare("INSERT INTO jobs(maintenance_id,vendor_id,scheduled_for,status) VALUES(?,?,?,?)")
        ->execute([$maintId,$vendorId,'2026-03-03 10:00','Assigned']);
  }
}

// Output
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
  . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SMG DB Init</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:#0b0f14;color:#e5e7eb;padding:24px}
    .card{background:#0f1623;border:1px solid #1f2230;border-radius:14px;padding:18px 18px;margin:14px 0}
    code{background:#0b0f14;border:1px solid #1f2230;border-radius:10px;padding:10px;display:block;white-space:pre-wrap;color:#d1d5db}
    a{color:#22c997}
    .pill{display:inline-block;background:rgba(34,201,151,.12);border:1px solid rgba(34,201,151,.25);color:#22c997;padding:3px 10px;border-radius:999px;font-weight:600;font-size:12px}
  </style>
</head>
<body>
  <h1>SMG — SQLite initialized</h1>

  <div class="card">
    <div class="pill">DB Path</div>
    <code><?=h(db_path())?></code>
  </div>

  <div class="card">
    <div class="pill">Next</div>
    <p>Open the app: <a href="<?=h($baseUrl)?>/smg.php"><?=h($baseUrl)?>/smg.php</a></p>
    <p>If you need to wipe and rebuild: <a href="?reset=1">init_db.php?reset=1</a></p>
  </div>

  <div class="card">
    <div class="pill">Seeded / Existing Users</div>
    <p>Passwords for demo users are <b>Password123!</b> (change later).</p>
    <p>TOTP is <b>required</b> on login (scan into your authenticator).</p>
<?php
$stmt = $pdo->query("SELECT id,role,email,full_name,totp_secret FROM users ORDER BY id ASC");
$all = $stmt->fetchAll();
foreach ($all as $u) {
  $issuer = rawurlencode('SMG');
  $label = rawurlencode($u['email']);
  $secret = $u['totp_secret'];
  $otpauth = "otpauth://totp/{$issuer}:{$label}?secret=" . rawurlencode($secret) . "&issuer={$issuer}&digits=6&period=30";
  echo "<h3 style='margin:14px 0 6px'>".h($u['role'])." — ".h($u['full_name'])."</h3>";
  echo "<code>Email: ".h($u['email'])."\nSecret: ".h($secret)."\notpauth://\n".$otpauth."</code>";
}
?>
  </div>
</body>
</html>
