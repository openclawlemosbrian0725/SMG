<?php
/**
 * index.php
 * Single-file PHP + SQLite app:
 * - Login (email/password)
 * - REQUIRED TOTP (RFC6238 compatible)
 * - Role-based dashboards: OWNER / TENANT / VENDOR
 * - Basic data flows: properties/units/leases, tenant maintenance + payments, vendor jobs + invoices/payouts
 *
 * Requires: init_db.php has been run at least once.
 */

declare(strict_types=1);

// ---- App base path & sessions (supports Apache Alias /SMG) ----
$__script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';        // e.g. /SMG/index.php
$__basePath = str_replace('\\', '/', dirname($__script)); // e.g. /SMG
if ($__basePath === '.' || $__basePath === '') $__basePath = '';
$__cookiePath = ($__basePath === '') ? '/' : $__basePath;

// Canonicalize "/SMG" -> "/SMG/" so relative URLs behave consistently
$__reqPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '';
if ($__basePath !== '' && $__reqPath === $__basePath) {
  header('Location: ' . $__basePath . '/', true, 301);
  exit;
}

$__isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
  'path' => $__cookiePath,
  'secure' => $__isHttps,
  'httponly' => true,
  'samesite' => 'Lax',
]);

session_start();

// -------------------------
// Utilities
// -------------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function is_post(): bool { return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'; }
function redirect(string $to): never {
  // Absolute URL or absolute path? leave it alone.
  if (preg_match('~^https?://~i', $to) || ($to !== '' && $to[0] === '/')) {
    header("Location: $to");
    exit;
  }

  // Anchor relative redirects to the app base path (e.g. /SMG/)
  $script = $_SERVER['SCRIPT_NAME'] ?? '/index.php';        // /SMG/index.php
  $base = str_replace('\\', '/', dirname($script));       // /SMG
  if ($base === '.' || $base === '') $base = '';
  $prefix = ($base === '') ? '/' : ($base . '/');

  header('Location: ' . $prefix . ltrim($to, '/'));
  exit;
}

function app_base(): string {
  return $_SERVER['SCRIPT_NAME'] ?? 'index.php';
}
function app_url(array $q = []): string {
  $base = app_base();
  if (!$q) return $base;
  return $base . '?' . http_build_query($q);
}

function now_iso(): string { return gmdate('Y-m-d H:i:s'); }
function money_fmt(int $cents): string { return '$' . number_format($cents / 100, 2); }
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

// -------------------------
// Base32 + TOTP (RFC6238)
// -------------------------
function base32_decode(string $b32): string {
  $b32 = strtoupper($b32);
  $b32 = preg_replace('/[^A-Z2-7]/', '', $b32) ?? '';
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $bits = '';
  for ($i=0; $i<strlen($b32); $i++) {
    $val = strpos($alphabet, $b32[$i]);
    if ($val === false) continue;
    $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
  }
  $bytes = str_split($bits, 8);
  $out = '';
  foreach ($bytes as $byte) {
    if (strlen($byte) < 8) continue;
    $out .= chr(bindec($byte));
  }
  return $out;
}

function totp_code(string $secret_b32, ?int $time = null, int $digits = 6, int $period = 30): string {
  $time = $time ?? time();
  $counter = intdiv($time, $period);

  // 8-byte big-endian counter
  $binCounter = pack('N*', 0) . pack('N*', $counter);

  $key = base32_decode($secret_b32);
  $hash = hash_hmac('sha1', $binCounter, $key, true);
  $offset = ord($hash[strlen($hash)-1]) & 0x0F;
  $truncated =
    ((ord($hash[$offset]) & 0x7F) << 24) |
    ((ord($hash[$offset+1]) & 0xFF) << 16) |
    ((ord($hash[$offset+2]) & 0xFF) << 8) |
    (ord($hash[$offset+3]) & 0xFF);

  $mod = 10 ** $digits;
  return str_pad((string)($truncated % $mod), $digits, '0', STR_PAD_LEFT);
}

function totp_verify(string $secret_b32, string $code, int $windowSteps = 1): bool {
  $code = preg_replace('/\D+/', '', $code) ?? '';
  if ($code === '') return false;
  $t = time();
  for ($i=-$windowSteps; $i<=$windowSteps; $i++) {
    $test = totp_code($secret_b32, $t + ($i * 30));
    if (hash_equals($test, $code)) return true;
  }
  return false;
}

// -------------------------
// Auth / Session
// -------------------------
function current_user(PDO $pdo): ?array {
  if (!isset($_SESSION['uid'])) return null;
  $stmt = $pdo->prepare("SELECT id,role,email,full_name,totp_secret FROM users WHERE id=?");
  $stmt->execute([$_SESSION['uid']]);
  $u = $stmt->fetch();
  return $u ?: null;
}

function require_login(PDO $pdo): array {
  $u = current_user($pdo);
  if (!$u) redirect('index.php?page=login');
  // Only enforce TOTP if the user actually has it enabled.
  if (!empty($u['totp_secret']) && !($_SESSION['totp_ok'] ?? false)) {
    redirect('index.php?page=totp');
  }
  return $u;
}

function logout(): never {
  $_SESSION = [];
  if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
      $params["path"], $params["domain"],
      $params["secure"], $params["httponly"]
    );
  }
  session_destroy();
  redirect('index.php?page=login');
}

// -------------------------
// Rendering (UI vibe based on your mockups)
// References: login/owner/tenant/vendor mockups :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5} :contentReference[oaicite:6]{index=6} :contentReference[oaicite:7]{index=7}
// -------------------------
function render_head(string $title): void {
  ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title><?=h($title)?></title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
  <style>
    :root{
      --bg:#0B0F14; --surface:#0F1623; --surface2:#0B0F14;
      --sidebar:#0f1117; --sidebarHover:#1a1d27;
      --text:#e5e7eb; --muted:#9ca3af; --faint:#6b7280;
      --border:#1f2230;
      --accent:#22C997; --accentDark:#1FAA7F;
      --danger:#ef4444; --warn:#f59e0b; --blue:#3b82f6;
      --radius:14px;
      --shadow:0 10px 40px rgba(0,0,0,.35);
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0;font-family:"DM Sans",system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:radial-gradient(1200px 800px at 20% 10%, rgba(34,201,151,.08), transparent 55%), var(--bg);color:var(--text)}
    a{color:var(--accent);text-decoration:none}
    a:hover{color:var(--accentDark)}
    .wrap{min-height:100vh;display:flex}
    .sidebar{width:250px;background:linear-gradient(180deg, #0f1117, #0b0f14);border-right:1px solid var(--border);padding:16px;display:flex;flex-direction:column}
    .brand{display:flex;align-items:center;gap:10px;padding:10px 10px 14px;border-bottom:1px solid var(--border);margin-bottom:10px}
    .mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accentDark));display:flex;align-items:center;justify-content:center;font-weight:800;color:#052017}
    .brand .t1{font-weight:700}
    .brand .t2{font-size:12px;color:var(--faint);margin-top:1px}
    .nav{padding:10px 6px;display:flex;flex-direction:column;gap:6px}
    .nav a{display:flex;align-items:center;gap:10px;padding:10px 10px;border-radius:10px;color:var(--muted);font-weight:600;font-size:13px}
    .nav a:hover{background:rgba(255,255,255,.04);color:var(--text)}
    .nav a.active{background:rgba(34,201,151,.10);color:var(--accent);border:1px solid rgba(34,201,151,.18)}
    .me{margin-top:auto;border-top:1px solid var(--border);padding-top:12px}
    .chip{display:flex;align-items:center;gap:10px;padding:10px;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05)}
    .avatar{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#0ea5e9);display:flex;align-items:center;justify-content:center;font-weight:800;color:#06191a}
    .sub{font-size:12px;color:var(--faint)}
    .btnlink{display:inline-flex;align-items:center;justify-content:center;gap:8px;border-radius:12px;padding:10px 14px;font-weight:800;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03);color:var(--text);cursor:pointer}
    .btnlink:hover{border-color:rgba(34,201,151,.35);background:rgba(34,201,151,.07)}
    .main{flex:1;display:flex;flex-direction:column}
    .top{height:62px;display:flex;align-items:center;justify-content:space-between;padding:0 18px;border-bottom:1px solid var(--border);background:rgba(15,22,35,.65);backdrop-filter: blur(8px)}
    .title{font-weight:800;letter-spacing:-.3px}
    .content{padding:18px;max-width:1150px;width:100%}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .card{background:linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.015));border:1px solid rgba(255,255,255,.06);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
    .card .hd{padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;justify-content:space-between}
    .card .hd .h1{font-weight:800}
    .card .bd{padding:14px 16px}
    .kpi{padding:16px;border-radius:var(--radius);border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02)}
    .kpi .k{font-size:12px;color:var(--muted);font-weight:700}
    .kpi .v{font-size:26px;font-weight:900;margin-top:6px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;font-size:13px}
    th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
    tr:hover td{background:rgba(255,255,255,.02)}
    .badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-weight:900;font-size:11px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.02)}
    .b-green{color:var(--accent);border-color:rgba(34,201,151,.25);background:rgba(34,201,151,.08)}
    .b-yellow{color:#fbbf24;border-color:rgba(251,191,36,.25);background:rgba(251,191,36,.08)}
    .b-red{color:#f87171;border-color:rgba(248,113,113,.25);background:rgba(248,113,113,.08)}
    .b-blue{color:#93c5fd;border-color:rgba(147,197,253,.25);background:rgba(147,197,253,.08)}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .btn{appearance:none;border:none;border-radius:12px;padding:10px 14px;font-weight:900;cursor:pointer}
    .btn-primary{background:linear-gradient(135deg,var(--accent),var(--accentDark));color:#052017}
    .btn-primary:hover{filter:brightness(1.05)}
    .btn-ghost{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);color:var(--text)}
    .btn-ghost:hover{border-color:rgba(34,201,151,.35);background:rgba(34,201,151,.06)}
    .btn-danger{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);color:#fca5a5}
    .btn-danger:hover{background:rgba(239,68,68,.18)}
    input,select,textarea{
      width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.10);
      background:rgba(0,0,0,.18);color:var(--text);outline:none
    }
    input:focus,select:focus,textarea:focus{border-color:rgba(34,201,151,.35);box-shadow:0 0 0 3px rgba(34,201,151,.12)}
    label{display:block;font-size:12px;font-weight:900;color:var(--muted);margin-bottom:6px}
    .form{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .col-12{grid-column:span 12}
    .col-6{grid-column:span 6}
    .col-4{grid-column:span 4}
    .col-3{grid-column:span 3}
    .muted{color:var(--muted)}
    .error{padding:10px 12px;border-radius:12px;border:1px solid rgba(239,68,68,.25);background:rgba(239,68,68,.10);color:#fecaca;font-weight:800}
    .ok{padding:10px 12px;border-radius:12px;border:1px solid rgba(34,201,151,.25);background:rgba(34,201,151,.10);color:#a7f3d0;font-weight:800}
    @media (max-width: 980px){
      .sidebar{display:none}
      .content{padding:12px}
      .col-6,.col-4,.col-3{grid-column:span 12}
    }
    .login-shell{min-height:100vh;display:flex}
    .login-left{width:480px;background:linear-gradient(180deg,#0f1117,#0b0f14);border-right:1px solid var(--border);padding:34px;display:flex;flex-direction:column;gap:22px}
    .login-right{flex:1;display:flex;align-items:center;justify-content:center;padding:22px}
    .login-card{width:100%;max-width:420px}
    .big{font-size:34px;font-weight:900;letter-spacing:-.7px}
    .glow{color:var(--accent)}
    .small{font-size:13px;color:var(--muted);line-height:1.65}
    .otp{display:flex;gap:10px}
    .otp input{font-size:22px;text-align:center;font-weight:900;padding:12px 0}
  </style>
</head>
<body>
  <?php
}

function render_login_html(string $panel, ?array $flash, string $prefill_email): void {
  ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SMG — Sign In</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f7f7f8;--surface:#fff;
  --sidebar-bg:#0f1117;
  --accent:#10B981;--accent-dim:#d1fae5;--accent-dark:#059669;
  --text:#111318;--text-muted:#6b7280;--text-faint:#9ca3af;
  --border:#e5e7eb;--border-dark:#1f2230;
  --red:#ef4444;--yellow:#f59e0b;--blue:#3b82f6;
  --radius:10px;--shadow:0 1px 3px rgba(0,0,0,.07);--shadow-md:0 4px 24px rgba(0,0,0,.1);
}
html,body{height:100%;font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text)}

/* ── LAYOUT ─────────────────────────────────── */
.page{display:flex;min-height:100vh}

/* LEFT PANEL */
.left{
  width:480px;flex-shrink:0;
  background:var(--sidebar-bg);
  display:flex;flex-direction:column;
  justify-content:space-between;
  padding:40px;
  position:relative;overflow:hidden;
}
/* subtle grid pattern */
.left::before{
  content:'';position:absolute;inset:0;
  background-image:
    linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);
  background-size:32px 32px;
  pointer-events:none;
}
/* emerald glow blob */
.left::after{
  content:'';position:absolute;
  width:360px;height:360px;
  background:radial-gradient(circle,rgba(16,185,129,.18) 0%,transparent 70%);
  bottom:-80px;right:-80px;
  pointer-events:none;
}

.left-top{position:relative;z-index:1}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:60px}
.logo-mark{
  width:40px;height:40px;border-radius:10px;
  background:var(--accent);
  display:flex;align-items:center;justify-content:center;
  font-size:18px;font-weight:700;color:#fff;
  flex-shrink:0;
}
.logo-text{color:#fff;font-size:17px;font-weight:600}
.logo-sub{color:#4b5563;font-size:12px;margin-top:1px}

.left-headline{
  font-size:32px;font-weight:700;color:#fff;
  line-height:1.25;margin-bottom:16px;letter-spacing:-.5px;
}
.left-headline span{color:var(--accent)}
.left-desc{font-size:14px;color:#6b7280;line-height:1.65;max-width:320px}

.features{margin-top:48px;display:flex;flex-direction:column;gap:16px;position:relative;z-index:1}
.feature{display:flex;align-items:flex-start;gap:14px}
.feature-icon{
  width:36px;height:36px;border-radius:9px;flex-shrink:0;
  background:rgba(16,185,129,.12);
  display:flex;align-items:center;justify-content:center;
  color:var(--accent);margin-top:1px;
}
.feature-icon svg{width:16px;height:16px}
.feature-title{font-size:13.5px;font-weight:600;color:#e5e7eb;margin-bottom:3px}
.feature-desc{font-size:12.5px;color:#4b5563;line-height:1.5}

.left-bottom{position:relative;z-index:1}
.left-tagline{font-size:12px;color:#374151;font-style:italic}

/* RIGHT PANEL */
.right{
  flex:1;display:flex;align-items:center;justify-content:center;
  padding:40px 24px;background:var(--bg);
}
.card{
  width:100%;max-width:420px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:16px;
  box-shadow:var(--shadow-md);
  overflow:hidden;
}

/* PANEL */
.panel{display:none;padding:28px}
.panel.active{display:block;animation:fadeUp .2s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

.panel-title{font-size:18px;font-weight:700;margin-bottom:4px}
.panel-sub{font-size:13px;color:var(--text-muted);margin-bottom:24px}

/* FORM */
.form-group{margin-bottom:16px}
label{display:block;font-size:12.5px;font-weight:600;color:var(--text-muted);margin-bottom:6px;letter-spacing:.02em}
.input-wrap{position:relative}
input[type="email"],input[type="password"],input[type="text"]{
  width:100%;padding:10px 14px;
  border:1px solid var(--border);border-radius:8px;
  font-size:13.5px;font-family:inherit;color:var(--text);
  background:var(--surface);
  transition:border-color .15s,box-shadow .15s;outline:none;
}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(16,185,129,.1)}
.input-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text-faint)}
.input-icon~input{padding-left:38px}
.input-toggle{
  position:absolute;right:12px;top:50%;transform:translateY(-50%);
  color:var(--text-faint);cursor:pointer;background:none;border:none;padding:0;
  display:flex;align-items:center;
}
.input-toggle:hover{color:var(--text-muted)}

.row-inline{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.checkbox-label{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted);cursor:pointer;user-select:none}
.checkbox-label input[type="checkbox"]{
  width:16px;height:16px;accent-color:var(--accent);cursor:pointer;
  border-radius:4px;
}
.link{font-size:13px;color:var(--accent);font-weight:500;cursor:pointer;text-decoration:none}
.link:hover{color:var(--accent-dark)}

.btn{
  width:100%;padding:11px;border-radius:8px;
  font-size:14px;font-weight:600;font-family:inherit;
  cursor:pointer;border:none;
  display:flex;align-items:center;justify-content:center;gap:8px;
  transition:all .15s;
}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent-dark);transform:translateY(-1px);box-shadow:0 4px 12px rgba(16,185,129,.3)}
.btn-primary:active{transform:translateY(0);box-shadow:none}
.btn-ghost{
  background:var(--surface);color:var(--text-muted);
  border:1px solid var(--border);margin-top:10px;
}
.btn-ghost:hover{background:var(--bg)}

.divider{display:flex;align-items:center;gap:12px;margin:20px 0}
.divider-line{flex:1;height:1px;background:var(--border)}
.divider-text{font-size:12px;color:var(--text-faint);font-weight:500}

/* 2FA panel */
.totp-wrap{text-align:center;padding:8px 0 16px}
.totp-icon{
  width:56px;height:56px;border-radius:14px;
  background:var(--accent-dim);color:var(--accent-dark);
  display:flex;align-items:center;justify-content:center;
  margin:0 auto 14px;
}
.totp-title{font-size:16px;font-weight:700;margin-bottom:6px}
.totp-desc{font-size:13px;color:var(--text-muted);line-height:1.5;margin-bottom:24px}
.otp-inputs{display:flex;gap:10px;justify-content:center;margin-bottom:24px}
.otp-input{
  width:48px;height:56px;
  border:1.5px solid var(--border);border-radius:9px;
  text-align:center;font-size:22px;font-weight:700;
  font-family:inherit;color:var(--text);outline:none;
  transition:border-color .15s,box-shadow .15s;
}
.otp-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(16,185,129,.1)}
.totp-resend{font-size:13px;color:var(--text-muted);margin-bottom:0}
.totp-resend span{color:var(--accent);cursor:pointer;font-weight:500}
.totp-resend span:hover{color:var(--accent-dark)}

/* ALERT */
.alert{
  display:flex;align-items:flex-start;gap:10px;
  padding:11px 14px;border-radius:8px;font-size:13px;
  margin-bottom:16px;line-height:1.45;
}
.alert-warn{background:#fef3c7;color:#92400e;border:1px solid #fde68a}
.alert-error{background:#fee2e2;color:#991b1b;border:1px solid #fecaca;display:none}

/* FOOTER */
.card-footer{
  padding:14px 28px;background:#fafafa;
  border-top:1px solid var(--border);
  font-size:12.5px;color:var(--text-faint);text-align:center;
}

/* STEP INDICATOR */
.steps{display:flex;align-items:center;justify-content:center;gap:6px;margin-bottom:24px}
.step{width:28px;height:4px;border-radius:999px;background:var(--border);transition:background .25s}
.step.done{background:var(--accent)}
.step.active{background:var(--accent);opacity:.5}

/* RESPONSIVE */
@media(max-width:860px){
  .left{display:none}
  .right{padding:24px 16px}
}
@media(max-width:480px){
  .card{border-radius:12px}
  .panel{padding:22px 18px}
}
</style>
</head>
<body>

<div class="page">

  <!-- LEFT: BRAND PANEL -->
  <div class="left">
    <div class="left-top">
      <div class="logo">
        <div class="logo-mark">S</div>
        <div>
          <div class="logo-text">SMG</div>
          <div class="logo-sub">Santiago Management Group</div>
        </div>
      </div>
      <div class="left-headline">
        Your properties,<br><span>fully under control.</span>
      </div>
      <div class="left-desc">
        A self-hosted platform to manage tenants, leases, maintenance, payments, and vendors — all in one place.
      </div>
      <div class="features">
        <div class="feature">
          <div class="feature-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
          </div>
          <div>
            <div class="feature-title">Multi-role access</div>
            <div class="feature-desc">Owner, Property Manager, Tenant and Vendor portals with granular permissions.</div>
          </div>
        </div>
        <div class="feature">
          <div class="feature-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
          </div>
          <div>
            <div class="feature-title">Automated payments</div>
            <div class="feature-desc">Rent collection via Square and Stripe with auto-reminders and late fee tracking.</div>
          </div>
        </div>
        <div class="feature">
          <div class="feature-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>
          </div>
          <div>
            <div class="feature-title">Maintenance workflows</div>
            <div class="feature-desc">Submit, track, assign and close maintenance requests with vendor coordination.</div>
          </div>
        </div>
      </div>
    </div>
    <div class="left-bottom">
      <div class="left-tagline">Secure · Self-hosted · Built for growth</div>
    </div>
  </div>

  <!-- RIGHT: AUTH PANEL -->
  <div class="right">
    <div class="card">
      <form method="post" action="<?=h(app_url(['page'=>$panel]))?>">
        <input type="hidden" name="_panel" value="<?=h($panel)?>"/>

      <!-- CARD HEADER BRAND -->
      <div style="padding:24px 28px 0;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);padding-bottom:20px">
        <div style="width:34px;height:34px;border-radius:8px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#fff;flex-shrink:0">S</div>
        <div>
          <div style="font-size:14px;font-weight:700;color:var(--text);line-height:1.2">Santiago Management Group</div>
          <div style="font-size:11.5px;color:var(--text-faint);margin-top:1px">Management Portal</div>
        </div>
      </div>

      <!-- ── SIGN IN PANEL ── -->
      <div class="panel <?=($panel==='login')?'active':''?>" id="panel-signin">
        <div class="panel-title">Welcome back</div>
        <div class="panel-sub">Enter your credentials and authenticator code to continue.</div>

        <div class="alert alert-error" id="login-error" style="<?=($flash && $flash['type']=='error')?'display:flex':'display:none'?>">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <?=h($flash['msg'] ?? '')?>
        </div>

        <div class="form-group">
          <label>Email address</label>
          <div class="input-wrap">
            <div class="input-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,12 2,6"/></svg>
            </div>
            <input type="email" id="signin-email" name="email" placeholder="you@example.com" autocomplete="email" value="<?=h($prefill_email)?>"/>
          </div>
        </div>

        <div class="form-group">
          <label>Password</label>
          <div class="input-wrap">
            <div class="input-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            </div>
            <input type="password" id="signin-password" name="password" placeholder="••••••••" autocomplete="current-password"/>
            <button class="input-toggle" type="button"  tabindex="-1">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
        </div>



        <div class="row-inline">
          <label class="checkbox-label">
            <input type="checkbox" checked/> Remember me
          </label>
          <a class="link" href="<?=h(app_url(['page'=>'forgot']))?>">Forgot password?</a>
        </div>

        <button class="btn btn-primary" type="submit">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          Sign In
        </button>

        <div class="divider"><div class="divider-line"></div><span class="divider-text">or continue with</span><div class="divider-line"></div></div>

        <button class="btn btn-ghost" style="gap:10px">
          <svg width="16" height="16" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
          Sign in with Google
        </button>
      </div>

      <!-- ── 2FA PANEL ── -->
      <div class="panel <?=($panel==='totp')?'active':''?>" id="panel-2fa">
        <div class="totp-wrap">
          <div class="totp-icon">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
          </div>
          <div class="totp-title">Two-factor authentication</div>
          <div class="totp-desc">Enter the 6-digit code from your<br>authenticator app to continue.</div>
          <div class="steps">
            <div class="step done"></div>
            <div class="step active"></div>
          </div>
          <div class="otp-inputs" id="otp-inputs">
            <input type="hidden" name="code" id="otp-code-hidden" value=""/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,0)"/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,1)"/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,2)"/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,3)"/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,4)"/>
            <input class="otp-input" maxlength="1" type="text" inputmode="numeric" pattern="[0-9]" oninput="otpNext(this,5)"/>
          </div>
        </div>
        <button class="btn btn-primary" type="submit">Verify & Sign In</button>
        <button class="btn btn-ghost"  style="margin-top:10px">← Back to sign in</a>
      </div>

      <!-- ── FORGOT PASSWORD PANEL ── -->
      <div class="panel <?=($panel==='forgot')?'active':''?>" id="panel-forgot">
        <div class="panel-title">Reset your password</div>
        <div class="panel-sub">Enter your email and we'll send you a reset link.</div>

        <div class="alert alert-warn" style="display:flex">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Reset links are only sent to verified SMG accounts.
        </div>

        <div class="form-group">
          <label>Email address</label>
          <div class="input-wrap">
            <div class="input-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,12 2,6"/></svg>
            </div>
            <input type="email" placeholder="you@example.com"/>
          </div>
        </div>

        <button class="btn btn-primary" type="submit">Send Reset Link</button>
        <a class="btn btn-ghost" href="<?=h(app_url(['page'=>'login']))?>">← Back to sign in</a>
      </div>

      <!-- ── PASSWORD RESET SENT ── -->
      <div class="panel <?=($panel==='reset_sent')?'active':''?>" id="panel-reset-sent">
        <div style="text-align:center;padding:16px 0">
          <div style="width:56px;height:56px;border-radius:14px;background:var(--accent-dim);color:var(--accent-dark);display:flex;align-items:center;justify-content:center;margin:0 auto 16px">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,12 2,6"/></svg>
          </div>
          <div style="font-size:17px;font-weight:700;margin-bottom:8px">Check your inbox</div>
          <div style="font-size:13px;color:var(--text-muted);line-height:1.6;margin-bottom:24px">We sent a password reset link to your email address. The link expires in 30 minutes.</div>
          <button class="btn btn-primary" type="submit">Back to Sign In</a>
        </div>
      </div>

            </form>

      <div class="card-footer">
        SMG v1.0 &nbsp;·&nbsp; Self-hosted &nbsp;·&nbsp; <span style="color:var(--accent)">Secured with TLS</span>
      </div>
    </div>
  </div>
</div>




<script>
(function(){
  function collectOtp(){
    var hidden=document.getElementById('otp-code-hidden');
    if(!hidden) return;
    var inputs=Array.from(document.querySelectorAll('#otp-inputs .otp-input'));
    var code=inputs.map(i=> (i.value||'').replace(/\D/g,'').slice(0,1)).join('');
    hidden.value=code;
  }
  document.addEventListener('input', function(e){
    if(e.target && e.target.classList && e.target.classList.contains('otp-input')) collectOtp();
  });
  document.addEventListener('submit', function(e){ collectOtp(); }, true);
})();

(function(){
  document.addEventListener('DOMContentLoaded', function(){
    var inputs = Array.from(document.querySelectorAll('#otp-inputs .otp-input'));

    inputs.forEach(function(input, idx){
      input.addEventListener('input', function(){
        input.value = input.value.replace(/\D/g,'');
        if(input.value && inputs[idx+1]) {
          inputs[idx+1].focus();
        }
      });

      input.addEventListener('keydown', function(e){
        if(e.key === 'Backspace' && !input.value && inputs[idx-1]) {
          inputs[idx-1].focus();
        }
      });

      input.addEventListener('paste', function(e){
        e.preventDefault();
        var text = (e.clipboardData || window.clipboardData).getData('text');
        var digits = text.replace(/\D/g,'').slice(0, inputs.length);

        digits.split('').forEach(function(d, i){
          if(inputs[i]) inputs[i].value = d;
        });

        if(inputs[digits.length-1]) {
          inputs[digits.length-1].focus();
        }
      });

      input.addEventListener('focus', function(){
        input.select();
      });
    });
  });
})();
</script>

<script id="SMG_FORCE_SUBMIT">
document.addEventListener("DOMContentLoaded", function () {
  var btns = Array.from(document.querySelectorAll("button, input[type=button], input[type=submit]"));
  var signInBtn = btns.find(b => (b.textContent || b.value || "").toLowerCase().includes("sign in"));
  if (!signInBtn) return;
  signInBtn.addEventListener("click", function (e) {
    var f = signInBtn.closest("form") || document.querySelector("form");
    if (!f) return;
    try { f.requestSubmit ? f.requestSubmit() : f.submit(); } catch (_) { try { f.submit(); } catch(__) {} }
  }, true);
});
</script>
</body>
</html>

<?php
}


function render_login_left(): void {
  ?>
  <div class="login-left">
    <div class="brand" style="border-bottom:none;margin:0;padding:0">
      <div class="mark">S</div>
      <div>
        <div class="t1">SMG</div>
        <div class="t2">Santiago Management Group</div>
      </div>
    </div>
    <div>
      <div class="big">Your properties,<br><span class="glow">fully under control.</span></div>
      <div class="small" style="margin-top:10px">Self-hosted platform to manage tenants, leases, maintenance, payments, and vendors — all in one place.</div>
    </div>
    <div class="card" style="box-shadow:none">
      <div class="bd">
        <div class="small"><b class="glow">Security note:</b> TOTP is required on login (as you requested).</div>
        <div class="small" style="margin-top:8px">If you haven’t run <code style="display:inline-block;padding:2px 6px;border-radius:8px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03)">init_db.php</code> yet, do that first to get demo users + TOTP secrets.</div>
      </div>
    </div>
    <div class="small" style="margin-top:auto;opacity:.7">“Institutional real estate + modern fintech product.”</div>
  </div>
  <?php
}

function render_app_shell_start(array $u, string $active, string $title): void {
  $initial = strtoupper(substr($u['full_name'], 0, 1));
  ?>
  <div class="wrap">
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">S</div>
        <div>
          <div class="t1">SMG</div>
          <div class="t2">Santiago Management Group</div>
        </div>
      </div>

      <div class="nav">
        <?php
          $links = nav_links_for_role($u['role']);
          foreach ($links as $key => $label) {
            $cls = ($key === $active) ? 'active' : '';
            echo '<a class="'.$cls.'" href="index.php?page='.$key.'">'.h($label).'</a>';
          }
        ?>
      </div>

      <div class="me">
        <div class="chip">
          <div class="avatar"><?=h($initial)?></div>
          <div style="min-width:0">
            <div style="font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><?=h($u['full_name'])?></div>
            <div class="sub"><?=h($u['role'])?> • <?=h($u['email'])?></div>
          </div>
        </div>
        <div class="row" style="margin-top:10px">
          <a class="btnlink" href="index.php?page=account" style="flex:1">Profile</a>
          <form method="post" action="<?=h(app_url(['action'=>'logout']))?>" style="margin:0">
            <button class="btnlink" type="submit">Sign out</button>
          </form>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="top">
        <div class="title"><?=h($title)?></div>
        <div class="row">
          <a class="btnlink" href="index.php?page=help">Help</a>
        </div>
      </div>
      <div class="content">
  <?php
}

function render_app_shell_end(): void {
  ?>
      </div>
    </main>
  </div>
</body>
</html>
  <?php
}


// ─────────────────────────────────────────────────────────────────────
// Owner UI — matches owner.html exactly
// ─────────────────────────────────────────────────────────────────────
function render_owner_head(string $title): void { ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title><?=h($title)?></title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --sidebar-w:240px;--bg:#f7f7f8;--surface:#fff;
    --sidebar-bg:#0f1117;--sidebar-hover:#1a1d27;
    --accent:#10B981;--accent-dim:#d1fae5;--accent-dark:#059669;
    --text:#111318;--text-muted:#6b7280;--text-faint:#9ca3af;
    --border:#e5e7eb;--border-dark:#1f2230;
    --red:#ef4444;--yellow:#f59e0b;--blue:#3b82f6;
    --radius:10px;--shadow:0 1px 3px rgba(0,0,0,.07);--shadow-md:0 4px 16px rgba(0,0,0,.1);
  }
  html,body{height:100%;font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text)}
  a{color:inherit;text-decoration:none}
  .app{display:flex;height:100vh;overflow:hidden}

  /* SIDEBAR */
  .sidebar{width:var(--sidebar-w);background:var(--sidebar-bg);display:flex;flex-direction:column;flex-shrink:0;z-index:100;transition:transform .25s ease}
  .sidebar-logo{padding:20px 20px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border-dark)}
  .logo-mark{width:32px;height:32px;background:var(--accent);border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:#fff}
  .logo-text{color:#fff;font-weight:600;font-size:15px}.logo-sub{color:#4b5563;font-size:11px}
  .sidebar-section{padding:12px 12px 4px}
  .sidebar-label{font-size:10px;font-weight:600;letter-spacing:.08em;color:#4b5563;text-transform:uppercase;padding:0 8px;margin-bottom:4px}
  .nav-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:7px;color:#9ca3af;font-size:13.5px;font-weight:500;cursor:pointer;transition:all .15s;user-select:none;text-decoration:none}
  .nav-item:hover{background:var(--sidebar-hover);color:#e5e7eb}
  .nav-item.active{background:rgba(16,185,129,.12);color:var(--accent)}
  .nav-item svg{width:16px;height:16px;flex-shrink:0}
  .nav-badge{margin-left:auto;background:var(--accent);color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:999px}
  .nav-badge.warn{background:var(--yellow);color:#000}
  .sidebar-bottom{margin-top:auto;border-top:1px solid var(--border-dark);padding:12px;position:relative}
  .user-chip{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:7px;cursor:pointer;transition:background .15s}
  .user-chip:hover{background:var(--sidebar-hover)}
  .avatar{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#059669);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0}
  .user-name{color:#e5e7eb;font-size:13px;font-weight:500}.user-role{color:#6b7280;font-size:11px}
  .logout-popup{position:absolute;bottom:72px;left:12px;right:12px;background:#1a1d27;border:1px solid var(--border-dark);border-radius:8px;overflow:hidden;display:none;box-shadow:var(--shadow-md)}
  .logout-popup.open{display:block}
  .logout-item{padding:11px 14px;font-size:13px;color:#9ca3af;cursor:pointer;display:flex;align-items:center;gap:8px;transition:background .15s;background:none;border:none;width:100%;font-family:inherit;text-decoration:none;text-align:left}
  .logout-item:hover{background:var(--sidebar-hover);color:#e5e7eb}
  .logout-item.danger{color:#f87171}.logout-item.danger:hover{color:var(--red)}

  /* MAIN */
  .main{flex:1;display:flex;flex-direction:column;overflow:hidden}
  .topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:56px;display:flex;align-items:center;gap:12px;flex-shrink:0;position:relative}
  .hamburger{display:none;cursor:pointer;color:var(--text-muted);background:none;border:none;padding:4px}
  .topbar-title{font-size:15px;font-weight:600;flex:1}
  .topbar-actions{display:flex;align-items:center;gap:8px}
  .content{flex:1;overflow-y:auto;padding:24px}

  /* BUTTONS */
  .btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:7px;font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:inherit;text-decoration:none}
  .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent-dark)}
  .btn-ghost{background:transparent;color:var(--text-muted);border:1px solid var(--border)}.btn-ghost:hover{background:var(--bg)}
  .btn-danger{background:#fee2e2;color:#dc2626;border:none}.btn-danger:hover{background:#fecaca}
  .icon-btn{width:34px;height:34px;border-radius:7px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--text-muted);border:1px solid var(--border);background:var(--surface);transition:all .15s;position:relative}
  .icon-btn:hover{background:var(--bg)}
  .notif-dot{position:absolute;top:6px;right:6px;width:7px;height:7px;border-radius:50%;background:var(--red);border:1.5px solid #fff}

  /* NOTIFICATION PANEL */
  .notif-panel{position:absolute;top:56px;right:16px;width:340px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-md);z-index:200;display:none}
  .notif-panel.open{display:block}
  .notif-header{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .notif-title{font-size:14px;font-weight:600}
  .notif-clear{font-size:12px;color:var(--accent);cursor:pointer}
  .notif-item{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;gap:10px;cursor:pointer;transition:background .15s}
  .notif-item:hover{background:var(--bg)}
  .notif-item:last-child{border-bottom:none}
  .notif-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .notif-body{flex:1}
  .notif-text{font-size:13px;line-height:1.4}
  .notif-time{font-size:11.5px;color:var(--text-faint);margin-top:3px}
  .notif-unread{background:rgba(16,185,129,.05);border-left:3px solid var(--accent)}

  /* METRICS */
  .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
  .metric-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow);cursor:pointer;transition:box-shadow .15s,transform .15s}
  .metric-card:hover{box-shadow:var(--shadow-md);transform:translateY(-1px)}
  .metric-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
  .metric-label{font-size:12.5px;font-weight:500;color:var(--text-muted)}
  .metric-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center}
  .metric-icon.green{background:var(--accent-dim);color:var(--accent-dark)}
  .metric-icon.blue{background:#dbeafe;color:#2563eb}
  .metric-icon.yellow{background:#fef3c7;color:#d97706}
  .metric-icon.red{background:#fee2e2;color:#dc2626}
  .metric-value{font-size:26px;font-weight:700;letter-spacing:-.5px;line-height:1;margin-bottom:6px}
  .metric-change{font-size:12px;color:var(--text-faint)}
  .metric-change .up{color:var(--accent);font-weight:600}
  .metric-change .down{color:var(--red);font-weight:600}

  /* CARD */
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;margin-bottom:16px}
  .card-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .card-title{font-size:14px;font-weight:600}
  .card-action{font-size:12.5px;color:var(--accent);font-weight:500;cursor:pointer}
  .card-action:hover{color:var(--accent-dark)}

  /* GRID */
  .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
  .grid-3-1{display:grid;grid-template-columns:2fr 1fr;gap:16px}

  /* TABLE */
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:10px 20px;font-size:11.5px;font-weight:600;letter-spacing:.04em;color:var(--text-muted);text-transform:uppercase;border-bottom:1px solid var(--border);background:#fafafa}
  td{padding:12px 20px;font-size:13.5px;border-bottom:1px solid var(--border);vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#fafafa}
  .td-name{font-weight:500}.td-sub{font-size:12px;color:var(--text-muted);margin-top:2px}
  .td-actions{display:flex;gap:6px}
  .action-btn{padding:4px 10px;border-radius:5px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text-muted);transition:all .15s;white-space:nowrap;text-decoration:none;display:inline-flex;align-items:center}
  .action-btn:hover{background:var(--bg);color:var(--text)}
  .action-btn.primary{border-color:var(--accent-dim);color:var(--accent-dark);background:var(--accent-dim)}
  .action-btn.danger{border-color:#fee2e2;color:var(--red);background:#fff}
  .unit-link{color:var(--accent);font-weight:500;cursor:pointer}

  /* BADGE */
  .badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:999px;font-size:11.5px;font-weight:600}
  .badge::before{content:'';width:6px;height:6px;border-radius:50%}
  .badge-green{background:#d1fae5;color:#065f46}.badge-green::before{background:var(--accent)}
  .badge-yellow{background:#fef3c7;color:#92400e}.badge-yellow::before{background:var(--yellow)}
  .badge-red{background:#fee2e2;color:#991b1b}.badge-red::before{background:var(--red)}
  .badge-blue{background:#dbeafe;color:#1e40af}.badge-blue::before{background:var(--blue)}
  .badge-gray{background:#f3f4f6;color:#374151}.badge-gray::before{background:#9ca3af}

  /* MAINT */
  .maint-item{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:12px}
  .maint-item:last-child{border-bottom:none}
  .maint-num{width:28px;height:28px;border-radius:6px;background:var(--bg);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:var(--text-muted);flex-shrink:0;margin-top:2px}
  .maint-body{flex:1}
  .maint-title{font-size:13.5px;font-weight:500;margin-bottom:4px}
  .maint-meta{font-size:12px;color:var(--text-muted);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .maint-actions{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}

  /* CHART */
  .chart-area{padding:20px}
  .chart-months{display:flex;gap:10px}
  .chart-month{flex:1;display:flex;flex-direction:column;gap:6px}
  .chart-month-label{font-size:11.5px;color:var(--text-muted);font-weight:500;text-align:center;padding-bottom:2px}
  .bar-group{display:flex;flex-direction:column;gap:4px}
  .bar-row{display:flex;align-items:center;gap:8px}
  .bar-track{flex:1;background:#f3f4f6;border-radius:4px;overflow:hidden;height:14px}
  .bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
  .bar-fill.income{background:var(--accent)}
  .bar-fill.expense{background:#cbd5e1}
  .bar-amount{font-size:11px;font-weight:600;width:42px;text-align:right;white-space:nowrap}
  .bar-amount.income{color:var(--accent-dark)}
  .bar-amount.expense{color:var(--text-muted)}
  .bar-type{font-size:10px;color:var(--text-faint);width:14px;flex-shrink:0}
  .chart-legend{display:flex;gap:16px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border)}
  .legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-muted)}
  .legend-dot{width:10px;height:10px;border-radius:3px}

  /* ACTIVITY */
  .activity-item{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:10px}
  .activity-item:last-child{border-bottom:none}
  .activity-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}
  .activity-text{font-size:13px;line-height:1.5}
  .activity-time{font-size:11.5px;color:var(--text-faint);margin-top:2px}

  /* PROP CARD */
  .prop-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
  .prop-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;transition:box-shadow .15s,transform .15s;cursor:pointer}
  .prop-card:hover{box-shadow:var(--shadow-md);transform:translateY(-2px)}
  .prop-img{width:100%;height:140px;background:linear-gradient(135deg,#1a1d27,#0f1117);display:flex;align-items:center;justify-content:center}
  .prop-img svg{opacity:.15}
  .prop-body{padding:16px}
  .prop-name{font-size:14px;font-weight:600;margin-bottom:4px}
  .prop-addr{font-size:12.5px;color:var(--text-muted);margin-bottom:12px}
  .prop-stats{display:flex;gap:16px}
  .prop-stat{text-align:center}
  .prop-stat-val{font-size:18px;font-weight:700}
  .prop-stat-label{font-size:11px;color:var(--text-muted)}
  .prop-footer{padding:12px 16px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}

  /* PAYMENT */
  .payment-item{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px}
  .payment-item:last-child{border-bottom:none}
  .payment-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .payment-icon.in{background:var(--accent-dim);color:var(--accent-dark)}
  .payment-icon.out{background:#fee2e2;color:#dc2626}
  .payment-body{flex:1}
  .payment-name{font-size:13.5px;font-weight:500}
  .payment-meta{font-size:12px;color:var(--text-muted)}
  .payment-amount{font-size:14px;font-weight:700}
  .payment-amount.in{color:var(--accent-dark)}
  .payment-amount.out{color:var(--red)}

  /* VENDOR */
  .vendor-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;display:flex;align-items:center;gap:14px;box-shadow:var(--shadow);margin-bottom:12px;transition:box-shadow .15s}
  .vendor-card:hover{box-shadow:var(--shadow-md)}
  .vendor-avatar{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:#fff;flex-shrink:0}
  .vendor-name{font-size:14px;font-weight:600;margin-bottom:2px}
  .vendor-trade{font-size:12.5px;color:var(--text-muted)}
  .vendor-stats{margin-left:auto;text-align:right}
  .vendor-jobs{font-size:13px;font-weight:600}

  /* LEASE TIMELINE */
  .lease-timeline{padding:20px}
  .timeline-item{display:flex;gap:14px;margin-bottom:20px}
  .timeline-line{display:flex;flex-direction:column;align-items:center}
  .timeline-dot{width:10px;height:10px;border-radius:50%;background:var(--accent);flex-shrink:0;margin-top:4px}
  .timeline-trail{flex:1;width:2px;background:var(--border);margin:4px 0}
  .timeline-body{flex:1;padding-bottom:4px}
  .timeline-title{font-size:13.5px;font-weight:500;margin-bottom:3px}
  .timeline-meta{font-size:12px;color:var(--text-muted)}

  /* PAGE HEADER */
  .page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
  .page-title{font-size:20px;font-weight:700}
  .page-sub{font-size:13px;color:var(--text-muted);margin-top:2px}

  /* MODAL */
  .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:500;display:none;align-items:center;justify-content:center;padding:20px}
  .modal-backdrop.open{display:flex}
  .modal{background:var(--surface);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.2);width:100%;max-width:520px;max-height:90vh;overflow-y:auto;animation:modalIn .2s ease}
  .modal.wide{max-width:640px}
  @keyframes modalIn{from{opacity:0;transform:scale(.96) translateY(8px)}to{opacity:1;transform:scale(1) translateY(0)}}
  .modal-header{padding:20px 24px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .modal-title{font-size:16px;font-weight:700}
  .modal-close{width:28px;height:28px;border-radius:6px;background:var(--bg);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text-muted);transition:background .15s}
  .modal-close:hover{background:var(--border)}
  .modal-body{padding:20px 24px}
  .modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}

  /* FORMS */
  .form-row{margin-bottom:16px}
  .form-row-2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
  label{display:block;font-size:12.5px;font-weight:600;color:var(--text-muted);margin-bottom:6px;letter-spacing:.02em}
  input,select,textarea{width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:7px;font-size:13.5px;font-family:inherit;color:var(--text);background:var(--surface);transition:border-color .15s,box-shadow .15s;outline:none}
  input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(16,185,129,.1)}
  textarea{resize:vertical;min-height:80px}
  select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b7280' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:30px}
  .form-divider{font-size:12px;font-weight:600;color:var(--text-faint);text-transform:uppercase;letter-spacing:.06em;margin:20px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}

  /* FLASH */
  .flash-ok{padding:10px 16px;border-radius:7px;border:1px solid #6ee7b7;background:#d1fae5;color:#065f46;font-weight:500;margin-bottom:16px}
  .flash-err{padding:10px 16px;border-radius:7px;border:1px solid #fca5a5;background:#fee2e2;color:#991b1b;font-weight:500;margin-bottom:16px}

  /* OVERLAY */
  .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99}

  /* MOBILE */
  @media(max-width:900px){
    .metrics{grid-template-columns:repeat(2,1fr)}
    .grid-2{grid-template-columns:1fr}
    .grid-3-1{grid-template-columns:1fr}
  }
  @media(max-width:700px){
    .sidebar{position:fixed;top:0;left:0;bottom:0;transform:translateX(-100%)}
    .sidebar.open{transform:translateX(0)}
    .overlay.open{display:block}
    .hamburger{display:flex}
    .content{padding:16px}
    .topbar{padding:0 16px}
    th,td{padding:10px 12px}
    .notif-panel{right:8px;width:calc(100vw - 16px)}
  }
  </style>
</head>
<body>
<script>window._u = <?php echo json_encode(app_url()); ?>;</script>
<div class="overlay" id="overlay" onclick="closeSidebar()"></div>
<div class="modal-backdrop" id="modal-backdrop" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modal-box"></div>
</div>
<div class="notif-panel" id="notif-panel">
  <div class="notif-header"><span class="notif-title">Notifications</span><span class="notif-clear" onclick="clearNotifs()">Mark all read</span></div>
  <div class="notif-item notif-unread"><div class="notif-icon" style="background:#fee2e2;color:#dc2626"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div><div class="notif-body"><div class="notif-text">Late payment reminder — rent overdue</div><div class="notif-time">Today</div></div></div>
  <div class="notif-item notif-unread"><div class="notif-icon" style="background:#fef3c7;color:#d97706"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg></div><div class="notif-body"><div class="notif-text">New maintenance request submitted</div><div class="notif-time">Today</div></div></div>
  <div class="notif-item"><div class="notif-icon" style="background:#d1fae5;color:#059669"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg></div><div class="notif-body"><div class="notif-text">Rent payment received</div><div class="notif-time">Yesterday</div></div></div>
</div>
<?php }

function render_owner_shell_start(array $u, string $active, string $pageTitle, string $btnLabel = '', string $btnModal = '', array $badges = []): void {
  $initial = strtoupper(substr($u['full_name'], 0, 1));
  // nav: [key => [label, icon, badge?, badgeWarn?]]
  $sections = [
    'Overview' => [
      'owner_dashboard' => ['Dashboard','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>'],
      'owner_properties' => ['Properties','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9,22 9,12 15,12 15,22"/></svg>'],
      'owner_tenants'    => ['Tenants','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>', $badges['tenants'] ?? null, false],
    ],
    'Operations' => [
      'owner_maintenance' => ['Maintenance','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>', $badges['maintenance'] ?? null, true],
      'owner_vendors'    => ['Vendors','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/></svg>'],
      'owner_leases'     => ['Leases','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'],
    ],
    'Finance' => [
      'owner_payments' => ['Payments','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>'],
      'owner_reports'  => ['Reports','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'],
    ],
    'System' => [
      'owner_users'    => ['Users','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 10-16 0"/></svg>'],
      'owner_settings' => ['Settings','<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M12 2v2M12 20v2M20 12h2M2 12h2M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41"/></svg>'],
    ],
  ];
  ?>
  <div class="app">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <div class="logo-mark">S</div>
        <div><div class="logo-text">SMG</div><div class="logo-sub">Santiago Management</div></div>
      </div>
      <?php foreach ($sections as $label => $links): ?>
      <div class="sidebar-section">
        <div class="sidebar-label"><?=h($label)?></div>
        <?php foreach ($links as $key => $item):
          [$name, $icon] = $item;
          $badge   = $item[2] ?? null;
          $badgeWarn = $item[3] ?? false;
        ?>
          <a class="nav-item <?=($key===$active)?'active':''?>" href="<?=h(app_url(['page'=>$key]))?>"><?=$icon?><?=h($name)?><?php if ($badge): ?><span class="nav-badge <?=($badgeWarn?'warn':'')?>"><?=h((string)$badge)?></span><?php endif; ?></a>
        <?php endforeach; ?>
      </div>
      <?php endforeach; ?>
      <div class="sidebar-bottom">
        <div class="logout-popup" id="logout-popup">
          <a class="logout-item" href="<?=h(app_url(['page'=>'account']))?>">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 10-16 0"/></svg>Profile Settings
          </a>
          <form method="post" action="<?=h(app_url(['action'=>'logout']))?>" style="margin:0">
            <button class="logout-item danger" type="submit">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>Sign Out
            </button>
          </form>
        </div>
        <div class="user-chip" onclick="document.getElementById('logout-popup').classList.toggle('open')">
          <div class="avatar"><?=h($initial)?></div>
          <div><div class="user-name"><?=h($u['full_name'])?></div><div class="user-role">Owner</div></div>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" style="margin-left:auto"><polyline points="18 15 12 9 6 15"/></svg>
        </div>
      </div>
    </aside>
    <div class="main">
      <div class="topbar">
        <button class="hamburger" onclick="toggleSidebar()">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
        </button>
        <div class="topbar-title"><?=h($pageTitle)?></div>
        <div class="topbar-actions">
          <div class="icon-btn" id="notif-btn" onclick="toggleNotif()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
            <div class="notif-dot" id="notif-dot"></div>
          </div>
          <?php if ($btnLabel): ?><button class="btn btn-primary" onclick="openModal('<?=h($btnModal)?>')"><?=h($btnLabel)?></button><?php endif; ?>
        </div>
      </div>
      <div class="content">
  <?php
}

function render_owner_shell_end(string $jsData = ''): void { ?>
      </div><!-- .content -->
    </div><!-- .main -->
  </div><!-- .app -->

<script>
// Sidebar
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('overlay').classList.toggle('open');}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.remove('open');}
document.addEventListener('click',e=>{
  const lp=document.getElementById('logout-popup');
  if(lp&&!e.target.closest('.sidebar-bottom')&&lp.classList.contains('open'))lp.classList.remove('open');
});

// Notifications
function toggleNotif(){document.getElementById('notif-panel').classList.toggle('open');}
function closeNotif(){document.getElementById('notif-panel').classList.remove('open');}
function clearNotifs(){document.querySelectorAll('.notif-unread').forEach(el=>el.classList.remove('notif-unread'));const d=document.getElementById('notif-dot');if(d)d.style.display='none';}
document.addEventListener('click',e=>{
  const np=document.getElementById('notif-panel');
  if(np&&!e.target.closest('#notif-btn')&&!e.target.closest('#notif-panel')&&np.classList.contains('open'))closeNotif();
});

// Modal
function closeModal(){document.getElementById('modal-backdrop').classList.remove('open');}
function openModal(type, name){
  const backdrop = document.getElementById('modal-backdrop');
  const box = document.getElementById('modal-box');
  box.className = 'modal';
  const X = `<button class="modal-close" onclick="closeModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`;
  const footer = (label, cancel='Cancel') => `<div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal()">${cancel}</button><button class="btn btn-primary" type="submit">${label}</button></div>`;

  // ── ADD PROPERTY ─────────────────────────────────────────────
  if(type === 'add-property'){
    box.className = 'modal wide';
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_property">
        <div class="modal-header"><span class="modal-title">Add New Property</span>${X}</div>
        <div class="modal-body">
          <div class="form-row">
            <label>Property Name</label>
            <input name="name" placeholder="e.g. 89 Gallup St" required/>
          </div>
          <div class="form-row">
            <label>Street Address</label>
            <input name="street" placeholder="e.g. 89 Gallup St" required/>
          </div>
          <div class="form-row-2">
            <div><label>City</label><input name="city" placeholder="Providence" required/></div>
            <div><label>State</label>
              <select name="state">
                <option>RI</option><option>MA</option><option>CT</option><option>NY</option><option>NJ</option>
                <option>PA</option><option>FL</option><option>TX</option><option>CA</option><option>Other</option>
              </select>
            </div>
          </div>
          <div class="form-row-2">
            <div><label>ZIP Code</label><input name="zip" placeholder="02905"/></div>
            <div><label>Property Type</label>
              <select name="property_type">
                <option>Single Family</option><option>Multi-Family</option><option>Condo</option>
                <option>Townhouse</option><option>Commercial</option>
              </select>
            </div>
          </div>
          <div class="form-row-2">
            <div><label>Total Units</label><input name="total_units" type="number" min="1" value="1"/></div>
            <div><label>Year Built</label><input name="year_built" placeholder="e.g. 1985"/></div>
          </div>
          <div class="form-divider">Financial Details</div>
          <div class="form-row-2">
            <div><label>Purchase Price ($)</label><input name="purchase_price" type="number" min="0" placeholder="e.g. 280000"/></div>
            <div><label>Monthly Mortgage ($)</label><input name="mortgage" type="number" min="0" placeholder="e.g. 1400"/></div>
          </div>
          <div class="form-row">
            <label>Monthly Escrow / Insurance ($)</label>
            <input name="escrow" type="number" min="0" placeholder="e.g. 320"/>
          </div>
          <div class="form-row">
            <label>Notes</label>
            <textarea name="notes" placeholder="Property notes, HOA details, special considerations…"></textarea>
          </div>
          <div class="form-row">
            <label>Property Image</label>
            <input type="file" name="property_image" accept="image/*"/>
          </div>
        </div>
        ${footer('Add Property')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD UNIT ─────────────────────────────────────────────────
  if(type === 'add-unit'){
    // Grab property options from the hidden data element if present
    const propOpts = (window._propOptions || '') ||
      '<option value="">Select property…</option>';
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_unit">
        <div class="modal-header"><span class="modal-title">Add Unit</span>${X}</div>
        <div class="modal-body">
          <div class="form-row">
            <label>Property</label>
            <select name="property_id" required>${propOpts}</select>
          </div>
          <div class="form-row-2">
            <div><label>Unit Label</label><input name="unit_label" placeholder="1A" required/></div>
            <div><label>Bedrooms</label><input name="bedrooms" type="number" min="0" value="2"/></div>
          </div>
          <div class="form-row-2">
            <div><label>Bathrooms</label><input name="bathrooms" type="number" step="0.5" min="0" value="1"/></div>
            <div><label>Sq Ft</label><input name="sqft" type="number" min="0" value="780"/></div>
          </div>
        </div>
        ${footer('Add Unit')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD TENANT ───────────────────────────────────────────────
  if(type === 'add-tenant'){
    box.className = 'modal wide';
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_user">
        <div class="modal-header"><span class="modal-title">Add Tenant</span>${X}</div>
        <div class="modal-body">
          <div class="form-row-2">
            <div><label>First Name</label><input name="first_name" placeholder="Maria" required/></div>
            <div><label>Last Name</label><input name="last_name" placeholder="Gonzalez" required/></div>
          </div>
          <div class="form-row">
            <label>Email</label><input name="email" type="email" placeholder="tenant@email.com" required/>
          </div>
          <div class="form-row">
            <label>Phone</label><input name="phone" type="tel" placeholder="(401) 555-0100"/>
          </div>
          <input type="hidden" name="role" value="TENANT"/>
        </div>
        ${footer('Create Tenant')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD VENDOR ───────────────────────────────────────────────
  if(type === 'add-vendor'){
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_user">
        <div class="modal-header"><span class="modal-title">Add Vendor</span>${X}</div>
        <div class="modal-body">
          <div class="form-row">
            <label>Business / Full Name</label><input name="first_name" placeholder="Mike's Plumbing" required/>
          </div>
          <div class="form-row">
            <label>Email</label><input name="email" type="email" placeholder="vendor@email.com" required/>
          </div>
          <div class="form-row">
            <label>Trade</label>
            <select name="trade">
              <option>Plumber</option><option>Electrician</option><option>HVAC</option>
              <option>General Handyman</option><option>Landscaping</option><option>Other</option>
            </select>
          </div>
          <div class="form-row">
            <label>Phone</label><input name="phone" type="tel" placeholder="(401) 555-0100"/>
          </div>
          <input type="hidden" name="role" value="VENDOR"/>
          <input type="hidden" name="last_name" value=""/>
        </div>
        ${footer('Add Vendor')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD LEASE ────────────────────────────────────────────────
  if(type === 'add-lease'){
    box.className = 'modal wide';
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_lease">
        <div class="modal-header"><span class="modal-title">New Lease</span>${X}</div>
        <div class="modal-body">
          <div class="form-row">
            <label>Unit</label>
            <select name="unit_id" required>${window._unitOptions||'<option value="">Select unit…</option>'}</select>
          </div>
          <div class="form-row">
            <label>Tenant Email <span style="font-weight:400;color:var(--text-faint)">(must be a registered TENANT user)</span></label>
            <input name="tenant_email" type="email" placeholder="tenant@smg.local" required/>
          </div>
          <div class="form-row-2">
            <div><label>Start Date</label><input name="start_date" type="date" required/></div>
            <div><label>End Date</label><input name="end_date" type="date" required/></div>
          </div>
          <div class="form-row-2">
            <div><label>Monthly Rent ($)</label><input name="rent" type="number" step="0.01" min="0" placeholder="1850.00" required/></div>
            <div><label>Security Deposit ($)</label><input name="deposit" type="number" step="0.01" min="0" placeholder="1850.00"/></div>
          </div>
        </div>
        ${footer('Create Lease')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD MAINTENANCE ──────────────────────────────────────────
  if(type === 'add-maintenance'){
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_maintenance">
        <div class="modal-header"><span class="modal-title">New Maintenance Request</span>${X}</div>
        <div class="modal-body">
          <div class="form-row"><label>Title</label><input name="title" placeholder="Leaking faucet — kitchen sink" required/></div>
          <div class="form-row-2">
            <div><label>Priority</label>
              <select name="priority"><option>Normal</option><option>Urgent</option><option>Low</option></select>
            </div>
            <div><label>Unit</label>
              <select name="unit_id">${window._unitOptions||'<option value="">Select…</option>'}</select>
            </div>
          </div>
          <div class="form-row"><label>Description</label><textarea name="description" placeholder="Describe the issue…"></textarea></div>
        </div>
        ${footer('Submit Request')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── ADD USER ─────────────────────────────────────────────────
  if(type === 'add-user'){
    box.innerHTML = `
      <form method="post" action="${window._u}?action=add_user">
        <div class="modal-header"><span class="modal-title">Add New User</span>${X}</div>
        <div class="modal-body">
          <div class="form-row-2">
            <div><label>First Name</label><input name="first_name" required/></div>
            <div><label>Last Name</label><input name="last_name"/></div>
          </div>
          <div class="form-row"><label>Email</label><input name="email" type="email" required/></div>
          <div class="form-row"><label>Role</label>
            <select name="role"><option value="TENANT">Tenant</option><option value="VENDOR">Vendor</option><option value="OWNER">Owner</option></select>
          </div>
        </div>
        ${footer('Create User')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── RECORD PAYMENT ───────────────────────────────────────────
  if(type === 'record-payment'){
    box.innerHTML = `
      <form method="post" action="${window._u}?action=record_payment">
        <div class="modal-header"><span class="modal-title">Record Payment</span>${X}</div>
        <div class="modal-body">
          <div class="form-row"><label>Tenant / Lease</label>
            <select name="lease_id">${window._leaseOptions||'<option value="">Select…</option>'}</select>
          </div>
          <div class="form-row-2">
            <div><label>Amount ($)</label><input name="amount" type="number" step="0.01" min="0" required/></div>
            <div><label>Date</label><input name="pay_date" type="date" required/></div>
          </div>
          <div class="form-row"><label>Memo</label><input name="memo" placeholder="February rent"/></div>
        </div>
        ${footer('Record Payment')}
      </form>`;
    backdrop.classList.add('open');
    return;
  }

  // ── FALLBACK ─────────────────────────────────────────────────
  box.innerHTML = `<div class="modal-header"><span class="modal-title">${type.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}</span>${X}</div><div class="modal-body" style="padding:32px;text-align:center;color:var(--text-muted)">Coming soon.</div>`;
  backdrop.classList.add('open');
}

// Cashflow chart
const chartData=[
  {m:'Sep',income:7400,expense:2800},{m:'Oct',income:7650,expense:3100},
  {m:'Nov',income:7400,expense:3600},{m:'Dec',income:7900,expense:2500},
  {m:'Jan',income:7650,expense:3200},{m:'Feb',income:7850,expense:2900}
];
const maxVal=Math.max(...chartData.map(d=>d.income));
function buildChart(id){
  const el=document.getElementById(id);if(!el)return;
  const rows=chartData.map(d=>{
    const iw=Math.round(d.income/maxVal*100);const ew=Math.round(d.expense/maxVal*100);
    return `<div class="chart-month"><div class="chart-month-label">${d.m}</div><div class="bar-group"><div class="bar-row"><span class="bar-type" style="color:var(--accent-dark);font-weight:600;font-size:9px">IN</span><div class="bar-track"><div class="bar-fill income" style="width:${iw}%"></div></div><span class="bar-amount income">$${(d.income/1000).toFixed(1)}k</span></div><div class="bar-row"><span class="bar-type" style="color:var(--text-faint);font-size:9px">EX</span><div class="bar-track"><div class="bar-fill expense" style="width:${ew}%"></div></div><span class="bar-amount expense">$${(d.expense/1000).toFixed(1)}k</span></div><div style="font-size:10px;font-weight:700;color:var(--text);text-align:right;margin-top:3px">Net: $${((d.income-d.expense)/1000).toFixed(1)}k</div></div></div>`;
  }).join('');
  el.innerHTML=`<div class="chart-months">${rows}</div><div class="chart-legend"><div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div>Income</div><div class="legend-item"><div class="legend-dot" style="background:#cbd5e1"></div>Expenses</div><div class="legend-item"><div class="legend-dot" style="background:#111318"></div>Net</div></div>`;
}
document.addEventListener('DOMContentLoaded',()=>{buildChart('dash-chart');});
<?php if($jsData) echo $jsData; ?>
</script>
</body>
</html>
<?php }


function owner_modal_js(PDO $pdo, int $owner_id): string {
  $props  = $pdo->prepare("SELECT id,name FROM properties WHERE owner_id=? ORDER BY id");
  $props->execute([$owner_id]);
  $props  = $props->fetchAll();

  $units  = $pdo->query("SELECT u.id, u.unit_label, p.name AS prop_name FROM units u JOIN properties p ON p.id=u.property_id ORDER BY p.id,u.id")->fetchAll();

  $leases = $pdo->query("
    SELECT l.id, t.full_name AS tenant_name, u.unit_label
    FROM leases l
    JOIN units u ON u.id=l.unit_id
    JOIN users t ON t.id=l.tenant_id
    WHERE l.status='ACTIVE'
    ORDER BY l.id
  ")->fetchAll();

  $propOpts  = '<option value="">Select property…</option>';
  foreach ($props as $p) $propOpts  .= '<option value="'.htmlspecialchars((string)$p['id'], ENT_QUOTES).'">'  .htmlspecialchars($p['name'], ENT_QUOTES).'</option>';

  $unitOpts  = '<option value="">Select unit…</option>';
  foreach ($units as $u2) $unitOpts .= '<option value="'.htmlspecialchars((string)$u2['id'], ENT_QUOTES).'">' .htmlspecialchars($u2['prop_name'].' · Unit '.$u2['unit_label'], ENT_QUOTES).'</option>';

  $leaseOpts = '<option value="">Select tenant…</option>';
  foreach ($leases as $l) $leaseOpts .= '<option value="'.htmlspecialchars((string)$l['id'], ENT_QUOTES).'">' .htmlspecialchars($l['tenant_name'].' — Unit '.$l['unit_label'], ENT_QUOTES).'</option>';

  return 'window._propOptions=' .json_encode($propOpts) .';'
        .'window._unitOptions=' .json_encode($unitOpts) .';'
        .'window._leaseOptions='.json_encode($leaseOpts).';';
}

function nav_links_for_role(string $role): array {
  return match ($role) {
    'OWNER' => [
      'owner_dashboard' => 'Dashboard',
      'owner_properties' => 'Properties',
      'owner_leases' => 'Leases',
      'owner_maintenance' => 'Maintenance',
      'owner_payments' => 'Payments',
      'owner_vendors' => 'Vendors',
    ],
    'TENANT' => [
      'tenant_dashboard' => 'Dashboard',
      'tenant_maintenance' => 'Maintenance',
      'tenant_payments' => 'Payments',
    ],
    'VENDOR' => [
      'vendor_dashboard' => 'Dashboard',
      'vendor_jobs' => 'Jobs',
      'vendor_payments' => 'Payments',
    ],
    default => ['help' => 'Help'],
  };
}

// -------------------------
// Actions (POST)
// -------------------------
$pdo = pdo();

if (isset($_GET['action']) && $_GET['action'] === 'logout' && is_post()) {
  logout();
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

$page = $_GET['page'] ?? 'login';

// Login submit
if ($page === 'login' && is_post() && !isset($_GET['action'])) {
  $email = trim((string)($_POST['email'] ?? ''));
  $password = (string)($_POST['password'] ?? '');
  $code = (string)($_POST['code'] ?? ''); // optional on the login form

  $stmt = $pdo->prepare("SELECT id,role,email,full_name,password_hash,totp_secret FROM users WHERE email=?");
  $stmt->execute([$email]);
  $u = $stmt->fetch();

  if (!$u || !password_verify($password, $u['password_hash'])) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Invalid email or password.'];
    redirect('index.php?page=login');
  }

  $_SESSION['uid'] = (int)$u['id'];
  $_SESSION['tmp_role'] = $u['role'];

  // If TOTP is enabled for this user:
  // - If they entered a code on the login page, verify it and complete sign-in.
  // - If they left it blank, continue to the dedicated 2FA screen.
  if (!empty($u['totp_secret'])) {
    $code_clean = preg_replace('/\D+/', '', $code) ?? '';
    if ($code_clean !== '') {
      if (!totp_verify($u['totp_secret'], $code_clean)) {
        $_SESSION['totp_ok'] = false;
        $_SESSION['flash'] = ['type'=>'error','msg'=>'Invalid authenticator code.'];
        redirect('index.php?page=login');
      }
      $_SESSION['totp_ok'] = true;
      $dest = match ($u['role']) {
        'OWNER'  => 'owner_dashboard',
        'TENANT' => 'tenant_dashboard',
        'VENDOR' => 'vendor_dashboard',
        default  => 'help'
      };
      redirect('index.php?page=' . $dest);
    }

    $_SESSION['totp_ok'] = false;
    redirect('index.php?page=totp');
  }

  // No TOTP enabled -> complete sign-in.
  $_SESSION['totp_ok'] = true;
  $dest = match ($u['role']) {
    'OWNER'  => 'owner_dashboard',
    'TENANT' => 'tenant_dashboard',
    'VENDOR' => 'vendor_dashboard',
    default  => 'help'
  };
  redirect('index.php?page=' . $dest);
}

// TOTP submit
if ($page === 'totp' && is_post() && !isset($_GET['action'])) {
  $u = current_user($pdo);
  if (!$u) redirect('index.php?page=login');

  // If the user doesn't actually have TOTP enabled, treat this as complete.
  if (empty($u['totp_secret'])) {
    $_SESSION['totp_ok'] = true;
    $dest = match ($u['role']) {
      'OWNER'  => 'owner_dashboard',
      'TENANT' => 'tenant_dashboard',
      'VENDOR' => 'vendor_dashboard',
      default  => 'help'
    };
    redirect('index.php?page=' . $dest);
  }

  $code = (string)($_POST['code'] ?? '');
  if (!totp_verify($u['totp_secret'], $code)) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Invalid code. Check your authenticator time sync and try again.'];
    redirect('index.php?page=totp');
  }

  $_SESSION['totp_ok'] = true;

  // route to role home
  $dest = match ($u['role']) {
    'OWNER'  => 'owner_dashboard',
    'TENANT' => 'tenant_dashboard',
    'VENDOR' => 'vendor_dashboard',
    default  => 'help'
  };
  redirect('index.php?page=' . $dest);
}

// Owner creates property
if (isset($_GET['action']) && $_GET['action'] === 'add_property' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $name   = trim((string)($_POST['name'] ?? ''));
  $street = trim((string)($_POST['street'] ?? ''));
  $city   = trim((string)($_POST['city'] ?? ''));
  $state  = trim((string)($_POST['state'] ?? ''));
  $zip    = trim((string)($_POST['zip'] ?? ''));

  // Build full address from parts, or fall back to legacy single field
  if ($street !== '') {
    $parts = array_filter([$street, $city ? $city.($state?' '.$state:'') : $state, $zip]);
    $address = implode(', ', $parts);
  } else {
    $address = trim((string)($_POST['address'] ?? ''));
  }

  if ($name === '' || $address === '') {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Property name and address are required.'];
    redirect('index.php?page=owner_properties');
  }

  $pdo->prepare("INSERT INTO properties(owner_id,name,address) VALUES(?,?,?)")->execute([$u['id'],$name,$address]);
  $_SESSION['flash'] = ['type'=>'ok','msg'=>'Property created successfully.'];
  redirect('index.php?page=owner_properties');
}

// Owner adds unit
if (isset($_GET['action']) && $_GET['action'] === 'add_unit' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $property_id = (int)($_POST['property_id'] ?? 0);
  $unit_label  = trim((string)($_POST['unit_label'] ?? ''));
  $bedrooms    = (int)($_POST['bedrooms'] ?? 0);
  $bathrooms   = (float)($_POST['bathrooms'] ?? 0);
  $sqft        = (int)($_POST['sqft'] ?? 0);

  if ($property_id <= 0 || $unit_label === '') {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Property and unit label are required.'];
    redirect('index.php?page=owner_properties');
  }

  // ensure property belongs to owner
  $chk = $pdo->prepare("SELECT id FROM properties WHERE id=? AND owner_id=?");
  $chk->execute([$property_id,$u['id']]);
  if (!$chk->fetchColumn()) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Invalid property.'];
    redirect('index.php?page=owner_properties');
  }

  $pdo->prepare("INSERT INTO units(property_id,unit_label,bedrooms,bathrooms,sqft) VALUES(?,?,?,?,?)")
      ->execute([$property_id,$unit_label,$bedrooms,$bathrooms,$sqft]);
  $_SESSION['flash'] = ['type'=>'ok','msg'=>'Unit added.'];
  redirect('index.php?page=owner_properties');
}

// Owner creates lease (assign tenant email)
if (isset($_GET['action']) && $_GET['action'] === 'add_lease' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $unit_id = (int)($_POST['unit_id'] ?? 0);
  $tenant_email = trim((string)($_POST['tenant_email'] ?? ''));
  $start = trim((string)($_POST['start_date'] ?? ''));
  $end   = trim((string)($_POST['end_date'] ?? ''));
  $rent  = (int)round(((float)($_POST['rent'] ?? 0))*100);
  $dep   = (int)round(((float)($_POST['deposit'] ?? 0))*100);

  if ($unit_id<=0 || $tenant_email==='' || $start==='' || $end==='' || $rent<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Unit, tenant email, dates, and rent are required.'];
    redirect('index.php?page=owner_leases');
  }

  // unit belongs to owner
  $q = $pdo->prepare("SELECT u.id FROM units u JOIN properties p ON p.id=u.property_id WHERE u.id=? AND p.owner_id=?");
  $q->execute([$unit_id,$u['id']]);
  if (!$q->fetchColumn()) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Invalid unit.'];
    redirect('index.php?page=owner_leases');
  }

  $t = $pdo->prepare("SELECT id FROM users WHERE email=? AND role='TENANT'");
  $t->execute([$tenant_email]);
  $tenant_id = (int)($t->fetchColumn() ?: 0);
  if ($tenant_id<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Tenant email not found (must be a TENANT user).'];
    redirect('index.php?page=owner_leases');
  }

  $pdo->prepare("INSERT INTO leases(unit_id,tenant_id,start_date,end_date,rent_cents,deposit_cents,due_day,grace_days,late_fee_cents,status)
                 VALUES(?,?,?,?,?,?,?,?,?,?)")
      ->execute([$unit_id,$tenant_id,$start,$end,$rent,$dep,1,5,0,'ACTIVE']);

  $_SESSION['flash']=['type'=>'ok','msg'=>'Lease created.'];
  redirect('index.php?page=owner_leases');
}

// Tenant creates maintenance request
if (isset($_GET['action']) && $_GET['action'] === 'tenant_new_maint' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'TENANT') redirect('index.php?page=help');

  $title = trim((string)($_POST['title'] ?? ''));
  $desc  = trim((string)($_POST['description'] ?? ''));
  $prio  = (string)($_POST['priority'] ?? 'Normal');
  $prio  = in_array($prio, ['Normal','Urgent'], true) ? $prio : 'Normal';

  // tenant active lease
  $leaseId = (int)($pdo->prepare("SELECT id FROM leases WHERE tenant_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT 1")
    ->execute([$u['id']]) ?: 0);
  $stmt = $pdo->prepare("SELECT id FROM leases WHERE tenant_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT 1");
  $stmt->execute([$u['id']]);
  $lease_id = (int)($stmt->fetchColumn() ?: 0);

  if ($lease_id<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'No active lease found for your account.'];
    redirect('index.php?page=tenant_maintenance');
  }
  if ($title==='' || $desc==='') {
    $_SESSION['flash']=['type'=>'error','msg'=>'Title and description are required.'];
    redirect('index.php?page=tenant_maintenance');
  }

  $pdo->prepare("INSERT INTO maintenance_requests(lease_id,title,description,priority,status) VALUES(?,?,?,?,?)")
      ->execute([$lease_id,$title,$desc,$prio,'In Review']);

  $_SESSION['flash']=['type'=>'ok','msg'=>'Maintenance request submitted.'];
  redirect('index.php?page=tenant_maintenance');
}

// Tenant records payment
if (isset($_GET['action']) && $_GET['action'] === 'tenant_pay' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'TENANT') redirect('index.php?page=help');

  $amount = (int)round(((float)($_POST['amount'] ?? 0))*100);
  $memo = trim((string)($_POST['memo'] ?? ''));

  $stmt = $pdo->prepare("SELECT id FROM leases WHERE tenant_id=? AND status='ACTIVE' ORDER BY id DESC LIMIT 1");
  $stmt->execute([$u['id']]);
  $lease_id = (int)($stmt->fetchColumn() ?: 0);

  if ($lease_id<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'No active lease found for your account.'];
    redirect('index.php?page=tenant_payments');
  }
  if ($amount<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Amount must be greater than 0.'];
    redirect('index.php?page=tenant_payments');
  }

  $pdo->prepare("INSERT INTO payments(lease_id,payer_user_id,amount_cents,memo,status) VALUES(?,?,?,?,?)")
      ->execute([$lease_id,$u['id'],$amount,$memo,'Processed']);

  $_SESSION['flash']=['type'=>'ok','msg'=>'Payment recorded.'];
  redirect('index.php?page=tenant_payments');
}

// Vendor submits invoice for a job
if (isset($_GET['action']) && $_GET['action'] === 'vendor_invoice' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'VENDOR') redirect('index.php?page=help');

  $job_id = (int)($_POST['job_id'] ?? 0);
  $desc   = trim((string)($_POST['desc'] ?? ''));
  $labor  = (int)round(((float)($_POST['labor'] ?? 0))*100);
  $parts  = (int)round(((float)($_POST['parts'] ?? 0))*100);

  if ($job_id<=0 || $desc==='' || ($labor+$parts)<=0) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Job, description, and total amount are required.'];
    redirect('index.php?page=vendor_jobs');
  }

  // ensure job belongs to vendor
  $chk = $pdo->prepare("SELECT id FROM jobs WHERE id=? AND vendor_id=?");
  $chk->execute([$job_id,$u['id']]);
  if (!$chk->fetchColumn()) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Invalid job.'];
    redirect('index.php?page=vendor_jobs');
  }

  $items = [
    ['label'=>'Labor', 'amount_cents'=>$labor],
    ['label'=>'Parts', 'amount_cents'=>$parts],
    ['label'=>'Notes', 'amount_cents'=>0, 'notes'=>$desc],
  ];
  $total = $labor + $parts;

  $pdo->prepare("INSERT INTO invoices(job_id,line_items_json,total_cents,status) VALUES(?,?,?,?)")
      ->execute([$job_id,json_encode($items, JSON_UNESCAPED_SLASHES),$total,'Submitted']);

  // create payout placeholder
  $invoiceId = (int)$pdo->lastInsertId();
  $pdo->prepare("INSERT INTO payouts(vendor_id,invoice_id,amount_cents,status) VALUES(?,?,?,?)")
      ->execute([$u['id'],$invoiceId,$total,'Pending']);

  $_SESSION['flash']=['type'=>'ok','msg'=>'Invoice submitted. Payout now pending.'];
  redirect('index.php?page=vendor_payments');
}

// Owner marks payout paid
if (isset($_GET['action']) && $_GET['action'] === 'owner_pay_payout' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $payout_id = (int)($_POST['payout_id'] ?? 0);
  if ($payout_id<=0) redirect('index.php?page=owner_payments');

  // ensure payout relates to owner's property via joins (coarse but safe)
  $q = $pdo->prepare("
    SELECT po.id
    FROM payouts po
    JOIN invoices i ON i.id = po.invoice_id
    JOIN jobs j ON j.id = i.job_id
    JOIN maintenance_requests mr ON mr.id = j.maintenance_id
    JOIN leases l ON l.id = mr.lease_id
    JOIN units u ON u.id = l.unit_id
    JOIN properties p ON p.id = u.property_id
    WHERE po.id=? AND p.owner_id=?
  ");
  $q->execute([$payout_id,$u['id']]);
  if (!$q->fetchColumn()) {
    $_SESSION['flash']=['type'=>'error','msg'=>'Invalid payout.'];
    redirect('index.php?page=owner_payments');
  }

  $pdo->prepare("UPDATE payouts SET status='Paid' WHERE id=?")->execute([$payout_id]);
  $_SESSION['flash']=['type'=>'ok','msg'=>'Payout marked as Paid.'];
  redirect('index.php?page=owner_payments');
}


// Owner adds user (tenant or vendor)
if (isset($_GET['action']) && $_GET['action'] === 'add_user' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $first = trim((string)($_POST['first_name'] ?? ''));
  $last  = trim((string)($_POST['last_name']  ?? ''));
  $email = strtolower(trim((string)($_POST['email'] ?? '')));
  $role  = strtoupper(trim((string)($_POST['role']  ?? 'TENANT')));

  if (!in_array($role, ['TENANT','VENDOR','OWNER'], true)) $role = 'TENANT';
  $full_name = trim("$first $last") ?: $first;

  if ($email === '' || $full_name === '') {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Name and email are required.'];
    redirect('index.php?page=owner_users');
  }

  // Check email not already taken
  $exists = $pdo->prepare("SELECT id FROM users WHERE email=?");
  $exists->execute([$email]);
  if ($exists->fetchColumn()) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Email already registered.'];
    redirect('index.php?page=owner_users');
  }

  // Generate a temporary password and empty TOTP secret
  $tmp_pass = bin2hex(random_bytes(8));
  $hash = password_hash($tmp_pass, PASSWORD_BCRYPT);

  $pdo->prepare("INSERT INTO users(role,email,password_hash,full_name,totp_secret,created_at) VALUES(?,?,?,?,?,datetime('now'))")
      ->execute([$role, $email, $hash, $full_name, '']);

  $_SESSION['flash'] = ['type'=>'ok','msg'=>"User "$full_name" created. Temp password: $tmp_pass"];
  $dest = $role === 'VENDOR' ? 'owner_vendors' : ($role === 'TENANT' ? 'owner_tenants' : 'owner_users');
  redirect("index.php?page=$dest");
}

// Owner adds maintenance request on behalf of tenant
if (isset($_GET['action']) && $_GET['action'] === 'add_maintenance' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $title       = trim((string)($_POST['title']       ?? ''));
  $description = trim((string)($_POST['description'] ?? ''));
  $priority    = trim((string)($_POST['priority']    ?? 'Normal'));
  $unit_id     = (int)($_POST['unit_id'] ?? 0);

  if (!in_array($priority, ['Normal','Urgent'], true)) $priority = 'Normal';

  if ($title === '' || $unit_id <= 0) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Title and unit are required.'];
    redirect('index.php?page=owner_maintenance');
  }

  // Find active lease for this unit
  $lease = $pdo->prepare("SELECT id FROM leases WHERE unit_id=? AND status='ACTIVE' LIMIT 1");
  $lease->execute([$unit_id]);
  $lease_id = $lease->fetchColumn();

  if (!$lease_id) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'No active lease found for that unit.'];
    redirect('index.php?page=owner_maintenance');
  }

  $pdo->prepare("INSERT INTO maintenance_requests(lease_id,title,description,priority,status,created_at) VALUES(?,?,?,?,'In Review',datetime('now'))")
      ->execute([$lease_id, $title, $description ?: $title, $priority]);

  $_SESSION['flash'] = ['type'=>'ok','msg'=>'Maintenance request created.'];
  redirect('index.php?page=owner_maintenance');
}

// Owner records a rent payment
if (isset($_GET['action']) && $_GET['action'] === 'record_payment' && is_post()) {
  $u = require_login($pdo);
  if ($u['role'] !== 'OWNER') redirect('index.php?page=help');

  $lease_id = (int)($_POST['lease_id'] ?? 0);
  $amount   = (float)($_POST['amount'] ?? 0);
  $memo     = trim((string)($_POST['memo'] ?? ''));
  $pay_date = trim((string)($_POST['pay_date'] ?? date('Y-m-d')));

  if ($lease_id <= 0 || $amount <= 0) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Lease and amount are required.'];
    redirect('index.php?page=owner_payments');
  }

  // Verify lease belongs to this owner
  $chk = $pdo->prepare("
    SELECT l.id, l.tenant_id FROM leases l
    JOIN units u ON u.id=l.unit_id
    JOIN properties p ON p.id=u.property_id
    WHERE l.id=? AND p.owner_id=?
  ");
  $chk->execute([$lease_id, $u['id']]);
  $row = $chk->fetch();

  if (!$row) {
    $_SESSION['flash'] = ['type'=>'error','msg'=>'Invalid lease.'];
    redirect('index.php?page=owner_payments');
  }

  $cents = (int)round($amount * 100);
  $pdo->prepare("INSERT INTO payments(lease_id,payer_user_id,amount_cents,memo,status,created_at) VALUES(?,?,?,?,'Processed',?)")
      ->execute([$lease_id, $row['tenant_id'], $cents, $memo, $pay_date]);

  $_SESSION['flash'] = ['type'=>'ok','msg'=>'Payment recorded: ' . money_fmt($cents)];
  redirect('index.php?page=owner_payments');
}

// -------------------------
// Page handlers (GET)
// -------------------------
if ($page === 'login') {
  $prefill_email = (string)($_POST['email'] ?? $_GET['email'] ?? '');
  render_login_html('login', $flash, $prefill_email);
  exit;
}

if ($page === 'totp') {
  render_login_html('totp', $flash, '');
  exit;
}

if ($page === 'forgot') {
  render_login_html('forgot', $flash, '');
  exit;
}

if ($page === 'reset_sent') {
  render_login_html('reset_sent', $flash, '');
  exit;
}


// Everything below requires logged in + totp_ok
$u = require_login($pdo);

// -------------------------
// Common pages
// -------------------------
if ($page === 'account') {
  render_head('SMG — Profile');
  render_app_shell_start($u, 'account', 'Profile');
  ?>
  <?php if ($flash): ?>
    <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
  <?php endif; ?>

  <div class="grid">
    <div class="card" style="grid-column:span 12">
      <div class="hd"><div class="h1">Account</div></div>
      <div class="bd">
        <div class="form">
          <div class="col-6">
            <label>Full name</label>
            <input value="<?=h($u['full_name'])?>" disabled />
          </div>
          <div class="col-6">
            <label>Email</label>
            <input value="<?=h($u['email'])?>" disabled />
          </div>
          <div class="col-6">
            <label>Role</label>
            <input value="<?=h($u['role'])?>" disabled />
          </div>
          <div class="col-6">
            <label>Two-factor</label>
            <input value="Enabled (TOTP required)" disabled />
          </div>
          <div class="col-12 muted">
            TOTP is enforced at login (per your requirement).
          </div>
        </div>
      </div>
    </div>
  </div>
  <?php
  render_app_shell_end();
  exit;
}

if ($page === 'help') {
  render_head('SMG — Help');
  render_app_shell_start($u, 'help', 'Help');
  ?>
  <div class="card">
    <div class="hd"><div class="h1">Quick start</div></div>
    <div class="bd">
      <ol class="muted" style="line-height:1.8">
        <li>Run <b>init_db.php</b> once to create <b>smg.sqlite</b> and seed users.</li>
        <li>Login in <b>index.php</b> with demo credentials, then enter the TOTP code.</li>
        <li>Owner can create properties/units/leases; tenant can submit maintenance and payments; vendor can submit invoices.</li>
      </ol>
      <div class="muted" style="margin-top:10px">
        This app is built from your UI mockups (login/owner/tenant/vendor) and backed by SQLite. :contentReference[oaicite:8]{index=8} :contentReference[oaicite:9]{index=9} :contentReference[oaicite:10]{index=10} :contentReference[oaicite:11]{index=11}
      </div>
    </div>
  </div>
  <?php
  render_app_shell_end();
  exit;
}

// -------------------------
// OWNER pages
// -------------------------
if ($u['role'] === 'OWNER') {

  if ($page === 'owner_dashboard') {
    $k = $pdo->prepare("SELECT COUNT(*) FROM properties WHERE owner_id=?");
    $k->execute([$u['id']]);
    $properties = (int)$k->fetchColumn();

    $units        = (int)$pdo->query("SELECT COUNT(*) FROM units")->fetchColumn();
    $tenants      = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='TENANT'")->fetchColumn();
    $income       = (int)$pdo->query("SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE status='Processed'")->fetchColumn();
    $openMaint    = (int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed'")->fetchColumn();
    $urgentMaint  = (int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE priority='Urgent' AND status!='Completed'")->fetchColumn();
    $pendingMaint = (int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed' AND priority!='Urgent'")->fetchColumn();
    $occupiedUnits = (int)$pdo->query("SELECT COUNT(DISTINCT unit_id) FROM leases WHERE status='ACTIVE'")->fetchColumn();
    $occupancyPct  = $units > 0 ? round($occupiedUnits / $units * 100) : 0;

    // Active leases — also fetch most recent payment status per tenant
    $tenantRows = $pdo->query("
      SELECT l.id AS lease_id, l.start_date, l.end_date, l.rent_cents,
             u.unit_label, t.full_name AS tenant_name, t.email AS tenant_email,
             (SELECT status FROM payments WHERE lease_id=l.id ORDER BY id DESC LIMIT 1) AS last_pay_status
      FROM leases l
      JOIN units u ON u.id=l.unit_id
      JOIN users t ON t.id=l.tenant_id
      WHERE l.status='ACTIVE'
      ORDER BY l.id ASC LIMIT 8
    ")->fetchAll();

    // Open maintenance for right card
    $maintRows = $pdo->query("
      SELECT mr.id, mr.title, mr.priority, mr.status, u.unit_label
      FROM maintenance_requests mr
      JOIN leases l ON l.id=mr.lease_id
      JOIN units u ON u.id=l.unit_id
      WHERE mr.status!='Completed'
      ORDER BY mr.id DESC LIMIT 5
    ")->fetchAll();

    // Recent activity: mix payments + maintenance
    $recentPay   = $pdo->query("SELECT p.created_at, p.amount_cents, t.full_name AS name, 'pay' AS type FROM payments p JOIN leases l ON l.id=p.lease_id JOIN users t ON t.id=l.tenant_id ORDER BY p.id DESC LIMIT 3")->fetchAll();
    $recentMaint = $pdo->query("SELECT mr.created_at, mr.title, mr.id AS maint_id, 'maint' AS type FROM maintenance_requests mr ORDER BY mr.id DESC LIMIT 2")->fetchAll();
    $activity = array_merge($recentPay, $recentMaint);
    usort($activity, fn($a,$b) => strcmp((string)$b['created_at'], (string)$a['created_at']));
    $activity = array_slice($activity, 0, 5);

    $badges = ['tenants' => $tenants ?: null, 'maintenance' => $openMaint ?: null];

    render_owner_head('SMG — Dashboard');
    render_owner_shell_start($u, 'owner_dashboard', 'Dashboard', '+ Add Unit', 'add-unit', $badges);
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="metrics">
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Properties</span><div class="metric-icon green"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg></div></div>
        <div class="metric-value"><?=h((string)$properties)?></div>
        <div class="metric-change"><?=h((string)$occupiedUnits)?> unit<?=($occupiedUnits!==1?'s':'')?> occupied</div>
      </div>
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Monthly Revenue</span><div class="metric-icon green"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg></div></div>
        <div class="metric-value"><?=h(money_fmt($income))?></div>
        <div class="metric-change"><span class="up">↑ On time</span> this month</div>
      </div>
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Open Maintenance</span><div class="metric-icon yellow"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg></div></div>
        <div class="metric-value"><?=h((string)$openMaint)?></div>
        <div class="metric-change"><?php if ($urgentMaint > 0): ?><span class="down"><?=h((string)$urgentMaint)?> urgent</span><?php endif; ?><?=($urgentMaint&&$pendingMaint?' · ':'')?><?=($pendingMaint?$pendingMaint.' pending':'')?></div>
      </div>
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Occupancy</span><div class="metric-icon blue"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/></svg></div></div>
        <div class="metric-value"><?=h((string)$occupancyPct)?>%</div>
        <div class="metric-change"><span class="up"><?=($occupancyPct>=100?'All units':''.h((string)$tenants).' active')?></span> rented</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header"><span class="card-title">Active Tenants</span><a class="card-action" href="<?=h(app_url(['page'=>'owner_tenants']))?>">View all →</a></div>
        <table><thead><tr><th>Tenant</th><th>Unit</th><th>Rent</th><th>Status</th></tr></thead><tbody>
        <?php foreach ($tenantRows as $tr):
          // Derive payment status badge
          $ps = $tr['last_pay_status'] ?? null;
          if ($ps === 'Processed')      { $psClass='badge-green'; $psLabel='Paid'; }
          elseif ($ps === 'Pending')    { $psClass='badge-yellow'; $psLabel='Pending'; }
          else                          { $psClass='badge-red'; $psLabel='Late'; }
        ?>
          <tr>
            <td><div class="td-name"><?=h($tr['tenant_name'])?></div><div class="td-sub">Lease ends <?=h(date('M Y', strtotime($tr['end_date'])))?></div></td>
            <td><span class="unit-link" onclick=""><?=h('Unit #'.$tr['unit_label'])?></span></td>
            <td><?=h(money_fmt((int)$tr['rent_cents']))?></td>
            <td><span class="badge <?=$psClass?>"><?=$psLabel?></span></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$tenantRows): ?><tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:24px">No active leases</td></tr><?php endif; ?>
        </tbody></table>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Maintenance Requests</span><a class="card-action" href="<?=h(app_url(['page'=>'owner_maintenance']))?>">View all →</a></div>
        <?php foreach ($maintRows as $mr):
          $priClass = match($mr['priority']) { 'Urgent'=>'badge-red', default=>'badge-yellow' };
          $stClass  = match($mr['status'])   { 'In Review'=>'badge-yellow', 'Scheduled'=>'badge-blue', 'Completed'=>'badge-green', default=>'badge-gray' };
        ?>
          <div class="maint-item">
            <div class="maint-num">#<?=h((string)$mr['id'])?></div>
            <div class="maint-body">
              <div class="maint-title"><?=h($mr['title'])?></div>
              <div class="maint-meta">Unit #<?=h($mr['unit_label'])?> · <span class="badge <?=$priClass?>" style="font-size:11px;padding:1px 7px"><?=h($mr['priority'])?></span> · <span class="badge <?=$stClass?>" style="font-size:11px;padding:1px 7px"><?=h($mr['status'])?></span></div>
            </div>
          </div>
        <?php endforeach; ?>
        <?php if (!$maintRows): ?><div style="padding:24px;text-align:center;color:var(--text-muted)">No open maintenance requests 🎉</div><?php endif; ?>
      </div>
    </div>

    <div class="grid-3-1">
      <div class="card">
        <div class="card-header"><span class="card-title">Cashflow — Last 6 Months</span><span class="card-action">Export CSV</span></div>
        <div class="chart-area" id="dash-chart"></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Recent Activity</span></div>
        <?php foreach ($activity as $act): ?>
          <?php if ($act['type']==='pay'): ?>
            <div class="activity-item"><div class="activity-dot" style="background:var(--accent)"></div><div><div class="activity-text">Rent received from <?=h($act['name'])?></div><div class="activity-time"><?=h($act['created_at'])?></div></div></div>
          <?php else: ?>
            <div class="activity-item"><div class="activity-dot" style="background:var(--yellow)"></div><div><div class="activity-text">Maintenance #<?=h((string)$act['maint_id'])?> submitted</div><div class="activity-time"><?=h($act['created_at'])?></div></div></div>
          <?php endif; ?>
        <?php endforeach; ?>
        <?php if (!$activity): ?><div style="padding:20px;color:var(--text-muted);font-size:13px">No recent activity</div><?php endif; ?>
      </div>
    </div>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  if ($page === 'owner_properties') {
    render_owner_head('SMG — Properties');

    $props = $pdo->prepare("SELECT * FROM properties WHERE owner_id=? ORDER BY id DESC");
    $props->execute([$u['id']]);
    $props = $props->fetchAll();

    $allUnits = $pdo->query("
      SELECT u.*, p.name AS prop_name, p.id AS prop_id,
        (SELECT COUNT(*) FROM leases l WHERE l.unit_id=u.id AND l.status='ACTIVE') AS occupied
      FROM units u JOIN properties p ON p.id=u.property_id ORDER BY u.id
    ")->fetchAll();

    render_owner_shell_start($u, 'owner_properties', 'Properties', '+ Add Property', 'add-property');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="page-header">
      <div><div class="page-title">Properties</div><div class="page-sub"><?=h((string)count($props))?> propert<?=(count($props)!==1?'ies':'y')?></div></div>
    </div>

    <div class="prop-grid">
      <?php foreach ($props as $prop):
        $propUnits = array_filter($allUnits, fn($u2) => (int)$u2['prop_id'] === (int)$prop['id']);
        $propUnits = array_values($propUnits);
        $totalU = count($propUnits);
        $occupiedU = array_sum(array_column($propUnits, 'occupied'));
        $monthlyRent = 0;
        foreach ($propUnits as $pu) {
          $ls = $pdo->prepare("SELECT rent_cents FROM leases WHERE unit_id=? AND status='ACTIVE' LIMIT 1");
          $ls->execute([$pu['id']]);
          $monthlyRent += (int)($ls->fetchColumn() ?: 0);
        }
      ?>
      <div class="prop-card">
        <div class="prop-img"><svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9,22 9,12 15,12 15,22"/></svg></div>
        <div class="prop-body">
          <div class="prop-name"><?=h($prop['name'])?></div>
          <div class="prop-addr"><?=h($prop['address'])?></div>
          <div class="prop-stats">
            <div class="prop-stat"><div class="prop-stat-val"><?=h((string)$totalU)?></div><div class="prop-stat-label">Units</div></div>
            <div class="prop-stat"><div class="prop-stat-val"><?=h((string)$occupiedU)?></div><div class="prop-stat-label">Occupied</div></div>
            <div class="prop-stat"><div class="prop-stat-val"><?=h(money_fmt($monthlyRent))?></div><div class="prop-stat-label">Monthly</div></div>
          </div>
        </div>
        <div class="prop-footer">
          <?php if ($totalU > 0 && $occupiedU === $totalU): ?><span class="badge badge-green">Fully Occupied</span><?php elseif ($occupiedU > 0): ?><span class="badge badge-yellow">Partially Occupied</span><?php else: ?><span class="badge badge-gray">Vacant</span><?php endif; ?>
          <span class="card-action">Manage →</span>
        </div>
      </div>
      <?php endforeach; ?>
      <!-- Add property card -->
      <div class="card" style="border:2px dashed var(--border);background:#fafafa;box-shadow:none;display:flex;align-items:center;justify-content:center;min-height:240px;flex-direction:column;gap:8px;cursor:pointer;border-radius:var(--radius)" onclick="openModal('add-property')">
        <div style="width:40px;height:40px;border-radius:10px;background:var(--accent-dim);display:flex;align-items:center;justify-content:center;color:var(--accent-dark)"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></div>
        <div style="font-size:13.5px;font-weight:500;color:var(--text-muted)">Add next property</div>
      </div>
    </div>



    <!-- Units -->
    <?php if ($props): ?>
    <div class="card" style="margin-top:16px">
      <div class="card-header"><span class="card-title">Units</span></div>
      <table>
        <thead><tr><th>Property</th><th>Unit</th><th>Beds</th><th>Baths</th><th>Sqft</th><th>Status</th></tr></thead>
        <tbody>
          <?php foreach ($allUnits as $un): ?>
            <tr>
              <td><?=h($un['prop_name'])?></td>
              <td><span class="unit-link"><?=h($un['unit_label'])?></span></td>
              <td><?=h((string)$un['bedrooms'])?></td>
              <td><?=h((string)$un['bathrooms'])?></td>
              <td><?=h((string)$un['sqft'])?> sq ft</td>
              <td><span class="badge <?=($un['occupied']?'badge-green':'badge-gray')?>"><?=($un['occupied']?'Occupied':'Vacant')?></span></td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$allUnits): ?><tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px">No units yet</td></tr><?php endif; ?>
        </tbody>
      </table>
    </div>

    <!-- Add unit form -->
    <div class="card" style="margin-top:16px">
      <div class="card-header"><span class="card-title">Add Unit</span></div>
      <div style="padding:20px">
        <form method="post" action="<?=h(app_url(['action'=>'add_unit']))?>">
          <div class="form-row-2">
            <div>
              <label>Property</label>
              <select name="property_id" required>
                <option value="">Select…</option>
                <?php foreach ($props as $prop): ?>
                  <option value="<?=h((string)$prop['id'])?>"><?=h($prop['name'])?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div><label>Unit Label</label><input name="unit_label" placeholder="1A" required value="1A"/></div>
          </div>
          <div class="form-row-2">
            <div><label>Bedrooms</label><input name="bedrooms" type="number" min="0" value="2"/></div>
            <div><label>Bathrooms</label><input name="bathrooms" type="number" step="0.5" min="0" value="1"/></div>
          </div>
          <div class="form-row"><label>Sq Ft</label><input name="sqft" type="number" min="0" value="780"/></div>
          <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px"><button class="btn btn-primary" type="submit">Add Unit</button></div>
        </form>
      </div>
    </div>
    <?php endif; ?>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  if ($page === 'owner_leases') {
    render_owner_head('SMG — Leases');

    $units = $pdo->query("
      SELECT u.id, u.unit_label, p.name AS prop_name, p.address
      FROM units u JOIN properties p ON p.id=u.property_id ORDER BY u.id
    ")->fetchAll();

    $leases = $pdo->query("
      SELECT l.*, u.unit_label, p.address, t.full_name AS tenant_name, t.email AS tenant_email
      FROM leases l
      JOIN units u ON u.id=l.unit_id
      JOIN properties p ON p.id=u.property_id
      JOIN users t ON t.id=l.tenant_id
      ORDER BY l.id DESC
    ")->fetchAll();

    $activeCount = count(array_filter($leases, fn($l) => $l['status']==='ACTIVE'));

    render_owner_shell_start($u, 'owner_leases', 'Leases', '+ New Lease', 'add-lease');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="page-header">
      <div><div class="page-title">Leases</div><div class="page-sub"><?=h((string)$activeCount)?> active</div></div>
    </div>

    <div class="card">
      <table>
        <thead><tr><th>Tenant</th><th>Unit</th><th>Start</th><th>End</th><th>Rent</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach ($leases as $l):
          $statusClass = match($l['status']) { 'ACTIVE'=>'badge-green', default=>'badge-gray' };
        ?>
          <tr>
            <td><div class="td-name"><?=h($l['tenant_name'])?></div><div class="td-sub"><?=h($l['tenant_email'])?></div></td>
            <td><span class="unit-link"><?=h($l['unit_label'])?></span></td>
            <td><?=h($l['start_date'])?></td>
            <td><?=h($l['end_date'])?></td>
            <td><?=h(money_fmt((int)$l['rent_cents']))?></td>
            <td><span class="badge <?=$statusClass?>"><?=h($l['status'])?></span></td>
            <td><div class="td-actions"><span class="action-btn primary">View</span></div></td>
          </tr>
        <?php endforeach; ?>
        <?php if (!$leases): ?><tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px">No leases yet</td></tr><?php endif; ?>
        </tbody>
      </table>
    </div>

    <!-- Lease timeline (static) -->
    <?php if ($leases): ?>
    <div class="card">
      <div class="card-header"><span class="card-title">Lease Timeline</span></div>
      <div class="lease-timeline">
        <?php foreach (array_slice($leases, 0, 4) as $i => $l): ?>
        <div class="timeline-item">
          <div class="timeline-line">
            <div class="timeline-dot" <?=($i===0?'':'style="background:var(--text-faint)"')?>></div>
            <?php if ($i < 3): ?><div class="timeline-trail"></div><?php endif; ?>
          </div>
          <div class="timeline-body">
            <div class="timeline-title"><?=h($l['tenant_name'])?> — Lease <?=($l['status']==='ACTIVE'?'Active':'Ended')?></div>
            <div class="timeline-meta">Unit <?=h($l['unit_label'])?> · <?=h($l['start_date'])?> → <?=h($l['end_date'])?> · <?=h(money_fmt((int)$l['rent_cents']))?>/mo</div>
          </div>
        </div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>

    <!-- Create lease form -->
    <div class="card" style="margin-top:16px">
      <div class="card-header"><span class="card-title">Create New Lease</span></div>
      <div style="padding:20px">
        <form method="post" action="<?=h(app_url(['action'=>'add_lease']))?>">
          <div class="form-row-2">
            <div>
              <label>Unit</label>
              <select name="unit_id" required>
                <option value="">Select…</option>
                <?php foreach ($units as $un): ?>
                  <option value="<?=h((string)$un['id'])?>"><?=h($un['prop_name'])?> · Unit <?=h($un['unit_label'])?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div><label>Tenant Email (must be a TENANT user)</label><input name="tenant_email" placeholder="tenant@smg.local" required/></div>
          </div>
          <div class="form-row-2">
            <div><label>Start Date</label><input name="start_date" type="date" required/></div>
            <div><label>End Date</label><input name="end_date" type="date" required/></div>
          </div>
          <div class="form-row-2">
            <div><label>Monthly Rent ($)</label><input name="rent" type="number" step="0.01" min="0" placeholder="1850.00" required/></div>
            <div><label>Security Deposit ($)</label><input name="deposit" type="number" step="0.01" min="0" placeholder="1850.00"/></div>
          </div>
          <div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn btn-primary" type="submit">Create Lease</button></div>
        </form>
      </div>
    </div>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  if ($page === 'owner_maintenance') {
    render_owner_head('SMG — Maintenance');

    $openRows = $pdo->query("
      SELECT mr.id, mr.title, mr.priority, mr.status, mr.created_at,
             u.unit_label, t.full_name AS tenant_name
      FROM maintenance_requests mr
      JOIN leases l ON l.id=mr.lease_id
      JOIN units u ON u.id=l.unit_id
      JOIN users t ON t.id=l.tenant_id
      WHERE mr.status!='Completed'
      ORDER BY mr.id DESC
    ")->fetchAll();

    $closedRows = $pdo->query("
      SELECT mr.id, mr.title, mr.created_at,
             u.unit_label, t.full_name AS tenant_name
      FROM maintenance_requests mr
      JOIN leases l ON l.id=mr.lease_id
      JOIN units u ON u.id=l.unit_id
      JOIN users t ON t.id=l.tenant_id
      WHERE mr.status='Completed'
      ORDER BY mr.id DESC LIMIT 10
    ")->fetchAll();

    render_owner_shell_start($u, 'owner_maintenance', 'Maintenance');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="page-header">
      <div>
        <div class="page-title">Maintenance</div>
        <div class="page-sub"><?=h((string)count($openRows))?> open · <?=h((string)count($closedRows))?> completed shown</div>
      </div>
    </div>

    <?php if ($openRows): ?>
    <div class="card">
      <div class="card-header"><span class="card-title">Open Requests</span></div>
      <?php foreach ($openRows as $mr):
        $priClass = match($mr['priority']) { 'Urgent'=>'badge-red', 'Normal'=>'badge-blue', default=>'badge-yellow' };
        $stClass  = match($mr['status']) { 'In Review'=>'badge-yellow', 'Scheduled'=>'badge-blue', default=>'badge-gray' };
      ?>
        <div class="maint-item">
          <div class="maint-num">#<?=h((string)$mr['id'])?></div>
          <div class="maint-body">
            <div class="maint-title"><?=h($mr['title'])?></div>
            <div class="maint-meta">
              Unit <?=h($mr['unit_label'])?> · <?=h($mr['tenant_name'])?> · <?=h($mr['created_at'])?>
              · <span class="badge <?=$priClass?>" style="font-size:11px;padding:1px 7px"><?=h($mr['priority'])?></span>
              · <span class="badge <?=$stClass?>" style="font-size:11px;padding:1px 7px"><?=h($mr['status'])?></span>
            </div>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
    <?php else: ?>
    <div class="card"><div style="padding:32px;text-align:center;color:var(--text-muted)">No open maintenance requests 🎉</div></div>
    <?php endif; ?>

    <?php if ($closedRows): ?>
    <div class="card">
      <div class="card-header"><span class="card-title">Recently Completed</span></div>
      <table>
        <thead><tr><th>#</th><th>Issue</th><th>Unit</th><th>Tenant</th><th>Closed</th></tr></thead>
        <tbody>
        <?php foreach ($closedRows as $cr): ?>
          <tr>
            <td style="color:var(--accent);font-weight:500">#<?=h((string)$cr['id'])?></td>
            <td><?=h($cr['title'])?></td>
            <td><span class="unit-link"><?=h($cr['unit_label'])?></span></td>
            <td><?=h($cr['tenant_name'])?></td>
            <td style="color:var(--text-muted)"><?=h($cr['created_at'])?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php endif; ?>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  if ($page === 'owner_payments') {
    render_owner_head('SMG — Payments');

    $payments = $pdo->query("
      SELECT pay.*, t.full_name AS tenant_name, u.unit_label
      FROM payments pay
      JOIN leases l ON l.id=pay.lease_id
      JOIN users t ON t.id=l.tenant_id
      JOIN units u ON u.id=l.unit_id
      ORDER BY pay.id DESC LIMIT 25
    ")->fetchAll();

    $payouts = $pdo->query("
      SELECT po.*, v.full_name AS vendor_name, i.status AS invoice_status
      FROM payouts po
      JOIN users v ON v.id=po.vendor_id
      JOIN invoices i ON i.id=po.invoice_id
      ORDER BY po.id DESC LIMIT 15
    ")->fetchAll();

    $collected = array_sum(array_column(
      array_filter($payments, fn($p) => $p['status']==='Processed'),
      'amount_cents'
    ));
    $pendingOut = array_sum(array_column(
      array_filter($payouts, fn($po) => $po['status']==='Pending'),
      'amount_cents'
    ));

    render_owner_shell_start($u, 'owner_payments', 'Payments', '+ Record Payment', 'record-payment');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="page-header">
      <div><div class="page-title">Payments</div><div class="page-sub">Rent income &amp; vendor payouts</div></div>
    </div>

    <div class="metrics" style="grid-template-columns:repeat(3,1fr)">
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Collected (Lifetime)</span><div class="metric-icon green"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg></div></div>
        <div class="metric-value"><?=h(money_fmt($collected))?></div>
        <div class="metric-change"><span class="up"><?=h((string)count($payments))?> transaction<?=(count($payments)!==1?'s':'')?></span></div>
      </div>
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Vendor Payouts Pending</span><div class="metric-icon yellow"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div></div>
        <div class="metric-value"><?=h(money_fmt($pendingOut))?></div>
        <div class="metric-change"><?=h((string)count(array_filter($payouts, fn($po) => $po['status']==='Pending')))?> pending payout<?=(count($payouts)!==1?'s':'')?></div>
      </div>
      <div class="metric-card">
        <div class="metric-header"><span class="metric-label">Total Transactions</span><div class="metric-icon blue"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg></div></div>
        <div class="metric-value"><?=h((string)(count($payments)+count($payouts)))?></div>
        <div class="metric-change">Rent + vendor combined</div>
      </div>
    </div>

    <!-- Rent payments -->
    <div class="card">
      <div class="card-header"><span class="card-title">Rent Payments</span><span class="card-action">Export</span></div>
      <?php foreach ($payments as $p): ?>
        <div class="payment-item">
          <div class="payment-icon in"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg></div>
          <div class="payment-body">
            <div class="payment-name">Rent — <?=h($p['tenant_name'])?></div>
            <div class="payment-meta">Unit <?=h($p['unit_label'])?> · <?=h($p['created_at'])?><?=($p['memo']?' · '.h($p['memo']):'')?></div>
          </div>
          <div class="payment-amount in">+<?=h(money_fmt((int)$p['amount_cents']))?></div>
        </div>
      <?php endforeach; ?>
      <?php if (!$payments): ?><div style="padding:24px;text-align:center;color:var(--text-muted)">No payments recorded yet</div><?php endif; ?>
    </div>

    <!-- Vendor payouts -->
    <?php if ($payouts): ?>
    <div class="card">
      <div class="card-header"><span class="card-title">Vendor Payouts</span></div>
      <?php foreach ($payouts as $po): ?>
        <div class="payment-item">
          <div class="payment-icon out"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg></div>
          <div class="payment-body">
            <div class="payment-name"><?=h($po['vendor_name'])?></div>
            <div class="payment-meta"><?=h($po['created_at'])?> · Invoice: <?=h($po['invoice_status'])?> · <span class="badge <?=($po['status']==='Paid'?'badge-green':'badge-yellow')?>" style="font-size:11px;padding:1px 7px"><?=h($po['status'])?></span></div>
          </div>
          <div class="payment-amount out">-<?=h(money_fmt((int)$po['amount_cents']))?></div>
          <?php if ($po['status']==='Pending'): ?>
            <form method="post" action="<?=h(app_url(['action'=>'owner_pay_payout']))?>" style="margin-left:8px">
              <input type="hidden" name="payout_id" value="<?=h((string)$po['id'])?>"/>
              <button class="action-btn primary" type="submit">Mark Paid</button>
            </form>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  if ($page === 'owner_vendors') {
    render_owner_head('SMG — Vendors');

    $vendors = $pdo->query("
      SELECT u.id, u.full_name, u.email,
        (SELECT COUNT(*) FROM jobs j WHERE j.vendor_id=u.id) AS job_count
      FROM users u WHERE u.role='VENDOR' ORDER BY u.id
    ")->fetchAll();

    $vendorColors = ['linear-gradient(135deg,#3b82f6,#1d4ed8)', 'linear-gradient(135deg,#f59e0b,#d97706)', 'linear-gradient(135deg,#10B981,#059669)', 'linear-gradient(135deg,#8b5cf6,#6d28d9)', 'linear-gradient(135deg,#ef4444,#dc2626)'];

    render_owner_shell_start($u, 'owner_vendors', 'Vendors', '+ Add Vendor', 'add-vendor');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="page-header">
      <div><div class="page-title">Vendors</div><div class="page-sub"><?=h((string)count($vendors))?> vendor<?=(count($vendors)!==1?'s':'')?></div></div>
    </div>

    <?php foreach ($vendors as $i => $v):
      $initials = implode('', array_map(fn($w) => strtoupper($w[0]), array_slice(explode(' ', $v['full_name']), 0, 2)));
      $color = $vendorColors[$i % count($vendorColors)];
    ?>
      <div class="vendor-card">
        <div class="vendor-avatar" style="background:<?=h($color)?>"><?=h($initials)?></div>
        <div>
          <div class="vendor-name"><?=h($v['full_name'])?></div>
          <div class="vendor-trade"><?=h($v['email'])?></div>
        </div>
        <div class="vendor-stats">
          <div class="vendor-jobs"><?=h((string)$v['job_count'])?> job<?=($v['job_count']!=1?'s':'')?></div>
        </div>
        <div style="margin-left:12px;display:flex;gap:6px">
          <span class="action-btn primary">Assign</span>
        </div>
      </div>
    <?php endforeach; ?>
    <?php if (!$vendors): ?>
      <div class="card"><div style="padding:40px;text-align:center;color:var(--text-muted)">No vendors yet. Add vendor users via the database or init_db.php.</div></div>
    <?php endif; ?>
    <?php
    render_owner_shell_end(owner_modal_js($pdo, $u['id']));
    exit;
  }

  // ── TENANTS PAGE ─────────────────────────────────────────────
  if ($page === 'owner_tenants') {
    $allTenants = $pdo->query("
      SELECT t.id, t.full_name, t.email,
             u.unit_label, l.start_date, l.end_date, l.rent_cents,
             (SELECT status FROM payments WHERE lease_id=l.id ORDER BY id DESC LIMIT 1) AS last_pay
      FROM users t
      JOIN leases l ON l.tenant_id=t.id AND l.status='ACTIVE'
      JOIN units u ON u.id=l.unit_id
      WHERE t.role='TENANT'
      ORDER BY t.full_name
    ")->fetchAll();
    $tc = count($allTenants);
    $om = (int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed'")->fetchColumn();
    $badges = ['tenants'=>$tc?:null,'maintenance'=>$om?:null];
    render_owner_head('SMG — Tenants');
    render_owner_shell_start($u, 'owner_tenants', 'Tenants', '+ Add Tenant', 'add-tenant', $badges);
    ?>
    <?php if ($flash): ?><div class="<?=($flash['type']==='ok'?'flash-ok':'flash-err')?>"><?=h($flash['msg'])?></div><?php endif; ?>
    <div class="page-header">
      <div><div class="page-title">Tenants</div><div class="page-sub"><?=h((string)$tc)?> active tenant<?=($tc!==1?'s':'')?></div></div>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Name</th><th>Unit</th><th>Lease Period</th><th>Rent</th><th>Payment</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach ($allTenants as $t):
          $ps=$t['last_pay']??null;
          if($ps==='Processed'){$pc='badge-green';$pl='Paid';}
          elseif($ps==='Pending'){$pc='badge-yellow';$pl='Pending';}
          else{$pc='badge-red';$pl='Late';}
        ?>
          <tr>
            <td><div class="td-name"><?=h($t['full_name'])?></div><div class="td-sub"><?=h($t['email'])?></div></td>
            <td><span class="unit-link"><?=h('Unit #'.$t['unit_label'])?></span></td>
            <td style="color:var(--text-muted)"><?=h(date("M 'y",strtotime($t['start_date'])))?> – <?=h(date("M 'y",strtotime($t['end_date'])))?></td>
            <td><?=h(money_fmt((int)$t['rent_cents']))?>/mo</td>
            <td><span class="badge <?=$pc?>"><?=$pl?></span></td>
            <td><div class="td-actions"><span class="action-btn primary">Edit</span><span class="action-btn">Message</span></div></td>
          </tr>
        <?php endforeach; ?>
        <?php if(!$allTenants):?><tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px">No active tenants</td></tr><?php endif;?>
        </tbody>
      </table>
    </div>
    <?php render_owner_shell_end(owner_modal_js($pdo, $u['id'])); exit; }

  // ── REPORTS PAGE ─────────────────────────────────────────────
  if ($page === 'owner_reports') {
    $rev=(int)$pdo->query("SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE status='Processed'")->fetchColumn();
    $exp=(int)$pdo->query("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE status='Paid'")->fetchColumn();
    $net=$rev-$exp;
    $tc=(int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='TENANT'")->fetchColumn();
    $om=(int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed'")->fetchColumn();
    $badges=['tenants'=>$tc?:null,'maintenance'=>$om?:null];
    render_owner_head('SMG — Reports');
    render_owner_shell_start($u,'owner_reports','Reports','','', $badges);
    ?>
    <div class="page-header">
      <div><div class="page-title">Reports</div><div class="page-sub">Financial overview</div></div>
      <button class="btn btn-ghost">Export QuickBooks</button>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px">
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
        <div style="font-size:12.5px;font-weight:500;color:var(--text-muted);margin-bottom:8px">Gross Revenue</div>
        <div style="font-size:28px;font-weight:700;color:var(--accent)"><?=h(money_fmt($rev))?></div>
        <div style="font-size:12px;color:var(--text-faint)">All processed payments</div>
      </div>
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
        <div style="font-size:12.5px;font-weight:500;color:var(--text-muted);margin-bottom:8px">Total Expenses</div>
        <div style="font-size:28px;font-weight:700;color:var(--red)"><?=h(money_fmt($exp))?></div>
        <div style="font-size:12px;color:var(--text-faint)">Paid vendor payouts</div>
      </div>
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
        <div style="font-size:12.5px;font-weight:500;color:var(--text-muted);margin-bottom:8px">Net Cashflow</div>
        <div style="font-size:28px;font-weight:700"><?=h(money_fmt($net))?></div>
        <div style="font-size:12px;color:var(--text-faint)">Revenue minus expenses</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><span class="card-title">Monthly Cashflow</span><span class="card-action">Download CSV</span></div>
        <div class="chart-area" id="dash-chart"></div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Expense Breakdown</span></div>
        <table><thead><tr><th>Category</th><th>Amount</th></tr></thead><tbody>
          <tr><td>Vendor Payouts (Paid)</td><td><?=h(money_fmt($exp))?></td></tr>
          <tr><td>Vendor Payouts (Pending)</td><td><?=h(money_fmt((int)$pdo->query("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE status='Pending'")->fetchColumn()))?></td></tr>
        </tbody></table>
      </div>
    </div>
    <?php render_owner_shell_end(owner_modal_js($pdo, $u['id'])); exit; }

  // ── USERS PAGE ─────────────────────────────────────────────
  if ($page === 'owner_users') {
    $allUsers=$pdo->query("SELECT id,full_name,email,role FROM users ORDER BY role,full_name")->fetchAll();
    $tc=(int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='TENANT'")->fetchColumn();
    $om=(int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed'")->fetchColumn();
    $badges=['tenants'=>$tc?:null,'maintenance'=>$om?:null];
    $rColors=['OWNER'=>'badge-green','TENANT'=>'badge-blue','VENDOR'=>'badge-yellow'];
    $rBgs=['OWNER'=>'linear-gradient(135deg,var(--accent),#059669)','TENANT'=>'linear-gradient(135deg,#3b82f6,#1d4ed8)','VENDOR'=>'linear-gradient(135deg,#f59e0b,#d97706)'];
    render_owner_head('SMG — Users');
    render_owner_shell_start($u,'owner_users','Users','+ Add User','add-user',$badges);
    ?>
    <div class="page-header">
      <div><div class="page-title">Users</div><div class="page-sub">Manage access and roles</div></div>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach($allUsers as $usr):
          $ini=implode('',array_map(fn($w)=>strtoupper($w[0]),array_slice(explode(' ',$usr['full_name']),0,2)));
          $rc=$rColors[$usr['role']]??'badge-gray';
          $bg=$rBgs[$usr['role']]??'#9ca3af';
        ?>
          <tr>
            <td><div style="display:flex;align-items:center;gap:10px"><div style="width:30px;height:30px;border-radius:50%;background:<?=h($bg)?>;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0"><?=h($ini)?></div><div><div class="td-name"><?=h($usr['full_name'])?></div><div class="td-sub"><?=h($usr['email'])?></div></div></div></td>
            <td><span class="badge <?=$rc?>"><?=h($usr['role'])?></span></td>
            <td><span class="badge badge-green">Active</span></td>
            <td><div class="td-actions"><span class="action-btn primary">Edit</span><?=((int)$usr['id']!==(int)$u['id']?'<span class="action-btn danger">Disable</span>':'')?></div></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php render_owner_shell_end(owner_modal_js($pdo, $u['id'])); exit; }

  // ── SETTINGS PAGE ─────────────────────────────────────────────
  if ($page === 'owner_settings') {
    $tc=(int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='TENANT'")->fetchColumn();
    $om=(int)$pdo->query("SELECT COUNT(*) FROM maintenance_requests WHERE status!='Completed'")->fetchColumn();
    $badges=['tenants'=>$tc?:null,'maintenance'=>$om?:null];
    render_owner_head('SMG — Settings');
    render_owner_shell_start($u,'owner_settings','Settings','','',$badges);
    ?>
    <div class="page-header"><div><div class="page-title">Settings</div><div class="page-sub">Platform configuration</div></div></div>
    <?php $settingSections=[
      'Notifications'=>[['Email notifications','Receive alerts for payments, maintenance, and lease events',true],['Late payment reminders','Auto-send reminders 3 days before and on due date',true]],
      'Payments'=>[['Autopay','Allow tenants to enable automatic monthly payments',true]],
      'Security'=>[['Two-factor authentication','TOTP required for Owner role','badge'],['Audit log','All sensitive actions are logged and immutable','badge']],
    ];
    foreach($settingSections as $stitle=>$srows):?>
    <div style="margin-bottom:24px">
      <div style="font-size:13px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px"><?=h($stitle)?></div>
      <?php foreach($srows as[$lbl,$desc,$val]):?>
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;box-shadow:var(--shadow)">
        <div><div style="font-size:14px;font-weight:500"><?=h($lbl)?></div><div style="font-size:12.5px;color:var(--text-muted);margin-top:2px"><?=h($desc)?></div></div>
        <?php if($val==='badge'):?><span class="badge badge-green" style="padding:4px 12px">Enabled</span><?php else:?><button onclick="this.style.background=(this.dataset.on==='1')?'var(--border)':'var(--accent)';this.dataset.on=(this.dataset.on==='1')?'0':'1'" data-on="1" style="width:40px;height:22px;border-radius:999px;background:var(--accent);border:none;cursor:pointer;position:relative;flex-shrink:0"></button><?php endif;?>
      </div>
      <?php endforeach;?>
    </div>
    <?php endforeach;?>
    <?php render_owner_shell_end(owner_modal_js($pdo, $u['id'])); exit; }

  redirect('index.php?page=owner_dashboard');
}

// -------------------------
// TENANT pages
// -------------------------
if ($u['role'] === 'TENANT') {

  // Find tenant's active lease info (if any)
  $lease = $pdo->prepare("
    SELECT l.*, u.unit_label, p.address
    FROM leases l
    JOIN units u ON u.id=l.unit_id
    JOIN properties p ON p.id=u.property_id
    WHERE l.tenant_id=? AND l.status='ACTIVE'
    ORDER BY l.id DESC LIMIT 1
  ");
  $lease->execute([$u['id']]);
  $lease = $lease->fetch();

  if ($page === 'tenant_dashboard') {
    $paid = (int)$pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE payer_user_id=? AND status='Processed'")
      ->execute([$u['id']]) ?: 0;
    $stmt = $pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE payer_user_id=? AND status='Processed'");
    $stmt->execute([$u['id']]);
    $paid = (int)$stmt->fetchColumn();

    $openMaint = 0;
    if ($lease) {
      $st = $pdo->prepare("SELECT COUNT(*) FROM maintenance_requests WHERE lease_id=? AND status!='Completed'");
      $st->execute([(int)$lease['id']]);
      $openMaint = (int)$st->fetchColumn();
    }

    render_head('SMG — Tenant Dashboard');
    render_app_shell_start($u, 'tenant_dashboard', 'Tenant Dashboard');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="grid">
      <div class="kpi" style="grid-column:span 4">
        <div class="k">Lease</div>
        <div class="v"><?=h($lease ? ('Unit '.$lease['unit_label']) : '—')?></div>
        <div class="muted" style="margin-top:6px"><?=h($lease['address'] ?? 'No active lease')?></div>
      </div>
      <div class="kpi" style="grid-column:span 4">
        <div class="k">Open maintenance</div>
        <div class="v"><?=h((string)$openMaint)?></div>
      </div>
      <div class="kpi" style="grid-column:span 4">
        <div class="k">Payments (processed)</div>
        <div class="v"><?=h(money_fmt($paid))?></div>
      </div>

      <div class="card" style="grid-column:span 12">
        <div class="hd">
          <div class="h1">Quick actions</div>
        </div>
        <div class="bd row">
          <a class="btnlink" href="index.php?page=tenant_maintenance" style="flex:0 0 auto">New Maintenance</a>
          <a class="btnlink" href="index.php?page=tenant_payments" style="flex:0 0 auto">Make Payment</a>
        </div>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  if ($page === 'tenant_maintenance') {
    render_head('SMG — Maintenance');
    render_app_shell_start($u, 'tenant_maintenance', 'Maintenance');

    $rows = [];
    if ($lease) {
      $st = $pdo->prepare("SELECT * FROM maintenance_requests WHERE lease_id=? ORDER BY id DESC");
      $st->execute([(int)$lease['id']]);
      $rows = $st->fetchAll();
    }
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="grid">
      <div class="card" style="grid-column:span 12">
        <div class="hd"><div class="h1">New request</div></div>
        <div class="bd">
          <?php if (!$lease): ?>
            <div class="error">No active lease found for your account.</div>
          <?php else: ?>
            <form method="post" action="<?=h(app_url(['action'=>'tenant_new_maint']))?>" class="form">
              <div class="col-8">
                <label>Title</label>
                <input name="title" placeholder="Leaking faucet — kitchen sink" required />
              </div>
              <div class="col-4">
                <label>Priority</label>
                <select name="priority">
                  <option>Normal</option>
                  <option>Urgent</option>
                </select>
              </div>
              <div class="col-12">
                <label>Description</label>
                <textarea name="description" placeholder="Describe the issue, best times for access, and any notes…" required></textarea>
              </div>
              <div class="col-12 row" style="justify-content:flex-end">
                <button class="btn btn-primary" type="submit">Submit request</button>
              </div>
            </form>
          <?php endif; ?>
        </div>
      </div>

      <div class="card" style="grid-column:span 12">
        <div class="hd"><div class="h1">Your requests</div></div>
        <div class="bd">
          <table>
            <thead><tr><th>ID</th><th>Title</th><th>Priority</th><th>Status</th><th>Created</th></tr></thead>
            <tbody>
              <?php foreach ($rows as $r): ?>
                <tr>
                  <td>#<?=h((string)$r['id'])?></td>
                  <td><?=h($r['title'])?></td>
                  <td><span class="badge <?=($r['priority']==='Urgent'?'b-red':'b-blue')?>"><?=h($r['priority'])?></span></td>
                  <td><span class="badge b-yellow"><?=h($r['status'])?></span></td>
                  <td class="muted"><?=h($r['created_at'])?></td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$rows): ?>
                <tr><td colspan="5" class="muted">No requests yet.</td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  if ($page === 'tenant_payments') {
    render_head('SMG — Payments');
    render_app_shell_start($u, 'tenant_payments', 'Payments');

    $pay = $pdo->prepare("
      SELECT * FROM payments
      WHERE payer_user_id=?
      ORDER BY id DESC LIMIT 25
    ");
    $pay->execute([$u['id']]);
    $pay = $pay->fetchAll();

    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="grid">
      <div class="card" style="grid-column:span 12">
        <div class="hd"><div class="h1">Make a payment</div></div>
        <div class="bd">
          <?php if (!$lease): ?>
            <div class="error">No active lease found for your account.</div>
          <?php else: ?>
            <div class="muted" style="font-weight:900;margin-bottom:10px">Lease: Unit <?=h($lease['unit_label'])?> • <?=h($lease['address'])?></div>
            <form method="post" action="<?=h(app_url(['action'=>'tenant_pay']))?>" class="form">
              <div class="col-4">
                <label>Amount (USD)</label>
                <input name="amount" type="number" step="0.01" min="0" placeholder="1850.00" required />
              </div>
              <div class="col-8">
                <label>Memo (optional)</label>
                <input name="memo" placeholder="March rent" />
              </div>
              <div class="col-12 row" style="justify-content:flex-end">
                <button class="btn btn-primary" type="submit">Submit payment</button>
              </div>
            </form>
          <?php endif; ?>
        </div>
      </div>

      <div class="card" style="grid-column:span 12">
        <div class="hd"><div class="h1">Payment history</div></div>
        <div class="bd">
          <table>
            <thead><tr><th>ID</th><th>Amount</th><th>Status</th><th>Memo</th><th>Created</th></tr></thead>
            <tbody>
              <?php foreach ($pay as $p): ?>
                <tr>
                  <td>#<?=h((string)$p['id'])?></td>
                  <td><?=h(money_fmt((int)$p['amount_cents']))?></td>
                  <td><span class="badge <?=($p['status']==='Processed'?'b-green':'b-yellow')?>"><?=h($p['status'])?></span></td>
                  <td class="muted"><?=h((string)$p['memo'])?></td>
                  <td class="muted"><?=h($p['created_at'])?></td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$pay): ?>
                <tr><td colspan="5" class="muted">No payments yet.</td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  redirect('index.php?page=tenant_dashboard');
}

// -------------------------
// VENDOR pages
// -------------------------
if ($u['role'] === 'VENDOR') {

  if ($page === 'vendor_dashboard') {
    $jobsOpen = (int)$pdo->prepare("SELECT COUNT(*) FROM jobs WHERE vendor_id=? AND status!='Completed'")
      ->execute([$u['id']]) ?: 0;
    $st = $pdo->prepare("SELECT COUNT(*) FROM jobs WHERE vendor_id=? AND status!='Completed'");
    $st->execute([$u['id']]);
    $jobsOpen = (int)$st->fetchColumn();

    $payoutPending = (int)$pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE vendor_id=? AND status='Pending'")
      ->execute([$u['id']]) ?: 0;
    $st = $pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE vendor_id=? AND status='Pending'");
    $st->execute([$u['id']]);
    $payoutPending = (int)$st->fetchColumn();

    $payoutPaid = (int)$pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE vendor_id=? AND status='Paid'")
      ->execute([$u['id']]) ?: 0;
    $st = $pdo->prepare("SELECT COALESCE(SUM(amount_cents),0) FROM payouts WHERE vendor_id=? AND status='Paid'");
    $st->execute([$u['id']]);
    $payoutPaid = (int)$st->fetchColumn();

    render_head('SMG — Vendor Dashboard');
    render_app_shell_start($u, 'vendor_dashboard', 'Vendor Dashboard');
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="grid">
      <div class="kpi" style="grid-column:span 4"><div class="k">Open jobs</div><div class="v"><?=h((string)$jobsOpen)?></div></div>
      <div class="kpi" style="grid-column:span 4"><div class="k">Pending payouts</div><div class="v"><?=h(money_fmt($payoutPending))?></div></div>
      <div class="kpi" style="grid-column:span 4"><div class="k">Paid (lifetime)</div><div class="v"><?=h(money_fmt($payoutPaid))?></div></div>

      <div class="card" style="grid-column:span 12">
        <div class="hd"><div class="h1">Quick actions</div></div>
        <div class="bd row">
          <a class="btnlink" href="index.php?page=vendor_jobs">View Jobs</a>
          <a class="btnlink" href="index.php?page=vendor_payments">View Payments</a>
        </div>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  if ($page === 'vendor_jobs') {
    render_head('SMG — Jobs');
    render_app_shell_start($u, 'vendor_jobs', 'Jobs');

    $jobs = $pdo->prepare("
      SELECT j.*, mr.title AS maint_title, mr.priority, mr.status AS maint_status, u.unit_label
      FROM jobs j
      JOIN maintenance_requests mr ON mr.id=j.maintenance_id
      JOIN leases l ON l.id=mr.lease_id
      JOIN units u ON u.id=l.unit_id
      WHERE j.vendor_id=?
      ORDER BY j.id DESC
    ");
    $jobs->execute([$u['id']]);
    $jobs = $jobs->fetchAll();
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="card">
      <div class="hd"><div class="h1">Assigned jobs</div></div>
      <div class="bd">
        <table>
          <thead><tr><th>Job</th><th>Maintenance</th><th>Unit</th><th>Priority</th><th>Scheduled</th><th>Status</th></tr></thead>
          <tbody>
            <?php foreach ($jobs as $j): ?>
              <tr>
                <td>#<?=h((string)$j['id'])?></td>
                <td><?=h($j['maint_title'])?></td>
                <td><?=h($j['unit_label'])?></td>
                <td><span class="badge <?=($j['priority']==='Urgent'?'b-red':'b-blue')?>"><?=h($j['priority'])?></span></td>
                <td class="muted"><?=h((string)($j['scheduled_for'] ?? '—'))?></td>
                <td><span class="badge b-yellow"><?=h($j['status'])?></span></td>
              </tr>
              <tr>
                <td colspan="6" style="background:rgba(255,255,255,.01)">
                  <div class="form" style="margin-top:8px">
                    <div class="col-12 muted" style="font-weight:900">Submit invoice for Job #<?=h((string)$j['id'])?></div>
                    <form method="post" action="<?=h(app_url(['action'=>'vendor_invoice']))?>" class="form col-12" style="margin:0">
                      <input type="hidden" name="job_id" value="<?=h((string)$j['id'])?>" />
                      <div class="col-6">
                        <label>Description</label>
                        <input name="desc" placeholder="Work performed summary…" required />
                      </div>
                      <div class="col-3">
                        <label>Labor (USD)</label>
                        <input name="labor" type="number" step="0.01" min="0" placeholder="150.00" required />
                      </div>
                      <div class="col-3">
                        <label>Parts (USD)</label>
                        <input name="parts" type="number" step="0.01" min="0" placeholder="45.00" required />
                      </div>
                      <div class="col-12 row" style="justify-content:flex-end">
                        <button class="btn btn-primary" type="submit">Submit Invoice</button>
                      </div>
                    </form>
                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
            <?php if (!$jobs): ?>
              <tr><td colspan="6" class="muted">No jobs assigned yet.</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  if ($page === 'vendor_payments') {
    render_head('SMG — Payments');
    render_app_shell_start($u, 'vendor_payments', 'Payments');

    $payouts = $pdo->prepare("
      SELECT po.*, i.total_cents, i.status AS invoice_status, j.id AS job_id
      FROM payouts po
      JOIN invoices i ON i.id=po.invoice_id
      JOIN jobs j ON j.id=i.job_id
      WHERE po.vendor_id=?
      ORDER BY po.id DESC
      LIMIT 50
    ");
    $payouts->execute([$u['id']]);
    $payouts = $payouts->fetchAll();
    ?>
    <?php if ($flash): ?>
      <div class="<?=($flash['type']==='ok'?'ok':'error')?>"><?=h($flash['msg'])?></div>
    <?php endif; ?>

    <div class="card">
      <div class="hd"><div class="h1">Payouts</div></div>
      <div class="bd">
        <table>
          <thead><tr><th>Payout</th><th>Job</th><th>Invoice</th><th>Amount</th><th>Status</th><th>Created</th></tr></thead>
          <tbody>
            <?php foreach ($payouts as $po): ?>
              <tr>
                <td>#<?=h((string)$po['id'])?></td>
                <td class="muted">#<?=h((string)$po['job_id'])?></td>
                <td><span class="badge b-blue"><?=h($po['invoice_status'])?></span></td>
                <td><?=h(money_fmt((int)$po['amount_cents']))?></td>
                <td><span class="badge <?=($po['status']==='Paid'?'b-green':'b-yellow')?>"><?=h($po['status'])?></span></td>
                <td class="muted"><?=h($po['created_at'])?></td>
              </tr>
            <?php endforeach; ?>
            <?php if (!$payouts): ?>
              <tr><td colspan="6" class="muted">No payouts yet.</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php
    render_app_shell_end();
    exit;
  }

  redirect('index.php?page=vendor_dashboard');
}

// Fallback
redirect('index.php?page=help');
