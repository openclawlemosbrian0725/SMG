<?php
declare(strict_types=1);

function db(): PDO {
  static $pdo = null;
  if ($pdo instanceof PDO) return $pdo;

  $config = require __DIR__ . '/config.php';
  $dsn = 'sqlite:' . $config['db_path'];

  $pdo = new PDO($dsn);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

  $pdo->exec('PRAGMA foreign_keys = ON;');
  $pdo->exec('PRAGMA journal_mode = WAL;');

  return $pdo;
}
