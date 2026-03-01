<?php
declare(strict_types=1);

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

final class OwnerController {
  public static function dashboard(): void {
    require_login();
    require_role(['OWNER', 'PROPERTY_MANAGER']);

    $pdo = db();

    $kpis = [
      'monthly_revenue' => (float)($pdo->query("
        SELECT COALESCE(SUM(amount),0) AS s
        FROM payments
        WHERE status='PAID' AND strftime('%Y-%m', paid_at)=strftime('%Y-%m','now')
      ")->fetch()['s'] ?? 0),
      'open_maintenance' => (int)($pdo->query("
        SELECT COUNT(*) AS c
        FROM maintenance_requests
        WHERE status IN ('OPEN','SCHEDULED','IN_PROGRESS')
      ")->fetch()['c'] ?? 0),
      'occupancy' => (int)($pdo->query("
        SELECT CAST(ROUND(
          100.0 * (SELECT COUNT(*) FROM tenancies WHERE status='ACTIVE')
          / NULLIF((SELECT COUNT(*) FROM units),0)
        ) AS INT) AS pct
      ")->fetch()['pct'] ?? 0),
    ];

    $properties = $pdo->query("
      SELECT p.id, p.name, p.address,
             (SELECT COUNT(*) FROM units u WHERE u.property_id=p.id) AS unit_count,
             (SELECT COUNT(*) FROM units u WHERE u.property_id=p.id AND u.status='OCCUPIED') AS occupied_count
      FROM properties p
      ORDER BY p.id ASC
    ")->fetchAll();

    $tenants = $pdo->query("
      SELECT t.id AS tenancy_id, u.unit_label, usr.name AS tenant_name, usr.email,
             l.start_date, l.end_date, l.rent_amount,
             (SELECT COALESCE(SUM(CASE WHEN status='PAID' THEN amount ELSE 0 END),0)
              FROM payments pay WHERE pay.lease_id=l.id AND strftime('%Y-%m', pay.paid_at)=strftime('%Y-%m','now')) AS paid_this_month,
             l.id AS lease_id
      FROM tenancies t
      JOIN units u ON u.id=t.unit_id
      JOIN users usr ON usr.id=t.tenant_user_id
      LEFT JOIN leases l ON l.tenancy_id=t.id AND l.status='ACTIVE'
      WHERE t.status='ACTIVE'
      ORDER BY usr.name ASC
      LIMIT 20
    ")->fetchAll();

    $maintenance = $pdo->query("
      SELECT mr.id, u.unit_label, mr.category, mr.priority, mr.status, mr.created_at, mr.description
      FROM maintenance_requests mr
      JOIN units u ON u.id=mr.unit_id
      ORDER BY mr.created_at DESC
      LIMIT 10
    ")->fetchAll();

    require __DIR__ . '/../views/owner.php';
  }

  public static function action(): void {
    require_login();
    require_role(['OWNER', 'PROPERTY_MANAGER']);

    $type = $_POST['type'] ?? '';
    $pdo = db();

    if ($type === 'add_property') {
      $name = trim($_POST['name'] ?? '');
      $address = trim($_POST['address'] ?? '');
      if ($name !== '' && $address !== '') {
        $stmt = $pdo->prepare("INSERT INTO properties(name,address,created_at) VALUES(:n,:a,datetime('now'))");
        $stmt->execute([':n'=>$name, ':a'=>$address]);
      }
      header('Location: /SMG/owner');
      exit;
    }

    if ($type === 'add_unit') {
      $property_id = (int)($_POST['property_id'] ?? 0);
      $label = trim($_POST['unit_label'] ?? '');
      if ($property_id > 0 && $label !== '') {
        $stmt = $pdo->prepare("INSERT INTO units(property_id,unit_label,status,created_at) VALUES(:p,:l,'VACANT',datetime('now'))");
        $stmt->execute([':p'=>$property_id, ':l'=>$label]);
      }
      header('Location: /SMG/owner');
      exit;
    }

    if ($type === 'record_payment') {
      $lease_id = (int)($_POST['lease_id'] ?? 0);
      $amount = (float)($_POST['amount'] ?? 0);
      $method = trim($_POST['method'] ?? 'MANUAL');
      if ($lease_id > 0 && $amount > 0) {
        $stmt = $pdo->prepare("
          SELECT t.tenant_user_id AS tenant_user_id
          FROM leases l JOIN tenancies t ON t.id=l.tenancy_id
          WHERE l.id=:id
        ");
        $stmt->execute([':id'=>$lease_id]);
        $row = $stmt->fetch();
        if ($row) {
          $stmt2 = $pdo->prepare("
            INSERT INTO payments(lease_id, tenant_user_id, amount, method, status, paid_at, created_at)
            VALUES(:l,:u,:a,:m,'PAID',datetime('now'),datetime('now'))
          ");
          $stmt2->execute([':l'=>$lease_id, ':u'=>(int)$row['tenant_user_id'], ':a'=>$amount, ':m'=>$method]);
        }
      }
      header('Location: /SMG/owner');
      exit;
    }

    header('Location: /SMG/owner');
    exit;
  }
}
