<?php
// Tenant dashboard. Utilises the same design system as owner.php but with
// tenant-specific navigation and metrics. Controller variables such as
// $openRequests and $nextRentDue can be set to populate the metrics.
$openRequests = $openRequests ?? 0;
$nextRentDue = $nextRentDue ?? 'N/A';
?>
<div class="dashboard">
    <aside class="sidebar">
        <div class="logo">SMG</div>
        <ul class="nav">
            <li class="nav-item active" onclick="showPage('dashboard')">Dashboard</li>
            <li class="nav-item" onclick="showPage('maintenance')">Maintenance</li>
            <li class="nav-item" onclick="showPage('payments')">Payments</li>
            <li class="nav-item" onclick="showPage('profile')">Profile</li>
        </ul>
    </aside>
    <div class="main">
        <div class="topbar">
            <h1>Tenant Portal</h1>
        </div>
        <!-- Dashboard page -->
        <div id="page-dashboard" class="page">
            <div class="metrics">
                <div class="metric">
                    <span class="label">Open Requests</span>
                    <span class="value"><?php echo (int)$openRequests; ?></span>
                </div>
                <div class="metric">
                    <span class="label">Next Rent Due</span>
                    <span class="value"><?php echo htmlspecialchars($nextRentDue); ?></span>
                </div>
            </div>
            <div class="card">
                <h3>Welcome!</h3>
                <p>From here you can file maintenance requests, view your payment history, and update your profile information.</p>
            </div>
        </div>
        <!-- Maintenance page -->
        <div id="page-maintenance" class="page" style="display:none;">
            <h2>Maintenance Requests</h2>
            <p>You can display a list of your maintenance requests here and a form to submit a new request.</p>
        </div>
        <!-- Payments page -->
        <div id="page-payments" class="page" style="display:none;">
            <h2>Payments</h2>
            <p>Here you can view your past payments and make a new payment.</p>
        </div>
        <!-- Profile page -->
        <div id="page-profile" class="page" style="display:none;">
            <h2>Your Profile</h2>
            <p>Update your contact information and password here.</p>
        </div>
    </div>
</div>

<script>
function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.getElementById('page-' + page).style.display = 'block';
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.textContent.trim().toLowerCase() === page) item.classList.add('active');
    });
}
</script>