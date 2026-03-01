<?php
// Vendor dashboard view. Similar design system, but tailored for vendors
// (contractors). You can populate $openJobs and $nextPayment if available.
$openJobs = $openJobs ?? 0;
$nextPayment = $nextPayment ?? 'N/A';
?>
<div class="dashboard">
    <aside class="sidebar">
        <div class="logo">SMG</div>
        <ul class="nav">
            <li class="nav-item active" onclick="showPage('dashboard')">Dashboard</li>
            <li class="nav-item" onclick="showPage('jobs')">Jobs</li>
            <li class="nav-item" onclick="showPage('payments')">Payments</li>
            <li class="nav-item" onclick="showPage('profile')">Profile</li>
        </ul>
    </aside>
    <div class="main">
        <div class="topbar">
            <h1>Vendor Portal</h1>
        </div>
        <!-- Dashboard page -->
        <div id="page-dashboard" class="page">
            <div class="metrics">
                <div class="metric">
                    <span class="label">Open Jobs</span>
                    <span class="value"><?php echo (int)$openJobs; ?></span>
                </div>
                <div class="metric">
                    <span class="label">Next Payment</span>
                    <span class="value"><?php echo htmlspecialchars($nextPayment); ?></span>
                </div>
            </div>
            <div class="card">
                <h3>Welcome, Contractor!</h3>
                <p>You can see your assigned jobs, update their statuses and view your payment schedule.</p>
            </div>
        </div>
        <!-- Jobs page -->
        <div id="page-jobs" class="page" style="display:none;">
            <h2>Your Jobs</h2>
            <p>List and manage your current jobs here.</p>
        </div>
        <!-- Payments page -->
        <div id="page-payments" class="page" style="display:none;">
            <h2>Payments</h2>
            <p>View your payment history and upcoming payments here.</p>
        </div>
        <!-- Profile page -->
        <div id="page-profile" class="page" style="display:none;">
            <h2>Your Profile</h2>
            <p>Update your company details and contact information.</p>
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