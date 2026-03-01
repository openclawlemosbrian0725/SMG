<?php
// Owner dashboard view. This template uses the custom design system defined in
// style.css. The controller should prepare variables such as $properties,
// $tenants, $maintenanceRequests and $payments to populate the tables.
// For demonstration, dummy arrays can be used if these variables are not set.
$properties = $properties ?? [];
$monthlyRevenue = $monthlyRevenue ?? 0;
$openMaintenance = $openMaintenance ?? 0;
$occupancyRate = $occupancyRate ?? 0;
?>
<div class="dashboard">
    <!-- Sidebar navigation -->
    <aside class="sidebar">
        <div class="logo">SMG</div>
        <ul class="nav">
            <li class="nav-item active" onclick="showPage('dashboard')">Dashboard</li>
            <li class="nav-item" onclick="showPage('properties')">Properties</li>
            <li class="nav-item" onclick="showPage('tenants')">Tenants</li>
            <li class="nav-item" onclick="showPage('maintenance')">Maintenance</li>
            <li class="nav-item" onclick="showPage('payments')">Payments</li>
        </ul>
    </aside>
    <div class="main">
        <!-- Top bar with page title and actions -->
        <div class="topbar">
            <h1>Owner Portal</h1>
            <div>
                <button class="btn btn-accent" onclick="openModal('modalAddProperty')">Add Property</button>
                <button class="btn btn-outline" onclick="openModal('modalAddUnit')">Add Unit</button>
            </div>
        </div>
        <!-- Dashboard page -->
        <div id="page-dashboard" class="page">
            <div class="metrics">
                <div class="metric">
                    <span class="label">Monthly Revenue</span>
                    <span class="value">$<?php echo number_format($monthlyRevenue, 2); ?></span>
                </div>
                <div class="metric">
                    <span class="label">Open Maintenance</span>
                    <span class="value"><?php echo (int)$openMaintenance; ?></span>
                </div>
                <div class="metric">
                    <span class="label">Occupancy Rate</span>
                    <span class="value"><?php echo number_format($occupancyRate, 0); ?>%</span>
                </div>
            </div>
            <div class="card">
                <h3>Properties</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Units</th>
                            <th>Location</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($properties as $property): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($property['name']); ?></td>
                                <td><?php echo (int)$property['unit_count']; ?></td>
                                <td><?php echo htmlspecialchars($property['location']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (empty($properties)): ?>
                            <tr><td colspan="3">No properties yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Properties page -->
        <div id="page-properties" class="page" style="display:none;">
            <h2>Properties</h2>
            <div class="card">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Address</th>
                            <th>Units</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($properties as $property): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($property['name']); ?></td>
                            <td><?php echo htmlspecialchars($property['address']); ?></td>
                            <td><?php echo (int)$property['unit_count']; ?></td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if (empty($properties)): ?>
                            <tr><td colspan="3">No properties available.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- Tenants page placeholder -->
        <div id="page-tenants" class="page" style="display:none;">
            <h2>Tenants</h2>
            <p>This section will list tenants associated with your units. It can be expanded to include forms for adding tenants, viewing lease details and more.</p>
        </div>
        <!-- Maintenance page placeholder -->
        <div id="page-maintenance" class="page" style="display:none;">
            <h2>Maintenance</h2>
            <p>Track maintenance requests here. You can add integration with your database to display open and completed requests.</p>
        </div>
        <!-- Payments page placeholder -->
        <div id="page-payments" class="page" style="display:none;">
            <h2>Payments</h2>
            <p>View rent payments and record new payments. Add your integration logic as needed.</p>
        </div>
    </div>
</div>

<!-- Modal for adding a property -->
<div id="modalAddProperty" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <span class="modal-title">Add Property</span>
            <button class="close-btn" onclick="closeModal('modalAddProperty')">&times;</button>
        </div>
        <form method="POST" action="/owner/add-property">
            <div class="form-group">
                <label for="prop-name">Property Name</label>
                <input class="form-input" id="prop-name" name="name" required>
            </div>
            <div class="form-group">
                <label for="prop-location">Location</label>
                <input class="form-input" id="prop-location" name="location" required>
            </div>
            <div class="form-group">
                <label for="prop-units">Number of Units</label>
                <input class="form-input" type="number" id="prop-units" name="unit_count" min="1" required>
            </div>
            <button class="btn btn-accent" type="submit">Add Property</button>
        </form>
    </div>
</div>

<!-- Modal for adding a unit -->
<div id="modalAddUnit" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <span class="modal-title">Add Unit</span>
            <button class="close-btn" onclick="closeModal('modalAddUnit')">&times;</button>
        </div>
        <form method="POST" action="/owner/add-unit">
            <div class="form-group">
                <label for="unit-property">Property</label>
                <select id="unit-property" name="property_id" class="form-input">
                    <?php foreach ($properties as $property): ?>
                        <option value="<?php echo (int)$property['id']; ?>"><?php echo htmlspecialchars($property['name']); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="unit-number">Unit Number</label>
                <input class="form-input" id="unit-number" name="number" required>
            </div>
            <div class="form-group">
                <label for="unit-rent">Monthly Rent ($)</label>
                <input class="form-input" type="number" id="unit-rent" name="rent" min="0" step="0.01" required>
            </div>
            <button class="btn btn-accent" type="submit">Add Unit</button>
        </form>
    </div>
</div>

<script>
// Show a specific page and set active nav item
function showPage(page) {
    const pages = document.querySelectorAll('.page');
    pages.forEach(p => p.style.display = 'none');
    document.getElementById('page-' + page).style.display = 'block';
    // update active nav item
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => item.classList.remove('active'));
    navItems.forEach(item => {
        if (item.textContent.trim().toLowerCase() === page) item.classList.add('active');
    });
}

// Open a modal by id
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('active');
}

// Close a modal by id
function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove('active');
}
</script>