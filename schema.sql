-- Schema for Smart PHC — Medicine Stock Prediction & Early Warning System
-- SQLite3 with Foreign Keys, CHECK constraints, and Indexes

PRAGMA foreign_keys = ON;

-- 1. Primary Health Centres (PHCs)
CREATE TABLE IF NOT EXISTS phcs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    location TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    approval_status TEXT NOT NULL DEFAULT 'approved' CHECK(approval_status IN ('pending', 'approved', 'rejected')),
    active_status INTEGER NOT NULL DEFAULT 1 CHECK(active_status IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users (Role-based: admin, phc_staff)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'phc_staff')),
    phc_id INTEGER REFERENCES phcs(id) ON DELETE SET NULL,
    active_status INTEGER NOT NULL DEFAULT 1 CHECK(active_status IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- 3. Medicines Catalogue
CREATE TABLE IF NOT EXISTS medicines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    generic_name TEXT,
    category TEXT DEFAULT 'Essential Medicines',
    unit TEXT NOT NULL DEFAULT 'tablets',
    dosage_form TEXT,
    prescription_required INTEGER NOT NULL DEFAULT 1 CHECK(prescription_required IN (0, 1)),
    active_status INTEGER NOT NULL DEFAULT 1 CHECK(active_status IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Inventory per PHC & Medicine
CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
    usable_quantity INTEGER NOT NULL CHECK(usable_quantity >= 0),
    safety_stock INTEGER NOT NULL DEFAULT 50 CHECK(safety_stock >= 0),
    avg_daily_consumption REAL NOT NULL DEFAULT 0.0 CHECK(avg_daily_consumption >= 0),
    replenishment_lead_time_days INTEGER NOT NULL DEFAULT 7 CHECK(replenishment_lead_time_days >= 0),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(phc_id, medicine_id)
);

-- 5. Stock Transactions Ledger
CREATE TABLE IF NOT EXISTS stock_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
    transaction_type TEXT NOT NULL CHECK(transaction_type IN ('received', 'issued', 'adjustment', 'transfer_dispatch', 'transfer_receipt')),
    quantity INTEGER NOT NULL,
    previous_quantity INTEGER NOT NULL,
    new_quantity INTEGER NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    related_transfer_id INTEGER REFERENCES transfer_requests(id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Stock & Shortage Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL CHECK(alert_type IN ('stockout_imminent', 'below_safety_stock', 'lead_time_breach', 'zero_stock')),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('Critical', 'High', 'Medium', 'Safe')),
    message TEXT NOT NULL,
    predicted_stockout_date TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Emergency Transfer Requests
CREATE TABLE IF NOT EXISTS transfer_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requesting_phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    supplying_phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
    requested_quantity INTEGER NOT NULL CHECK(requested_quantity > 0),
    approved_quantity INTEGER CHECK(approved_quantity >= 0),
    reason TEXT NOT NULL,
    distance_km REAL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'dispatched', 'received', 'cancelled')),
    reviewed_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    admin_notes TEXT,
    dispatched_at TIMESTAMP,
    dispatched_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    received_at TIMESTAMP,
    received_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. Patient Medicine Delivery Requests
CREATE TABLE IF NOT EXISTS delivery_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_code TEXT UNIQUE NOT NULL,
    phc_id INTEGER NOT NULL REFERENCES phcs(id) ON DELETE CASCADE,
    medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK(quantity > 0),
    patient_name TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    delivery_address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Assigned', 'Out for delivery', 'Delivered', 'Rejected')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 9. Comprehensive Audit Trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    details TEXT,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for high-performance operational lookups
CREATE INDEX IF NOT EXISTS idx_inventory_phc_med ON inventory(phc_id, medicine_id);
CREATE INDEX IF NOT EXISTS idx_stock_trans_phc ON stock_transactions(phc_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_phc_status ON alerts(phc_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_lookup ON alerts(phc_id, medicine_id, alert_type, status);
CREATE INDEX IF NOT EXISTS idx_transfers_req_phc ON transfer_requests(requesting_phc_id, status);
CREATE INDEX IF NOT EXISTS idx_transfers_sup_phc ON transfer_requests(supplying_phc_id, status);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfer_requests(status);
CREATE INDEX IF NOT EXISTS idx_deliveries_phc_status ON delivery_requests(phc_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
