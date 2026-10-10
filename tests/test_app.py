import os
import tempfile
import pytest
from app import create_app
from database import init_db, get_db, close_db
from seed import seed_database
from prediction import calculate_stock_prediction, sync_inventory_alerts
from matching import find_surplus_matches, haversine_distance

@pytest.fixture
def app_instance():
    """Create test application configured with an isolated temporary SQLite database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)  # Crucial on Windows: Close OS handle immediately so SQLite has exclusive lock ownership

    app = create_app("testing")
    app.config["DATABASE_PATH"] = db_path
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Disabled in unit test client by default

    with app.app_context():
        init_db()
        seed_database()

    yield app

    # Teardown: Ensure any active appcontext / g.db connection is closed
    with app.app_context():
        close_db()

    # Explicit garbage collection to ensure SQLite driver releases file locks on Windows
    import gc
    gc.collect()

    if os.path.exists(db_path):
        os.unlink(db_path)

@pytest.fixture
def client(app_instance):
    return app_instance.test_client()

# -------------------------------------------------------------
# 1. Application & Database Initialization Tests
# -------------------------------------------------------------
def test_app_starts_successfully(client):
    """Test 1: Application starts and responds to HTTP requests."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"Smart PHC" in response.data

def test_database_tables_created(app_instance):
    """Test 2: Database schema initializes all 9 required tables and indexes."""
    with app_instance.app_context():
        db = get_db()
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        required_tables = [
            "phcs", "users", "medicines", "inventory",
            "stock_transactions", "alerts", "transfer_requests",
            "delivery_requests", "audit_logs"
        ]
        for tbl in required_tables:
            assert tbl in tables, f"Missing table {tbl}"

def test_seed_database_idempotency(app_instance):
    """Test 3: Seeding can run repeatedly without duplicating unique records."""
    with app_instance.app_context():
        # Run seeding second time
        seed_database()
        db = get_db()
        phc_count = db.execute("SELECT COUNT(*) FROM phcs").fetchone()[0]
        med_count = db.execute("SELECT COUNT(*) FROM medicines").fetchone()[0]
        assert phc_count == 8
        assert med_count == 14

# -------------------------------------------------------------
# 2. Public Search & Patient Portal Tests
# -------------------------------------------------------------
def test_public_medicine_search(client):
    """Test 4: Public medicine search works without authentication."""
    # Unfiltered
    res = client.get("/patient/search")
    assert res.status_code == 200
    assert b"Public Medicine Availability Search" in res.data

    # Query with keyword
    res_amox = client.get("/patient/search?q=Amoxicillin")
    assert res_amox.status_code == 200
    assert b"Amoxicillin" in res_amox.data

def test_patient_delivery_request_and_privacy(client, app_instance):
    """Test 22 & 23: Patient delivery requests validate inputs and mask private contact data."""
    # Submission
    res = client.post("/patient/delivery", data={
        "phc_id": 1,
        "medicine_id": 1,
        "quantity": 10,
        "patient_name": "Private Patient Jane",
        "contact_phone": "+91 99999 11111",
        "delivery_address": "Confidential Road 42",
        "notes": "Homebound"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Delivery request submitted successfully" in res.data
    assert b"TRK-" in res.data

    # Extract tracking code from database
    with app_instance.app_context():
        db = get_db()
        rec = db.execute("SELECT tracking_code FROM delivery_requests WHERE patient_name = 'Private Patient Jane'").fetchone()
        assert rec is not None
        code = rec["tracking_code"]

    # Public tracking endpoint
    track_res = client.get(f"/patient/track?code={code}")
    assert track_res.status_code == 200
    assert b"Pending" in track_res.data
    # Ensure patient phone and exact home address are NOT exposed publicly
    assert b"+91 99999 11111" not in track_res.data
    assert b"Confidential Road 42" not in track_res.data

# -------------------------------------------------------------
# 3. Authentication & Authorization Tests
# -------------------------------------------------------------
def test_login_and_logout(client):
    """Test 5: Login and logout flow works with proper role redirection."""
    # Login as admin
    login_res = client.post("/login", data={
        "username": "admin",
        "password": "Admin@123"
    }, follow_redirects=True)
    assert login_res.status_code == 200
    assert b"District Health Command Centre" in login_res.data

    # Logout
    logout_res = client.get("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"signed out successfully" in logout_res.data

def test_invalid_credentials_rejected(client):
    """Test 6: Invalid credentials are safely rejected."""
    res = client.post("/login", data={
        "username": "admin",
        "password": "WrongPassword999"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Invalid username or password" in res.data

def test_unauthenticated_access_denied(client):
    """Test 7: Unauthenticated users cannot access staff or admin dashboards."""
    res_phc = client.get("/phc/dashboard", follow_redirects=False)
    assert res_phc.status_code in (302, 401)

    res_admin = client.get("/admin/dashboard", follow_redirects=False)
    assert res_admin.status_code in (302, 401)

def test_admin_routes_reject_ordinary_staff(client):
    """Test 9: Admin-only routes reject staff accounts with 403 Forbidden."""
    # Login as staff
    client.post("/login", data={
        "username": "green_valley_staff",
        "password": "Staff@123"
    }, follow_redirects=True)

    # Attempt admin access
    res = client.get("/admin/dashboard")
    assert res.status_code == 403

def test_phc_staff_isolation(client, app_instance):
    """Test 8: PHC staff cannot modify another PHC's inventory or transfers."""
    # Login as Green Valley staff (PHC id 1)
    client.post("/login", data={
        "username": "green_valley_staff",
        "password": "Staff@123"
    }, follow_redirects=True)

    # Try to issue stock from another PHC's inventory (Sunrise Lake PHC)
    with app_instance.app_context():
        db = get_db()
        sun_phc = db.execute("SELECT id FROM phcs WHERE name = 'Sunrise Lake PHC'").fetchone()
        sun_inv = db.execute("SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = 1", (sun_phc["id"],)).fetchone()
        initial_sun_stock = sun_inv["usable_quantity"]

    # When staff issues stock, app forces user's assigned session phc_id
    client.post("/phc/stock/issue", data={
        "medicine_id": 1,
        "quantity": 5,
        "notes": "Attempt unauthorized cross-PHC issue"
    }, follow_redirects=True)

    # Verify Sunrise Lake stock was untouched
    with app_instance.app_context():
        db = get_db()
        sun_inv_after = db.execute("SELECT usable_quantity FROM inventory WHERE id = ?", (sun_inv["id"],)).fetchone()
        assert sun_inv_after["usable_quantity"] == initial_sun_stock

# -------------------------------------------------------------
# 4. Stock Prediction & Forecasting Engine Tests
# -------------------------------------------------------------
def test_prediction_days_remaining_zero_consumption():
    """Test 12: Zero consumption safely handled without division by zero."""
    pred = calculate_stock_prediction(usable_stock=100, safety_stock=50, avg_daily_consumption=0.0, lead_time_days=7)
    assert pred["days_remaining"] is None
    assert pred["days_remaining_display"] == "Insufficient consumption data"
    assert pred["predicted_stockout_date"] is None

def test_prediction_missing_consumption_not_fabricated():
    """Test 13: Missing or negative consumption does not fabricate stock-out date."""
    pred = calculate_stock_prediction(usable_stock=80, safety_stock=40, avg_daily_consumption=-5.0, lead_time_days=7)
    assert pred["days_remaining"] is None
    assert "Insufficient consumption data" in pred["days_remaining_display"]

def test_prediction_risk_classification():
    """Test 14: Risk classification considers consumption rate and replenishment lead time."""
    # Depleted completely -> Critical
    p_zero = calculate_stock_prediction(usable_stock=0, safety_stock=50, avg_daily_consumption=10.0, lead_time_days=7)
    assert p_zero["risk_level"] == "Critical"

    # Depletes in 2.0 days, lead time is 7 days -> Critical (breaches lead time!)
    p_crit = calculate_stock_prediction(usable_stock=20, safety_stock=50, avg_daily_consumption=10.0, lead_time_days=7)
    assert p_crit["risk_level"] == "Critical"
    assert p_crit["days_remaining"] == 2.0

    # Depletes in 9.0 days, lead time is 7 days (9.0 <= 7 * 1.5 = 10.5) -> High
    p_high = calculate_stock_prediction(usable_stock=90, safety_stock=50, avg_daily_consumption=10.0, lead_time_days=7)
    assert p_high["risk_level"] == "High"

    # Depletes in 40 days -> Safe
    p_safe = calculate_stock_prediction(usable_stock=400, safety_stock=50, avg_daily_consumption=10.0, lead_time_days=7)
    assert p_safe["risk_level"] == "Safe"

def test_duplicate_open_alerts_prevented(app_instance):
    """Test 15: Recalculating stock updates existing open alert without creating duplicates."""
    with app_instance.app_context():
        db = get_db()
        p_id = 1
        m_id = 1
        # Calculate critical prediction
        pred_crit = calculate_stock_prediction(10, 50, 10.0, 7)
        sync_inventory_alerts(db, p_id, m_id, pred_crit)
        db.commit()

        # Count open alerts
        c1 = db.execute("SELECT COUNT(*) FROM alerts WHERE phc_id = ? AND medicine_id = ? AND status = 'open'", (p_id, m_id)).fetchone()[0]
        assert c1 == 1

        # Recalculate again with updated values
        pred_crit2 = calculate_stock_prediction(12, 50, 10.0, 7)
        sync_inventory_alerts(db, p_id, m_id, pred_crit2)
        db.commit()

        c2 = db.execute("SELECT COUNT(*) FROM alerts WHERE phc_id = ? AND medicine_id = ? AND status = 'open'", (p_id, m_id)).fetchone()[0]
        assert c2 == 1, "Duplicate open alert was created!"

# -------------------------------------------------------------
# 5. Inventory Operations & Ledger Tests
# -------------------------------------------------------------
def test_stock_receipt_updates_inventory_and_transactions(client, app_instance):
    """Test 10: Receiving stock increases usable quantity and logs transaction ledger."""
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)

    with app_instance.app_context():
        db = get_db()
        inv = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 1").fetchone()
        initial_stock = inv["usable_quantity"]

    res = client.post("/phc/stock/receive", data={
        "medicine_id": 1,
        "quantity": 50,
        "notes": "State warehouse arrival"
    }, follow_redirects=True)
    assert res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        inv_after = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 1").fetchone()
        assert inv_after["usable_quantity"] == initial_stock + 50

        tx = db.execute(
            "SELECT * FROM stock_transactions WHERE phc_id = 1 AND medicine_id = 1 AND transaction_type = 'received' ORDER BY id DESC"
        ).fetchone()
        assert tx is not None
        assert tx["quantity"] == 50

def test_stock_issuance_cannot_produce_negative_inventory(client, app_instance):
    """Test 11: Dispensing more stock than available is prevented."""
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)

    with app_instance.app_context():
        db = get_db()
        inv = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 1").fetchone()
        curr_stock = inv["usable_quantity"]

    # Try to issue curr_stock + 100 units
    res = client.post("/phc/stock/issue", data={
        "medicine_id": 1,
        "quantity": curr_stock + 100,
        "notes": "Excess dispensing attempt"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"exceeds current usable stock" in res.data

    with app_instance.app_context():
        db = get_db()
        inv_after = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 1").fetchone()
        assert inv_after["usable_quantity"] == curr_stock

# -------------------------------------------------------------
# 6. Surplus Matching & Transfer Governance Tests
# -------------------------------------------------------------
def test_surplus_matching_rules(app_instance):
    """Test 16 & 17: Surplus matching excludes requesting PHC and preserves supplier safety stock."""
    with app_instance.app_context():
        db = get_db()
        req_phc_id = 1  # Green Valley PHC
        med_id = 1      # Amoxicillin 500mg

        matches = find_surplus_matches(db, req_phc_id, med_id, requested_qty=100)
        assert len(matches) > 0

        for match in matches:
            # Must not be the requesting PHC
            assert match["phc_id"] != req_phc_id
            # Must have positive surplus above safety reserve
            assert match["surplus_available"] > 0
            # Recommended transfer must not exceed surplus
            assert match["recommended_transfer_qty"] <= match["surplus_available"]
            # Remaining stock after transfer must be >= safety stock
            assert match["remaining_stock_after"] >= match["safety_stock"]

def test_transfer_lifecycle_dispatch_and_receipt(client, app_instance):
    """Test 18, 19, 20 & 21: Full transfer lifecycle from request, admin approval, dispatch, to atomic receipt confirmation."""
    with app_instance.app_context():
        db = get_db()
        gv_id = 1   # Green Valley (Requester)
        sun_id = 2  # Sunrise Lake (Supplier)
        med_id = 1  # Amoxicillin

        gv_initial = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = ? AND medicine_id = ?", (gv_id, med_id)).fetchone()["usable_quantity"]
        sun_initial = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = ? AND medicine_id = ?", (sun_id, med_id)).fetchone()["usable_quantity"]

    # 1. Requester submits transfer
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    client.post("/phc/transfers/request", data={
        "supplying_phc_id": sun_id,
        "medicine_id": med_id,
        "requested_quantity": 50,
        "distance_km": 4.8,
        "reason": "Outpatient clinic shortage"
    }, follow_redirects=True)

    with app_instance.app_context():
        db = get_db()
        tr = db.execute("SELECT id FROM transfer_requests WHERE requesting_phc_id = ? AND status = 'pending' ORDER BY id DESC", (gv_id,)).fetchone()
        tr_id = tr["id"]

    # 2. Admin approves transfer
    client.get("/logout")
    client.post("/login", data={"username": "admin", "password": "Admin@123"}, follow_redirects=True)
    app_res = client.post(f"/admin/transfers/approve/{tr_id}", data={
        "approved_quantity": 50,
        "admin_notes": "Emergency match approved"
    }, follow_redirects=True)
    assert app_res.status_code == 200

    # 3. Supplying PHC staff dispatches stock
    client.get("/logout")
    client.post("/login", data={"username": "sunrise_staff", "password": "Staff@123"}, follow_redirects=True)
    disp_res = client.post(f"/phc/transfers/dispatch/{tr_id}", follow_redirects=True)
    assert disp_res.status_code == 200

    # Verify supplier stock was deducted immediately upon dispatch
    with app_instance.app_context():
        db = get_db()
        sun_after = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = ? AND medicine_id = ?", (sun_id, med_id)).fetchone()["usable_quantity"]
        assert sun_after == sun_initial - 50

    # 4. Receiving PHC confirms physical receipt
    client.get("/logout")
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    rec_res = client.post(f"/phc/transfers/receive/{tr_id}", follow_redirects=True)
    assert rec_res.status_code == 200

    # Verify receiver stock increased
    with app_instance.app_context():
        db = get_db()
        gv_after = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = ? AND medicine_id = ?", (gv_id, med_id)).fetchone()["usable_quantity"]
        assert gv_after == gv_initial + 50

        # Check transfer status is 'received'
        tr_final = db.execute("SELECT status FROM transfer_requests WHERE id = ?", (tr_id,)).fetchone()
        assert tr_final["status"] == "received"

    # 5. Duplicate receipt confirmation is blocked (Test 20)
    dup_res = client.post(f"/phc/transfers/receive/{tr_id}", follow_redirects=True)
    assert b"status to confirm receipt" in dup_res.data
    with app_instance.app_context():
        db = get_db()
        gv_check = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = ? AND medicine_id = ?", (gv_id, med_id)).fetchone()["usable_quantity"]
        assert gv_check == gv_after, "Stock was erroneously added twice on duplicate submission!"

def test_audit_logging_recorded(client, app_instance):
    """Test 24: Important actions write audit logs."""
    client.post("/login", data={"username": "admin", "password": "Admin@123"}, follow_redirects=True)
    with app_instance.app_context():
        db = get_db()
        log = db.execute("SELECT * FROM audit_logs WHERE action = 'USER_LOGIN' AND username = 'admin' ORDER BY id DESC").fetchone()
        assert log is not None
        assert "Successful authentication" in log["details"]

def test_all_main_views_render_successfully(client):
    """Test 25, 26, 27: All views, navigation links, and templates render without errors."""
    # Public views
    for path in ["/", "/patient/search", "/patient/delivery", "/patient/track", "/login"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed GET {path}"

    # Staff views
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    for path in ["/phc/dashboard", "/phc/inventory", "/phc/alerts", "/phc/transfers", "/phc/transfers/recommendations/1", "/phc/deliveries"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed GET {path}"

    # Admin views
    client.get("/logout")
    client.post("/login", data={"username": "admin", "password": "Admin@123"}, follow_redirects=True)
    for path in ["/admin/dashboard", "/admin/phcs", "/admin/stock-monitor", "/admin/transfers", "/admin/reports", "/admin/audit-logs"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed GET {path}"

def test_csrf_protection_enabled(app_instance):
    """Test 28: CSRF protection blocks requests without valid token when enabled."""
    app_instance.config["WTF_CSRF_ENABLED"] = True
    c = app_instance.test_client()
    # POST without CSRF token must fail with 400
    res = c.post("/login", data={"username": "admin", "password": "Admin@123"})
    assert res.status_code == 400

# -------------------------------------------------------------
# 7. Comprehensive Specific Workflow Tests (TEST 1 - TEST 12)
# -------------------------------------------------------------
def test_scenario_1_minimal_landing_page(client):
    """TEST 1: Landing page displays only Smart PHC and the three login options."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Smart PHC" in html
    assert "Patient Login" in html
    assert "District Administrator Login" in html
    assert "Medical Pharmacist Login" in html
    assert "Never let a rural clinic run out" not in html
    assert "Judges Demonstration Guide" not in html

def test_scenario_2_provider_registration_pending_status(client, app_instance):
    """TEST 2: Register a new provider starts as pending and cannot appear in search."""
    res = client.post("/provider/register", data={
        "name": "New Hope Health Centre",
        "location": "North Sub-district",
        "contact_phone": "+91 80 9988 7766",
        "username": "new_hope_staff",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)
    assert res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE name = 'New Hope Health Centre'").fetchone()
        assert phc is not None
        assert phc["approval_status"] == "pending"
        assert phc["active_status"] == 0

    search_res = client.get("/patient/search")
    assert b"New Hope Health Centre" not in search_res.data

def test_scenario_3_admin_approves_provider(client, app_instance):
    """TEST 3: District Administrator views pending provider and approves it."""
    client.post("/provider/register", data={
        "name": "Hill Crest Rural Centre",
        "location": "Ridge Road",
        "contact_phone": "+91 80 5544 3322",
        "username": "hill_crest_staff",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)

    with app_instance.app_context():
        db = get_db()
        phc = db.execute("SELECT id FROM phcs WHERE name = 'Hill Crest Rural Centre'").fetchone()
        phc_id = phc["id"]

    client.post("/login", data={"username": "admin", "password": "Admin@123"}, follow_redirects=True)
    app_res = client.post(f"/admin/phcs/approve/{phc_id}", follow_redirects=True)
    assert app_res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        phc_after = db.execute("SELECT approval_status, active_status FROM phcs WHERE id = ?", (phc_id,)).fetchone()
        assert phc_after["approval_status"] == "approved"
        assert phc_after["active_status"] == 1

def test_scenario_4_pharmacist_inventory_update(client, app_instance):
    """TEST 4: Pharmacist views and updates their own inventory; persists after refresh."""
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    
    with app_instance.app_context():
        db = get_db()
        inv = db.execute("SELECT id FROM inventory WHERE phc_id = 1 AND medicine_id = 1").fetchone()
        inv_id = inv["id"]

    up_res = client.post(f"/phc/inventory/update-levels/{inv_id}", data={
        "usable_quantity": 250,
        "safety_stock": 60,
        "avg_daily_consumption": 12.0,
        "replenishment_lead_time_days": 7
    }, follow_redirects=True)
    assert up_res.status_code == 200

    view_res = client.get("/phc/inventory")
    assert view_res.status_code == 200
    assert b"250" in view_res.data

    with app_instance.app_context():
        db = get_db()
        inv_after = db.execute("SELECT usable_quantity, safety_stock FROM inventory WHERE id = ?", (inv_id,)).fetchone()
        assert inv_after["usable_quantity"] == 250
        assert inv_after["safety_stock"] == 60

def test_scenario_5_patient_medicine_search(client):
    """TEST 5: Patient searches medicine and views actual availability."""
    client.post("/patient/register", data={
        "full_name": "Alice Patient",
        "contact_phone": "+91 98888 77777",
        "delivery_address": "Green Avenue 12",
        "username": "alice_p",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)

    res = client.get("/patient/search?q=Paracetamol")
    assert res.status_code == 200
    assert b"Paracetamol 500mg" in res.data
    assert b"In Stock" in res.data

def test_scenario_6_7_8_delivery_order_workflow_and_stock_consistency(client, app_instance):
    """TEST 6, 7 & 8: Patient orders delivery, pharmacist accepts/rejects, stock reserved and released safely."""
    with app_instance.app_context():
        db = get_db()
        inv = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 2").fetchone()
        initial_stock = inv["usable_quantity"]

    order_res = client.post("/patient/delivery", data={
        "phc_id": 1,
        "medicine_id": 2,
        "quantity": 10,
        "patient_name": "Bob Patient",
        "contact_phone": "+91 97777 66666",
        "delivery_address": "North Sector 5",
        "notes": "Homebound"
    }, follow_redirects=True)
    assert order_res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        inv_reserved = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 2").fetchone()
        assert inv_reserved["usable_quantity"] == initial_stock - 10
        order = db.execute("SELECT id, tracking_code FROM delivery_requests WHERE patient_name = 'Bob Patient' ORDER BY id DESC").fetchone()
        order_id = order["id"]
        tracking_code = order["tracking_code"]

    client.get("/logout")
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    accept_res = client.post(f"/phc/deliveries/accept/{order_id}", follow_redirects=True)
    assert accept_res.status_code == 200

    track_res = client.get(f"/patient/track?code={tracking_code}")
    assert b"Accepted" in track_res.data

    reject_res = client.post(f"/phc/deliveries/reject/{order_id}", data={"notes": "Out of delivery area"}, follow_redirects=True)
    assert reject_res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        inv_restored = db.execute("SELECT usable_quantity FROM inventory WHERE phc_id = 1 AND medicine_id = 2").fetchone()
        assert inv_restored["usable_quantity"] == initial_stock

    track_res2 = client.get(f"/patient/track?code={tracking_code}")
    assert b"Rejected" in track_res2.data

def test_scenario_9_provider_replenishment_request(client, app_instance):
    """TEST 9: Provider submits replenishment request, admin approves it, provider views status."""
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    sub_res = client.post("/phc/replenishment/submit", data={
        "medicine_id": 1,
        "requested_quantity": 200,
        "reason": "Seasonal surge replenishment"
    }, follow_redirects=True)
    assert sub_res.status_code == 200

    with app_instance.app_context():
        db = get_db()
        req = db.execute("SELECT id, status FROM provider_stock_requests WHERE phc_id = 1 AND requested_quantity = 200 ORDER BY id DESC").fetchone()
        req_id = req["id"]
        assert req["status"] == "pending"

    client.get("/logout")
    client.post("/login", data={"username": "admin", "password": "Admin@123"}, follow_redirects=True)
    admin_view = client.get("/admin/provider-requests")
    assert admin_view.status_code == 200
    assert b"Seasonal surge replenishment" in admin_view.data

    app_res = client.post(f"/admin/provider-requests/approve/{req_id}", data={"admin_notes": "Approved central lot"}, follow_redirects=True)
    assert app_res.status_code == 200

    client.get("/logout")
    client.post("/login", data={"username": "green_valley_staff", "password": "Staff@123"}, follow_redirects=True)
    phc_req_view = client.get("/phc/replenishment")
    assert phc_req_view.status_code == 200
    assert b"Approved" in phc_req_view.data

def test_scenario_10_pharmacist_cannot_access_other_phc_data(client, app_instance):
    """TEST 10: Pharmacist cannot alter another PHC's orders."""
    client.post("/login", data={"username": "sunrise_staff", "password": "Staff@123"}, follow_redirects=True)

    with app_instance.app_context():
        db = get_db()
        gv_order = db.execute("SELECT id FROM delivery_requests WHERE phc_id = 1").fetchone()
        gv_order_id = gv_order["id"]

    res = client.post(f"/phc/deliveries/reject/{gv_order_id}", follow_redirects=True)
    assert b"Delivery request not found" in res.data or res.status_code in (403, 302)

def test_scenario_11_patient_cannot_access_admin_or_pharmacist_routes(client):
    """TEST 11: Patient account cannot access administrator or pharmacist dashboards."""
    client.post("/patient/register", data={
        "full_name": "Charlie Patient",
        "contact_phone": "+91 91111 22222",
        "delivery_address": "Test Street 1",
        "username": "charlie_p",
        "password": "Password@123",
        "confirm_password": "Password@123"
    }, follow_redirects=True)

    res_phc = client.get("/phc/dashboard")
    assert res_phc.status_code == 403

    res_admin = client.get("/admin/dashboard")
    assert res_admin.status_code == 403


