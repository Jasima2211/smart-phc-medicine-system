import os
import sqlite3
from werkzeug.security import generate_password_hash
from database import get_db, init_db
from prediction import calculate_stock_prediction, sync_inventory_alerts

def seed_database(custom_path=None):
    """
    Seed the database with rich, realistic fictional healthcare data.
    Designed for hackathon demonstrations:
      - 8 PHCs in a cohesive geographic district
      - 14 essential medicines
      - Coordinated shortage-to-surplus matching scenarios
      - Initial stock transactions, alerts, pending transfers, deliveries, and audit trails
      - Idempotent: can be run repeatedly without duplicating unique records
    """
    from flask import has_app_context
    from database import get_db_path

    is_standalone = False
    if not has_app_context() or (custom_path is not None and os.path.abspath(custom_path) != os.path.abspath(get_db_path())):
        conn = get_db(custom_path)
        is_standalone = True
        init_db(custom_path)
    else:
        conn = get_db()
        init_db()
    try:
        _run_seeding(conn)
        print("[OK] Smart PHC database seeded successfully with 8 PHCs, 14 Medicines, Inventory, Transfers, and Audit Logs.")
    finally:
        if is_standalone:
            conn.close()

def _run_seeding(conn):
    # 1. Seed PHCs (District Cluster around Lat 12.97, Lon 77.59)
    phcs_data = [
        ("Green Valley PHC", "Sector 4, Green Valley Sub-District", "+91 80 2345 6701", 12.9716, 77.5946, "approved"),
        ("Sunrise Lake PHC", "Lakeside Road, East Enclave", "+91 80 2345 6702", 12.9790, 77.6250, "approved"),
        ("Hillside Community Health Centre", "Hill Crest Avenue, North Ward", "+91 80 2345 6703", 13.0102, 77.5804, "approved"),
        ("Riverside Rural PHC", "River Bank Village, South Sector", "+91 80 2345 6704", 12.9352, 77.6101, "approved"),
        ("District Central PHC", "Civil Hospital Complex, Central Circle", "+91 80 2345 6705", 12.9810, 77.5980, "approved"),
        ("Pine Forest PHC", "Woodlands Road, Western Block", "+91 80 2345 6706", 12.9550, 77.5450, "approved"),
        ("Orchard Park PHC", "Old Orchard Market, South-East", "+91 80 2345 6707", 12.9220, 77.6410, "approved"),
        ("Highland Terrace PHC (New)", "Highland Cantonment Road", "+91 80 2345 6708", 13.0350, 77.6200, "pending"),
    ]

    for name, loc, phone, lat, lon, status in phcs_data:
        conn.execute(
            """
            INSERT INTO phcs (name, location, contact_phone, latitude, longitude, approval_status, active_status)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(name) DO UPDATE SET
                location=excluded.location,
                contact_phone=excluded.contact_phone,
                latitude=excluded.latitude,
                longitude=excluded.longitude,
                approval_status=excluded.approval_status
            """,
            (name, loc, phone, lat, lon, status)
        )
    conn.commit()

    # Map PHC names to IDs
    phc_map = {}
    for row in conn.execute("SELECT id, name FROM phcs").fetchall():
        phc_map[row["name"]] = row["id"]

    # 2. Seed Users
    # Secure hashes for demonstration accounts
    admin_pw = generate_password_hash("Admin@123")
    staff_pw = generate_password_hash("Staff@123")

    patient_pw = generate_password_hash("Patient@123")

    users_data = [
        ("admin", admin_pw, "admin", None, "District Medical Officer", None, None),
        ("green_valley_staff", staff_pw, "phc_staff", phc_map.get("Green Valley PHC"), "Pharmacist Green Valley", "+91 80 2345 6701", "Sector 4"),
        ("sunrise_staff", staff_pw, "phc_staff", phc_map.get("Sunrise Lake PHC"), "Pharmacist Sunrise Lake", "+91 80 2345 6702", "Lakeside Road"),
        ("hillside_staff", staff_pw, "phc_staff", phc_map.get("Hillside Community Health Centre"), "Pharmacist Hillside", "+91 80 2345 6703", "Hill Crest Ave"),
        ("riverside_staff", staff_pw, "phc_staff", phc_map.get("Riverside Rural PHC"), "Pharmacist Riverside", "+91 80 2345 6704", "River Bank Village"),
        ("central_staff", staff_pw, "phc_staff", phc_map.get("District Central PHC"), "Pharmacist Central", "+91 80 2345 6705", "Civil Hospital Complex"),
        ("pine_staff", staff_pw, "phc_staff", phc_map.get("Pine Forest PHC"), "Pharmacist Pine Forest", "+91 80 2345 6706", "Woodlands Road"),
        ("orchard_staff", staff_pw, "phc_staff", phc_map.get("Orchard Park PHC"), "Pharmacist Orchard Park", "+91 80 2345 6707", "Old Orchard Market"),
        ("patient_jane", patient_pw, "patient", None, "Jane Doe", "+91 98450 11223", "House 14B, Green Valley Cross Road"),
    ]

    for uname, pw_hash, role, phc_id, full_name, phone, addr in users_data:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, phc_id, full_name, contact_phone, delivery_address, active_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash,
                role=excluded.role,
                phc_id=excluded.phc_id,
                full_name=excluded.full_name,
                contact_phone=excluded.contact_phone,
                delivery_address=excluded.delivery_address
            """,
            (uname, pw_hash, role, phc_id, full_name, phone, addr)
        )
    conn.commit()

    # Map usernames to IDs
    user_map = {}
    for row in conn.execute("SELECT id, username FROM users").fetchall():
        user_map[row["username"]] = row["id"]

    # 3. Seed Medicines Catalogue
    medicines_data = [
        ("Amoxicillin 500mg", "Amoxicillin Trihydrate", "Antibiotics", "capsules", "500mg Oral Capsule", 1),
        ("Paracetamol 500mg", "Acetaminophen", "Analgesics & Antipyretics", "tablets", "500mg Oral Tablet", 0),
        ("Metformin 500mg", "Metformin Hydrochloride", "Antidiabetic", "tablets", "500mg Prolonged Release", 1),
        ("Oral Rehydration Salts (ORS)", "WHO Formula Electrolytes", "Gastrointestinal", "sachets", "20.5g Powder Sachet", 0),
        ("Azithromycin 250mg", "Azithromycin Dihydrate", "Antibiotics", "tablets", "250mg Film-Coated Tablet", 1),
        ("Amlodipine 5mg", "Amlodipine Besylate", "Cardiovascular", "tablets", "5mg Oral Tablet", 1),
        ("Ibuprofen 400mg", "Ibuprofen", "Anti-inflammatory", "tablets", "400mg Film-Coated Tablet", 0),
        ("Salbutamol Inhaler 100mcg", "Salbutamol Sulphate", "Respiratory", "inhalers", "100mcg/dose 200 Actuations", 1),
        ("Cetirizine 10mg", "Cetirizine Dihydrochloride", "Antihistamine", "tablets", "10mg Oral Tablet", 0),
        ("Omeprazole 20mg", "Omeprazole", "Gastrointestinal", "capsules", "20mg Gastro-resistant Capsule", 1),
        ("Ciprofloxacin 500mg", "Ciprofloxacin Hydrochloride", "Antibiotics", "tablets", "500mg Film-Coated Tablet", 1),
        ("Insulin Regular 100IU/ml", "Human Insulin (rDNA)", "Antidiabetic", "vials", "10ml Vial (100 IU/ml)", 1),
        ("Albendazole 400mg", "Albendazole", "Antiparasitic", "tablets", "400mg Chewable Tablet", 0),
        ("Artemether-Lumefantrine", "Artemether 20mg / Lumefantrine 120mg", "Antimalarial", "tablets", "Fixed-dose Combination Tablet", 1),
    ]

    for name, generic, cat, unit, dosage, rx in medicines_data:
        conn.execute(
            """
            INSERT INTO medicines (name, generic_name, category, unit, dosage_form, prescription_required, active_status)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(name) DO UPDATE SET
                generic_name=excluded.generic_name,
                category=excluded.category,
                unit=excluded.unit,
                dosage_form=excluded.dosage_form,
                prescription_required=excluded.prescription_required
            """,
            (name, generic, cat, unit, dosage, rx)
        )
    conn.commit()

    # Map medicine names to IDs
    med_map = {}
    for row in conn.execute("SELECT id, name FROM medicines").fetchall():
        med_map[row["name"]] = row["id"]

    # 4. Seed Inventory with Rich Scenarios
    # Scenario 1: Green Valley has critical shortage of Amoxicillin 500mg (18 units, 15 daily usage, lead time 7 days -> 1.2 days left)
    # Sunrise Lake has massive surplus of Amoxicillin (420 units, safety 60, daily 14 -> surplus 360 units, 4.8 km away)
    # Hillside has moderate surplus (180 units, safety 50, daily 10 -> surplus 130 units, 6.2 km away)
    inventory_items = [
        # Green Valley PHC
        ("Green Valley PHC", "Amoxicillin 500mg", 18, 50, 15.0, 7),     # CRITICAL: 1.2 days left
        ("Green Valley PHC", "Paracetamol 500mg", 35, 60, 20.0, 5),     # CRITICAL: 1.8 days left
        ("Green Valley PHC", "Metformin 500mg", 140, 50, 8.0, 7),       # SAFE: 17.5 days
        ("Green Valley PHC", "Oral Rehydration Salts (ORS)", 110, 40, 10.0, 4), # SAFE: 11 days
        ("Green Valley PHC", "Salbutamol Inhaler 100mcg", 6, 15, 2.5, 7),# CRITICAL: 2.4 days
        ("Green Valley PHC", "Amlodipine 5mg", 90, 40, 6.0, 7),         # SAFE: 15 days
        ("Green Valley PHC", "Cetirizine 10mg", 25, 30, 0.0, 5),        # MEDIUM: Below safety stock, zero usage rate
        ("Green Valley PHC", "Omeprazole 20mg", 180, 40, 9.0, 6),       # SAFE: 20 days

        # Sunrise Lake PHC (Surplus Partner)
        ("Sunrise Lake PHC", "Amoxicillin 500mg", 420, 60, 14.0, 7),   # SURPLUS: 360 units safe surplus!
        ("Sunrise Lake PHC", "Paracetamol 500mg", 550, 80, 25.0, 5),   # SURPLUS: 470 units
        ("Sunrise Lake PHC", "Metformin 500mg", 220, 50, 11.0, 7),     # SAFE
        ("Sunrise Lake PHC", "Salbutamol Inhaler 100mcg", 45, 12, 2.0, 6), # SURPLUS: 33 units
        ("Sunrise Lake PHC", "Azithromycin 250mg", 160, 40, 7.0, 7),   # SAFE
        ("Sunrise Lake PHC", "Ciprofloxacin 500mg", 210, 40, 8.0, 6),  # SAFE

        # Hillside Community Health Centre
        ("Hillside Community Health Centre", "Amoxicillin 500mg", 180, 50, 10.0, 7), # SURPLUS: 130 units
        ("Hillside Community Health Centre", "Paracetamol 500mg", 300, 70, 18.0, 5), # SURPLUS
        ("Hillside Community Health Centre", "Metformin 500mg", 45, 50, 9.0, 7),    # HIGH RISK: 5.0 days < lead 7
        ("Hillside Community Health Centre", "Insulin Regular 100IU/ml", 8, 20, 3.0, 10), # CRITICAL: 2.7 days
        ("Hillside Community Health Centre", "Oral Rehydration Salts (ORS)", 250, 50, 12.0, 5), # SAFE

        # Riverside Rural PHC
        ("Riverside Rural PHC", "Oral Rehydration Salts (ORS)", 12, 40, 8.0, 6), # CRITICAL: 1.5 days
        ("Riverside Rural PHC", "Amoxicillin 500mg", 90, 40, 6.0, 7),            # SAFE
        ("Riverside Rural PHC", "Albendazole 400mg", 150, 30, 4.0, 7),           # SAFE
        ("Riverside Rural PHC", "Paracetamol 500mg", 120, 50, 12.0, 5),          # SAFE

        # District Central PHC (Large Buffer Depot)
        ("District Central PHC", "Amoxicillin 500mg", 800, 100, 30.0, 5),       # SAFE/SURPLUS
        ("District Central PHC", "Paracetamol 500mg", 1200, 150, 45.0, 4),      # SAFE/SURPLUS
        ("District Central PHC", "Insulin Regular 100IU/ml", 60, 15, 2.5, 7),   # SURPLUS: 45 units
        ("District Central PHC", "Salbutamol Inhaler 100mcg", 95, 20, 4.0, 6),  # SURPLUS: 75 units
        ("District Central PHC", "Metformin 500mg", 450, 80, 18.0, 6),          # SAFE

        # Pine Forest PHC
        ("Pine Forest PHC", "Amlodipine 5mg", 15, 30, 4.5, 7),                  # CRITICAL: 3.3 days
        ("Pine Forest PHC", "Amoxicillin 500mg", 110, 40, 7.0, 7),              # SAFE
        ("Pine Forest PHC", "Ibuprofen 400mg", 190, 40, 8.0, 5),                # SAFE

        # Orchard Park PHC
        ("Orchard Park PHC", "Azithromycin 250mg", 10, 25, 4.0, 7),             # CRITICAL: 2.5 days
        ("Orchard Park PHC", "Oral Rehydration Salts (ORS)", 320, 50, 15.0, 5),  # SURPLUS
        ("Orchard Park PHC", "Cetirizine 10mg", 210, 30, 6.0, 5),               # SAFE
    ]

    for phc_name, med_name, usable, safety, daily, lead_time in inventory_items:
        p_id = phc_map.get(phc_name)
        m_id = med_map.get(med_name)
        if not p_id or not m_id:
            continue

        conn.execute(
            """
            INSERT INTO inventory (phc_id, medicine_id, usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(phc_id, medicine_id) DO UPDATE SET
                usable_quantity=excluded.usable_quantity,
                safety_stock=excluded.safety_stock,
                avg_daily_consumption=excluded.avg_daily_consumption,
                replenishment_lead_time_days=excluded.replenishment_lead_time_days,
                last_updated=CURRENT_TIMESTAMP
            """,
            (p_id, m_id, usable, safety, daily, lead_time)
        )

        # Synchronize prediction & alerts
        pred = calculate_stock_prediction(usable, safety, daily, lead_time)
        sync_inventory_alerts(conn, p_id, m_id, pred)

    conn.commit()

    # 5. Seed Stock Transactions (Historical Audit Trail)
    gv_id = phc_map.get("Green Valley PHC")
    sun_id = phc_map.get("Sunrise Lake PHC")
    amox_id = med_map.get("Amoxicillin 500mg")
    para_id = med_map.get("Paracetamol 500mg")
    u_admin = user_map.get("admin")
    u_gv = user_map.get("green_valley_staff")

    transactions = [
        (gv_id, amox_id, "received", 100, 0, 100, u_gv, None, "Quarterly batch intake from state central depot"),
        (gv_id, amox_id, "issued", 50, 100, 50, u_gv, None, "Dispensed to outpatient pediatric clinic"),
        (gv_id, amox_id, "issued", 32, 50, 18, u_gv, None, "High consumption spike during seasonal flu outbreak"),
        (gv_id, para_id, "received", 200, 0, 200, u_gv, None, "Initial district replenishment lot"),
        (gv_id, para_id, "issued", 165, 200, 35, u_gv, None, "Dispensed for viral fever triage patients"),
        (sun_id, amox_id, "received", 500, 0, 500, u_admin, None, "Direct district warehouse buffer allocation"),
        (sun_id, amox_id, "issued", 80, 500, 420, u_admin, None, "Local PHC dispensary dispensing"),
    ]

    for p_id, m_id, t_type, qty, prev_q, new_q, u_id, rel_tr, notes in transactions:
        # Check if identical record already seeded to avoid duplication
        exists = conn.execute(
            "SELECT id FROM stock_transactions WHERE phc_id = ? AND medicine_id = ? AND notes = ?",
            (p_id, m_id, notes)
        ).fetchone()
        if not exists:
            conn.execute(
                """
                INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, related_transfer_id, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (p_id, m_id, t_type, qty, prev_q, new_q, u_id, rel_tr, notes)
            )
    conn.commit()

    # 6. Seed Transfer Requests (Demonstration Workflow)
    # A pending emergency transfer request from Green Valley to Sunrise Lake for Amoxicillin 500mg
    existing_tr = conn.execute(
        "SELECT id FROM transfer_requests WHERE requesting_phc_id = ? AND supplying_phc_id = ? AND medicine_id = ?",
        (gv_id, sun_id, amox_id)
    ).fetchone()

    if not existing_tr:
        conn.execute(
            """
            INSERT INTO transfer_requests (
                requesting_phc_id, supplying_phc_id, medicine_id, requested_quantity, approved_quantity,
                reason, distance_km, status, admin_notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                gv_id, sun_id, amox_id, 100, 100,
                "Emergency Stock Shortage: Stock down to 18 units (1.2 days left) during pediatric flu surge.",
                4.8,
                "Recommended by distance-aware surplus matching algorithm. Sunrise Lake holds 360 surplus units."
            )
        )
    conn.commit()

    # 7. Seed Patient Delivery Requests
    delivery_samples = [
        ("TRK-GV-8910", gv_id, amox_id, 20, "Mary Johnson (Caregiver)", "+91 98450 11223", "House 14B, Green Valley Cross Road", "Pending", "Mother caring for 4-year-old child with acute otitis media; unable to travel."),
        ("TRK-GV-8911", gv_id, para_id, 15, "Robert Vance", "+91 98450 44556", "Flat 302, Lakeview Apartments", "Approved", "Elderly patient with mobility limitation."),
        ("TRK-SUN-7701", sun_id, med_map.get("Metformin 500mg"), 60, "Sunita Rao", "+91 98450 77889", "Door 8, Temple Street, East Enclave", "Delivered", "Chronic diabetic maintenance medicine, verified monthly prescription."),
        ("TRK-HC-4402", phc_map.get("Hillside Community Health Centre"), med_map.get("Insulin Regular 100IU/ml"), 2, "David Kumar", "+91 98450 99001", "Cottage 5, North Ridge Road", "Out for delivery", "Cold-chain insulin delivery dispatched via local community health worker."),
    ]

    for code, p_id, m_id, qty, patient, phone, addr, status, notes in delivery_samples:
        conn.execute(
            """
            INSERT INTO delivery_requests (tracking_code, phc_id, medicine_id, quantity, patient_name, contact_phone, delivery_address, status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tracking_code) DO UPDATE SET
                status=excluded.status,
                notes=excluded.notes
            """,
            (code, p_id, m_id, qty, patient, phone, addr, status, notes)
        )
    conn.commit()

    # 8. Seed Audit Logs
    audit_samples = [
        (u_admin, "admin", "admin", "SYSTEM_INIT", "database", 1, "Initialized Smart PHC system database and seed records", "127.0.0.1"),
        (u_gv, "green_valley_staff", "phc_staff", "STOCK_ISSUE", "inventory", gv_id, "Issued 32 units Amoxicillin 500mg due to pediatric clinic patient surge", "127.0.0.1"),
        (u_gv, "green_valley_staff", "phc_staff", "TRANSFER_REQUESTED", "transfer_requests", 1, "Submitted emergency transfer request for 100 units Amoxicillin 500mg to Sunrise Lake PHC", "127.0.0.1"),
    ]

    for u_id, uname, role, action, ent_type, ent_id, details, ip in audit_samples:
        conn.execute(
            """
            INSERT INTO audit_logs (user_id, username, role, action, entity_type, entity_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (u_id, uname, role, action, ent_type, ent_id, details, ip)
        )
    conn.commit()

    # 9. Seed Provider Stock Replenishment Requests
    sample_stock_requests = [
        (gv_id, para_id, 200, "Seasonal viral flu clinic surge replenishment request", "pending", None, None),
        (sun_id, med_map.get("Metformin 500mg"), 150, "Monthly chronic diabetes patient buffer stock replenishment", "approved", "Approved for monthly allocation", u_admin),
    ]

    for p_id, m_id, qty, rsn, stat, notes, rev_id in sample_stock_requests:
        exists = conn.execute(
            "SELECT id FROM provider_stock_requests WHERE phc_id = ? AND medicine_id = ? AND reason = ?",
            (p_id, m_id, rsn)
        ).fetchone()
        if not exists:
            conn.execute(
                """
                INSERT INTO provider_stock_requests (phc_id, medicine_id, requested_quantity, reason, status, admin_notes, reviewed_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (p_id, m_id, qty, rsn, stat, notes, rev_id)
            )
    conn.commit()

if __name__ == "__main__":
    seed_database()
