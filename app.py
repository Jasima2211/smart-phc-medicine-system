import os
import csv
import io
import secrets
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g, abort, make_response, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import config_by_name
from database import get_db, close_db, init_db, query_db, execute_db
from prediction import calculate_stock_prediction, sync_inventory_alerts
from matching import find_surplus_matches

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))

    # Register database teardown
    app.teardown_appcontext(close_db)

    # ---------------------------------------------------------
    # CSRF Protection via Session Token & Template Filters
    # ---------------------------------------------------------
    @app.template_filter("format_dt")
    def format_dt_filter(value):
        if value is None:
            return "—"
        if isinstance(value, str):
            return value[:16]
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%d %H:%M")
        return str(value)[:16]

    def generate_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(24)
        return session["csrf_token"]

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf_token)

    @app.before_request
    def check_csrf():
        if not app.config.get("WTF_CSRF_ENABLED", True):
            return
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            session_token = session.get("csrf_token")
            if not token or not session_token or token != session_token:
                return abort(400, description="Invalid or missing CSRF token.")

    # ---------------------------------------------------------
    # Audit Logging Helper
    # ---------------------------------------------------------
    def log_audit(action, entity_type, entity_id=None, details=""):
        user_id = session.get("user_id")
        username = session.get("username", "anonymous")
        role = session.get("role", "public")
        ip = request.remote_addr or "127.0.0.1"
        try:
            db = get_db()
            db.execute(
                """
                INSERT INTO audit_logs (user_id, username, role, action, entity_type, entity_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, role, action, entity_type, entity_id, details, ip)
            )
            db.commit()
        except Exception:
            pass

    # ---------------------------------------------------------
    # Authorization Decorators
    # ---------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please sign in to access healthcare operations.", "warning")
                return redirect(url_for("login", next=request.url))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Administrator sign-in required.", "warning")
                return redirect(url_for("admin_login"))
            if session.get("role") != "admin":
                flash("Access denied: Administrative privileges required.", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function

    def phc_staff_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Medical Pharmacist sign-in required.", "warning")
                return redirect(url_for("pharmacist_login"))
            if session.get("role") != "phc_staff":
                flash("Access denied: Pharmacist privileges required.", "danger")
                return abort(403)
            phc_id = session.get("phc_id")
            if not phc_id:
                flash("Account not linked to an authorized Primary Health Centre.", "danger")
                return abort(403)
            # Verify PHC is approved and active in database
            db = get_db()
            phc = db.execute("SELECT approval_status, active_status FROM phcs WHERE id = ?", (phc_id,)).fetchone()
            if not phc or phc["approval_status"] != "approved" or phc["active_status"] != 1:
                flash("Primary Health Centre is not approved or inactive.", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function

    def patient_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Patient sign-in required.", "warning")
                return redirect(url_for("patient_login", next=request.url))
            if session.get("role") != "patient":
                flash("Access denied: Patient account required.", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function

    # ---------------------------------------------------------
    # Landing & Public Routes
    # ---------------------------------------------------------
    @app.route("/")
    def landing():
        """Public minimal landing page containing only Smart PHC and the three login options."""
        return render_template("landing.html", active_page="landing")

    # ---------------------------------------------------------
    # Authentication & Registration Routes
    # ---------------------------------------------------------
    @app.route("/login/patient")
    @app.route("/patient/login")
    def patient_login():
        """Dedicated Patient Login portal."""
        if "user_id" in session and session.get("role") == "patient":
            return redirect(url_for("patient_search"))
        return render_template("login.html", role="patient", active_page="login")

    @app.route("/login/admin")
    @app.route("/admin/login")
    def admin_login():
        """Dedicated District Administrator Login portal."""
        if "user_id" in session and session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return render_template("login.html", role="admin", active_page="login")

    @app.route("/login/pharmacist")
    @app.route("/pharmacist/login")
    def pharmacist_login():
        """Dedicated Medical Pharmacist Login portal."""
        if "user_id" in session and session.get("role") == "phc_staff":
            return redirect(url_for("phc_dashboard"))
        return render_template("login.html", role="phc_staff", active_page="login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User sign in for administrators, pharmacists, and patients."""
        if request.method == "GET":
            if "user_id" in session:
                role = session.get("role")
                if role == "admin":
                    return redirect(url_for("admin_dashboard"))
                elif role == "phc_staff":
                    return redirect(url_for("phc_dashboard"))
                elif role == "patient":
                    return redirect(url_for("patient_search"))
            role_hint = request.args.get("role", "")
            return render_template("login.html", role=role_hint, active_page="login")

        # POST
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? AND active_status = 1", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # Check PHC approval if staff
            if user["role"] == "phc_staff":
                if not user["phc_id"]:
                    flash("Pharmacist account is not linked to any Primary Health Centre.", "danger")
                    return redirect(url_for("pharmacist_login"))
                phc = db.execute("SELECT * FROM phcs WHERE id = ?", (user["phc_id"],)).fetchone()
                if not phc:
                    flash("Associated Primary Health Centre not found.", "danger")
                    return redirect(url_for("pharmacist_login"))
                if phc["approval_status"] == "pending":
                    flash("Your Primary Health Centre registration is pending approval by the District Administrator.", "warning")
                    return redirect(url_for("pharmacist_login"))
                if phc["approval_status"] == "rejected":
                    flash("Your Primary Health Centre registration has been rejected by the District Administrator.", "danger")
                    return redirect(url_for("pharmacist_login"))
                if phc["approval_status"] == "suspended" or phc["active_status"] == 0:
                    flash("Your Primary Health Centre has been suspended.", "danger")
                    return redirect(url_for("pharmacist_login"))

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["phc_id"] = user["phc_id"]

            user_dict = dict(user)
            if user_dict.get("full_name"):
                session["full_name"] = user_dict["full_name"]
            if user_dict.get("contact_phone"):
                session["contact_phone"] = user_dict["contact_phone"]
            if user_dict.get("delivery_address"):
                session["delivery_address"] = user_dict["delivery_address"]

            if user["phc_id"]:
                phc = db.execute("SELECT name FROM phcs WHERE id = ?", (user["phc_id"],)).fetchone()
                session["phc_name"] = phc["name"] if phc else "Assigned PHC"

            # Update last login timestamp
            db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
            db.commit()

            log_audit("USER_LOGIN", "users", user["id"], f"Successful authentication for {username}")
            flash(f"Welcome back, {user['username']}!", "success")

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "phc_staff":
                return redirect(url_for("phc_dashboard"))
            else:
                return redirect(url_for("patient_search"))
        else:
            flash("Invalid username or password credentials.", "danger")

        return render_template("login.html", active_page="login")

    @app.route("/patient/register", methods=["GET", "POST"])
    def patient_register():
        """Patient registration portal."""
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            contact_phone = request.form.get("contact_phone", "").strip()
            delivery_address = request.form.get("delivery_address", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not (full_name and contact_phone and delivery_address and username and password):
                flash("Please fill in all required registration fields.", "danger")
                return render_template("patient_register.html", active_page="patient_register")

            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("patient_register.html", active_page="patient_register")

            if len(password) < 6:
                flash("Password must be at least 6 characters.", "danger")
                return render_template("patient_register.html", active_page="patient_register")

            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Username is already taken. Please select another.", "danger")
                return render_template("patient_register.html", active_page="patient_register")

            pw_hash = generate_password_hash(password)
            cur = db.execute(
                """
                INSERT INTO users (username, password_hash, role, phc_id, full_name, contact_phone, delivery_address, active_status)
                VALUES (?, ?, 'patient', NULL, ?, ?, ?, 1)
                """,
                (username, pw_hash, full_name, contact_phone, delivery_address)
            )
            user_id = cur.lastrowid
            db.commit()

            # Auto-login after successful registration
            session.clear()
            session["user_id"] = user_id
            session["username"] = username
            session["role"] = "patient"
            session["full_name"] = full_name
            session["contact_phone"] = contact_phone
            session["delivery_address"] = delivery_address

            log_audit("PATIENT_REGISTERED", "users", user_id, f"Patient {username} registered successfully.")
            flash(f"Welcome, {full_name}! Your patient account has been created.", "success")
            return redirect(url_for("patient_search"))

        return render_template("patient_register.html", active_page="patient_register")

    @app.route("/provider/register", methods=["GET", "POST"])
    def provider_register():
        """Primary Health Centre and Pharmacist provider registration."""
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            location = request.form.get("location", "").strip()
            contact_phone = request.form.get("contact_phone", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not (name and location and contact_phone and username and password):
                flash("Please fill in all required registration fields.", "danger")
                return render_template("provider_register.html", active_page="provider_register")

            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("provider_register.html", active_page="provider_register")

            db = get_db()
            existing_phc = db.execute("SELECT id FROM phcs WHERE name = ?", (name,)).fetchone()
            if existing_phc:
                flash("A Primary Health Centre with this name is already registered.", "danger")
                return render_template("provider_register.html", active_page="provider_register")

            existing_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing_user:
                flash("Pharmacist username is already taken.", "danger")
                return render_template("provider_register.html", active_page="provider_register")

            # Create PHC with pending status and inactive until approved
            cur_phc = db.execute(
                """
                INSERT INTO phcs (name, location, contact_phone, approval_status, active_status)
                VALUES (?, ?, ?, 'pending', 0)
                """,
                (name, location, contact_phone)
            )
            phc_id = cur_phc.lastrowid

            pw_hash = generate_password_hash(password)
            cur_user = db.execute(
                """
                INSERT INTO users (username, password_hash, role, phc_id, full_name, contact_phone, active_status)
                VALUES (?, ?, 'phc_staff', ?, ?, ?, 1)
                """,
                (username, pw_hash, phc_id, f"Pharmacist {name}", contact_phone)
            )
            user_id = cur_user.lastrowid
            db.commit()

            log_audit("PROVIDER_REGISTERED", "phcs", phc_id, f"PHC {name} registered (pending approval). Staff: {username}")
            flash("Registration submitted successfully. Your Primary Health Centre is pending approval by the District Administrator.", "info")
            return redirect(url_for("pharmacist_login"))

        return render_template("provider_register.html", active_page="provider_register")

    @app.route("/logout")
    def logout():
        """Sign out active session."""
        username = session.get("username")
        if username:
            log_audit("USER_LOGOUT", "users", session.get("user_id"), f"Sign-out for {username}")
        session.clear()
        flash("You have been signed out successfully.", "info")
        return redirect(url_for("landing"))

    # ---------------------------------------------------------
    # View A: Patient Portal Routes
    # ---------------------------------------------------------
    @app.route("/patient/search")
    def patient_search():
        """Public medicine availability lookup with live database records."""
        q = request.args.get("q", "").strip()
        phc_id = request.args.get("phc_id", type=int)

        db = get_db()
        all_phcs = db.execute(
            "SELECT id, name, location FROM phcs WHERE approval_status = 'approved' AND active_status = 1 ORDER BY name"
        ).fetchall()

        query = """
            SELECT 
                i.id AS inventory_id,
                i.usable_quantity,
                i.safety_stock,
                i.last_updated,
                m.id AS medicine_id,
                m.name AS medicine_name,
                m.generic_name,
                m.category,
                m.unit,
                m.dosage_form,
                m.prescription_required,
                p.id AS phc_id,
                p.name AS phc_name,
                p.location AS phc_location,
                p.contact_phone
            FROM inventory i
            JOIN medicines m ON m.id = i.medicine_id
            JOIN phcs p ON p.id = i.phc_id
            WHERE p.approval_status = 'approved' AND p.active_status = 1 AND m.active_status = 1
        """
        params = []

        if q:
            query += " AND (m.name LIKE ? OR m.generic_name LIKE ? OR m.category LIKE ? OR p.name LIKE ? OR p.location LIKE ?)"
            term = f"%{q}%"
            params.extend([term, term, term, term, term])

        if phc_id:
            query += " AND p.id = ?"
            params.append(phc_id)

        query += " ORDER BY m.name ASC, i.usable_quantity DESC"
        results = db.execute(query, params).fetchall()

        return render_template(
            "patient.html",
            results=results,
            all_phcs=all_phcs,
            query=q,
            selected_phc_id=phc_id,
            active_page="patient_search"
        )

    @app.route("/patient/delivery", methods=["GET", "POST"])
    def patient_delivery():
        """Patient medicine delivery request submission with safe stock reservation."""
        db = get_db()
        if request.method == "POST":
            phc_id = request.form.get("phc_id", type=int)
            medicine_id = request.form.get("medicine_id", type=int)
            quantity = request.form.get("quantity", type=int)
            patient_name = request.form.get("patient_name", "").strip()
            contact_phone = request.form.get("contact_phone", "").strip()
            delivery_address = request.form.get("delivery_address", "").strip()
            notes = request.form.get("notes", "").strip()

            if not (phc_id and medicine_id and quantity and quantity > 0 and patient_name and contact_phone and delivery_address):
                flash("Please fill in all required delivery fields.", "danger")
                return redirect(url_for("patient_delivery", phc_id=phc_id, medicine_id=medicine_id))

            # Verify PHC is approved and active
            phc = db.execute("SELECT id, name FROM phcs WHERE id = ? AND approval_status = 'approved' AND active_status = 1", (phc_id,)).fetchone()
            if not phc:
                flash("The selected Primary Health Centre is not currently accepting delivery orders.", "danger")
                return redirect(url_for("patient_delivery"))

            # Atomic check and stock reservation
            inv = db.execute("SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?", (phc_id, medicine_id)).fetchone()
            if not inv or inv["usable_quantity"] < quantity:
                available = inv["usable_quantity"] if inv else 0
                flash(f"Cannot place order for {quantity} units: only {available} units available in stock.", "danger")
                return redirect(url_for("patient_delivery", phc_id=phc_id, medicine_id=medicine_id))

            # Deduct reserved stock
            prev_qty = inv["usable_quantity"]
            new_qty = prev_qty - quantity
            db.execute("UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?", (new_qty, inv["id"]))

            # Generate unique tracking reference code
            tracking_code = f"TRK-{secrets.token_hex(4).upper()}"

            # Log stock reservation in ledger
            user_id = session.get("user_id")
            db.execute(
                """
                INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                VALUES (?, ?, 'issued', ?, ?, ?, ?, ?)
                """,
                (phc_id, medicine_id, quantity, prev_qty, new_qty, user_id, f"Patient delivery order {tracking_code} (reserved)")
            )

            # Insert delivery request
            db.execute(
                """
                INSERT INTO delivery_requests (tracking_code, phc_id, medicine_id, quantity, patient_name, contact_phone, delivery_address, user_id, status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
                """,
                (tracking_code, phc_id, medicine_id, quantity, patient_name, contact_phone, delivery_address, user_id, notes)
            )

            # Sync alerts with new stock level
            pred = calculate_stock_prediction(new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"])
            sync_inventory_alerts(db, phc_id, medicine_id, pred)

            db.commit()

            log_audit("PATIENT_DELIVERY_REQUESTED", "delivery_requests", None, f"Tracking: {tracking_code}, Med #{medicine_id}, Qty: {quantity}")
            flash(f"Delivery request submitted successfully! Your tracking reference code is: {tracking_code}", "success")
            return redirect(url_for("patient_track", code=tracking_code))

        # GET request
        pre_phc = request.args.get("phc_id", type=int)
        pre_med = request.args.get("medicine_id", type=int)

        all_phcs = db.execute("SELECT id, name, location FROM phcs WHERE approval_status = 'approved' AND active_status = 1 ORDER BY name").fetchall()
        all_medicines = db.execute("SELECT id, name, dosage_form, unit FROM medicines WHERE active_status = 1 ORDER BY name").fetchall()

        return render_template(
            "patient_delivery.html",
            all_phcs=all_phcs,
            all_medicines=all_medicines,
            selected_phc_id=pre_phc,
            selected_med_id=pre_med,
            default_patient_name=session.get("full_name", ""),
            default_phone=session.get("contact_phone", ""),
            default_address=session.get("delivery_address", ""),
            active_page="patient_delivery"
        )

    @app.route("/patient/track")
    def patient_track():
        """Public status lookup by tracking reference code (masks personal phone & address)."""
        code = request.args.get("code", "").strip().upper()
        delivery = None
        if code:
            db = get_db()
            delivery = db.execute(
                """
                SELECT 
                    d.tracking_code, d.quantity, d.status, d.notes, d.created_at, d.updated_at,
                    m.name AS medicine_name,
                    p.name AS phc_name, p.contact_phone
                FROM delivery_requests d
                JOIN medicines m ON m.id = d.medicine_id
                JOIN phcs p ON p.id = d.phc_id
                WHERE d.tracking_code = ?
                """,
                (code,)
            ).fetchone()

        return render_template(
            "patient_track.html",
            tracking_code=code,
            delivery=delivery,
            active_page="patient_track"
        )

    @app.route("/patient/orders")
    @patient_required
    def patient_orders():
        """View delivery orders placed by the signed-in patient."""
        user_id = session["user_id"]
        db = get_db()
        orders = db.execute(
            """
            SELECT 
                d.*,
                m.name AS medicine_name,
                p.name AS phc_name
            FROM delivery_requests d
            JOIN medicines m ON m.id = d.medicine_id
            JOIN phcs p ON p.id = d.phc_id
            WHERE d.user_id = ?
            ORDER BY d.created_at DESC
            """,
            (user_id,)
        ).fetchall()

        return render_template("patient_orders.html", orders=orders, active_page="patient_orders")

    @app.route("/patient/orders/cancel/<int:order_id>", methods=["POST"])
    @patient_required
    def patient_order_cancel(order_id):
        """Cancel a pending delivery order and release reserved stock back into inventory."""
        user_id = session["user_id"]
        db = get_db()

        order = db.execute("SELECT * FROM delivery_requests WHERE id = ? AND user_id = ?", (order_id, user_id)).fetchone()
        if not order:
            flash("Order not found.", "danger")
            return redirect(url_for("patient_orders"))

        if order["status"] != "Pending":
            flash("Only pending orders can be cancelled.", "warning")
            return redirect(url_for("patient_orders"))

        # Release stock back to PHC inventory
        inv = db.execute("SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?", (order["phc_id"], order["medicine_id"])).fetchone()
        if inv:
            prev_qty = inv["usable_quantity"]
            new_qty = prev_qty + order["quantity"]
            db.execute("UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?", (new_qty, inv["id"]))
            db.execute(
                """
                INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                VALUES (?, ?, 'received', ?, ?, ?, ?, ?)
                """,
                (order["phc_id"], order["medicine_id"], order["quantity"], prev_qty, new_qty, user_id, f"Order {order['tracking_code']} cancelled by patient (restocked)")
            )
            pred = calculate_stock_prediction(new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"])
            sync_inventory_alerts(db, order["phc_id"], order["medicine_id"], pred)

        db.execute("UPDATE delivery_requests SET status = 'Cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (order_id,))
        db.commit()

        log_audit("PATIENT_DELIVERY_CANCELLED", "delivery_requests", order_id, f"Order {order['tracking_code']} cancelled by patient.")
        flash(f"Order #{order['tracking_code']} has been cancelled.", "info")
        return redirect(url_for("patient_orders"))

    # ---------------------------------------------------------
    # View B: Medical Pharmacist Portal Routes
    # ---------------------------------------------------------
    @app.route("/phc/dashboard")
    @phc_staff_required
    def phc_dashboard():
        """Staff operations command dashboard."""
        phc_id = session["phc_id"]
        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()
        if not phc:
            abort(404, description="Assigned Primary Health Centre not found.")

        # Inventory items & dynamic predictions
        query = """
            SELECT 
                i.id, i.phc_id, i.medicine_id, i.usable_quantity, i.safety_stock,
                i.avg_daily_consumption, i.replenishment_lead_time_days, i.last_updated,
                m.name AS medicine_name, m.dosage_form, m.unit, m.category
            FROM inventory i
            JOIN medicines m ON m.id = i.medicine_id
            WHERE i.phc_id = ?
            ORDER BY m.name
        """
        raw_items = db.execute(query, (phc_id,)).fetchall()

        items = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        safe_count = 0
        critical_items = []

        for row in raw_items:
            pred = calculate_stock_prediction(
                row["usable_quantity"],
                row["safety_stock"],
                row["avg_daily_consumption"],
                row["replenishment_lead_time_days"]
            )
            item_dict = dict(row)
            item_dict["prediction"] = pred
            items.append(item_dict)

            r_level = pred["risk_level"]
            if r_level == "Critical":
                critical_count += 1
                critical_items.append(item_dict)
            elif r_level == "High":
                high_count += 1
                critical_items.append(item_dict)
            elif r_level == "Medium":
                medium_count += 1
            else:
                safe_count += 1

        # Pending transfers
        pending_transfers = db.execute(
            """
            SELECT COUNT(*) FROM transfer_requests 
            WHERE (requesting_phc_id = ? OR supplying_phc_id = ?) 
              AND status IN ('pending', 'approved', 'dispatched')
            """,
            (phc_id, phc_id)
        ).fetchone()[0]

        # Pending deliveries
        pending_deliveries = db.execute(
            "SELECT COUNT(*) FROM delivery_requests WHERE phc_id = ? AND status = 'Pending'",
            (phc_id,)
        ).fetchone()[0]

        # Pending replenishment requests
        pending_replenishments = db.execute(
            "SELECT COUNT(*) FROM provider_stock_requests WHERE phc_id = ? AND status = 'pending'",
            (phc_id,)
        ).fetchone()[0]

        # Recent transactions
        recent_transactions = db.execute(
            """
            SELECT st.*, m.name AS medicine_name, u.username
            FROM stock_transactions st
            JOIN medicines m ON m.id = st.medicine_id
            LEFT JOIN users u ON u.id = st.user_id
            WHERE st.phc_id = ?
            ORDER BY st.created_at DESC
            LIMIT 5
            """,
            (phc_id,)
        ).fetchall()

        metrics = {
            "total_medicines": len(items),
            "critical_alerts": critical_count,
            "high_risk": high_count,
            "medium_risk": medium_count,
            "safe_count": safe_count,
            "pending_transfers": pending_transfers,
            "pending_deliveries": pending_deliveries,
            "pending_replenishments": pending_replenishments,
        }

        return render_template(
            "phc_dashboard.html",
            phc=phc,
            metrics=metrics,
            critical_items=critical_items,
            recent_transactions=recent_transactions,
            active_page="phc_dashboard"
        )

    @app.route("/phc/inventory")
    @phc_staff_required
    def phc_inventory():
        """Full inventory management table with predictions and actions."""
        phc_id = session["phc_id"]
        selected_risk = request.args.get("risk", "").strip()

        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()

        query = """
            SELECT 
                i.id, i.phc_id, i.medicine_id, i.usable_quantity, i.safety_stock,
                i.avg_daily_consumption, i.replenishment_lead_time_days, i.last_updated,
                m.name AS medicine_name, m.dosage_form, m.unit, m.category
            FROM inventory i
            JOIN medicines m ON m.id = i.medicine_id
            WHERE i.phc_id = ?
            ORDER BY m.name
        """
        rows = db.execute(query, (phc_id,)).fetchall()

        inventory_items = []
        for r in rows:
            pred = calculate_stock_prediction(
                r["usable_quantity"],
                r["safety_stock"],
                r["avg_daily_consumption"],
                r["replenishment_lead_time_days"]
            )
            item_dict = dict(r)
            item_dict["prediction"] = pred

            if selected_risk:
                if pred["risk_level"].lower() == selected_risk.lower():
                    inventory_items.append(item_dict)
            else:
                inventory_items.append(item_dict)

        # Get catalogue medicines not already in this PHC's inventory
        tracked_ids = [r["medicine_id"] for r in rows]
        if tracked_ids:
            placeholders = ",".join(["?"] * len(tracked_ids))
            all_catalogue_medicines = db.execute(
                f"SELECT id, name, dosage_form, unit FROM medicines WHERE active_status = 1 AND id NOT IN ({placeholders}) ORDER BY name",
                tracked_ids
            ).fetchall()
        else:
            all_catalogue_medicines = db.execute(
                "SELECT id, name, dosage_form, unit FROM medicines WHERE active_status = 1 ORDER BY name"
            ).fetchall()

        return render_template(
            "inventory.html",
            phc=phc,
            inventory_items=inventory_items,
            all_catalogue_medicines=all_catalogue_medicines,
            selected_risk=selected_risk,
            active_page="inventory"
        )

    @app.route("/phc/inventory/add", methods=["POST"])
    @phc_staff_required
    def phc_inventory_add():
        """Add a medicine from the central catalogue into this PHC's dispensary inventory."""
        phc_id = session["phc_id"]
        medicine_id = request.form.get("medicine_id", type=int)
        usable_quantity = request.form.get("usable_quantity", type=int, default=0)
        safety_stock = request.form.get("safety_stock", type=int, default=50)
        avg_daily_consumption = request.form.get("avg_daily_consumption", type=float, default=5.0)
        replenishment_lead_time_days = request.form.get("replenishment_lead_time_days", type=int, default=7)

        if not medicine_id or usable_quantity < 0 or safety_stock < 0 or avg_daily_consumption < 0 or replenishment_lead_time_days < 1:
            flash("Please provide valid non-negative values to add medicine.", "danger")
            return redirect(url_for("phc_inventory"))

        db = get_db()
        existing = db.execute("SELECT id FROM inventory WHERE phc_id = ? AND medicine_id = ?", (phc_id, medicine_id)).fetchone()
        if existing:
            flash("This medicine is already tracked in your inventory.", "warning")
            return redirect(url_for("phc_inventory"))

        cur = db.execute(
            """
            INSERT INTO inventory (phc_id, medicine_id, usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (phc_id, medicine_id, usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days)
        )
        inv_id = cur.lastrowid

        if usable_quantity > 0:
            db.execute(
                """
                INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                VALUES (?, ?, 'received', ?, 0, ?, ?, 'Initial inventory addition')
                """,
                (phc_id, medicine_id, usable_quantity, usable_quantity, session["user_id"])
            )

        pred = calculate_stock_prediction(usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days)
        sync_inventory_alerts(db, phc_id, medicine_id, pred)
        db.commit()

        log_audit("INVENTORY_ADDED", "inventory", inv_id, f"Added med #{medicine_id} with initial stock {usable_quantity}")
        flash("Medicine successfully added to dispensary inventory.", "success")
        return redirect(url_for("phc_inventory"))

    @app.route("/phc/inventory/update-levels/<int:inventory_id>", methods=["POST"])
    @phc_staff_required
    def phc_inventory_update_levels(inventory_id):
        """Update usable quantity, safety stock threshold, consumption velocity, and lead time."""
        phc_id = session["phc_id"]
        usable_quantity = request.form.get("usable_quantity", type=int)
        safety_stock = request.form.get("safety_stock", type=int)
        avg_daily_consumption = request.form.get("avg_daily_consumption", type=float)
        lead_time = request.form.get("replenishment_lead_time_days", type=int)

        if usable_quantity is None or usable_quantity < 0 or safety_stock is None or safety_stock < 0 or avg_daily_consumption is None or avg_daily_consumption < 0 or lead_time is None or lead_time < 1:
            flash("Invalid input values. Quantities and thresholds must be non-negative.", "danger")
            return redirect(url_for("phc_inventory"))

        db = get_db()
        inv = db.execute("SELECT * FROM inventory WHERE id = ? AND phc_id = ?", (inventory_id, phc_id)).fetchone()
        if not inv:
            flash("Inventory record not found.", "danger")
            return redirect(url_for("phc_inventory"))

        prev_qty = inv["usable_quantity"]
        db.execute(
            """
            UPDATE inventory 
            SET usable_quantity = ?, safety_stock = ?, avg_daily_consumption = ?, replenishment_lead_time_days = ?, last_updated = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (usable_quantity, safety_stock, avg_daily_consumption, lead_time, inventory_id)
        )

        if usable_quantity != prev_qty:
            diff = usable_quantity - prev_qty
            db.execute(
                """
                INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                VALUES (?, ?, 'adjustment', ?, ?, ?, ?, 'Stock count update')
                """,
                (phc_id, inv["medicine_id"], abs(diff), prev_qty, usable_quantity, session["user_id"])
            )

        pred = calculate_stock_prediction(usable_quantity, safety_stock, avg_daily_consumption, lead_time)
        sync_inventory_alerts(db, phc_id, inv["medicine_id"], pred)
        db.commit()

        log_audit("INVENTORY_UPDATED", "inventory", inventory_id, f"Stock updated to {usable_quantity}, safety stock to {safety_stock}")
        flash("Dispensary stock and safety thresholds updated successfully.", "success")
        return redirect(url_for("phc_inventory"))

    @app.route("/phc/stock/receive", methods=["POST"])
    @phc_staff_required
    def phc_stock_receive():
        """Receive inbound stock into inventory and recalculate."""
        phc_id = session["phc_id"]
        medicine_id = request.form.get("medicine_id", type=int)
        quantity = request.form.get("quantity", type=int)
        notes = request.form.get("notes", "").strip()

        if not medicine_id or not quantity or quantity <= 0:
            flash("Valid positive quantity is required to receive stock.", "danger")
            return redirect(url_for("phc_inventory"))

        db = get_db()
        inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (phc_id, medicine_id)
        ).fetchone()

        if not inv:
            flash("Medicine inventory record not found.", "danger")
            return redirect(url_for("phc_inventory"))

        prev_qty = inv["usable_quantity"]
        new_qty = prev_qty + quantity

        db.execute(
            "UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
            (new_qty, inv["id"])
        )

        db.execute(
            """
            INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
            VALUES (?, ?, 'received', ?, ?, ?, ?, ?)
            """,
            (phc_id, medicine_id, quantity, prev_qty, new_qty, session["user_id"], notes or "Inbound stock receipt")
        )

        pred = calculate_stock_prediction(
            new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"]
        )
        sync_inventory_alerts(db, phc_id, medicine_id, pred)

        db.commit()

        log_audit("STOCK_RECEIVE", "inventory", inv["id"], f"Received {quantity} units. Stock: {prev_qty} -> {new_qty}.")
        flash(f"Successfully received {quantity} units into usable stock. Current balance: {new_qty} units.", "success")
        return redirect(url_for("phc_inventory"))

    @app.route("/phc/stock/issue", methods=["POST"])
    @phc_staff_required
    def phc_stock_issue():
        """Issue stock from inventory with strict non-negative check."""
        phc_id = session["phc_id"]
        medicine_id = request.form.get("medicine_id", type=int)
        quantity = request.form.get("quantity", type=int)
        notes = request.form.get("notes", "").strip()

        if not medicine_id or not quantity or quantity <= 0:
            flash("Valid positive quantity is required to dispense stock.", "danger")
            return redirect(url_for("phc_inventory"))

        db = get_db()
        inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (phc_id, medicine_id)
        ).fetchone()

        if not inv:
            flash("Medicine inventory record not found.", "danger")
            return redirect(url_for("phc_inventory"))

        prev_qty = inv["usable_quantity"]
        if quantity > prev_qty:
            flash(f"Cannot dispense {quantity} units: exceeds current usable stock ({prev_qty} units).", "danger")
            return redirect(url_for("phc_inventory"))

        new_qty = prev_qty - quantity

        db.execute(
            "UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
            (new_qty, inv["id"])
        )

        db.execute(
            """
            INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
            VALUES (?, ?, 'issued', ?, ?, ?, ?, ?)
            """,
            (phc_id, medicine_id, quantity, prev_qty, new_qty, session["user_id"], notes or "Outpatient clinic dispensing")
        )

        pred = calculate_stock_prediction(
            new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"]
        )
        sync_inventory_alerts(db, phc_id, medicine_id, pred)

        db.commit()

        log_audit("STOCK_ISSUE", "inventory", inv["id"], f"Issued {quantity} units. Stock: {prev_qty} -> {new_qty}.")
        flash(f"Dispensed {quantity} units. Remaining usable balance: {new_qty} units.", "success")
        return redirect(url_for("phc_inventory"))

    @app.route("/phc/stock/adjust", methods=["POST"])
    @phc_staff_required
    def phc_stock_adjust():
        """Correct inventory count through physical audit."""
        phc_id = session["phc_id"]
        medicine_id = request.form.get("medicine_id", type=int)
        quantity = request.form.get("quantity", type=int)
        notes = request.form.get("notes", "").strip()

        if medicine_id is None or quantity is None or quantity < 0:
            flash("Valid non-negative count is required for stock adjustment.", "danger")
            return redirect(url_for("phc_inventory"))

        db = get_db()
        inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (phc_id, medicine_id)
        ).fetchone()

        if not inv:
            flash("Medicine inventory record not found.", "danger")
            return redirect(url_for("phc_inventory"))

        prev_qty = inv["usable_quantity"]
        diff = quantity - prev_qty

        db.execute(
            "UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
            (quantity, inv["id"])
        )

        db.execute(
            """
            INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
            VALUES (?, ?, 'adjustment', ?, ?, ?, ?, ?)
            """,
            (phc_id, medicine_id, abs(diff), prev_qty, quantity, session["user_id"], notes or "Physical inventory count adjustment")
        )

        pred = calculate_stock_prediction(
            quantity, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"]
        )
        sync_inventory_alerts(db, phc_id, medicine_id, pred)

        db.commit()

        log_audit("STOCK_ADJUSTMENT", "inventory", inv["id"], f"Adjusted count from {prev_qty} to {quantity}. Note: {notes}")
        flash(f"Inventory count corrected to {quantity} units.", "info")
        return redirect(url_for("phc_inventory"))

    @app.route("/phc/alerts")
    @phc_staff_required
    def phc_alerts():
        """Staff view of active alerts."""
        phc_id = session["phc_id"]
        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()

        alerts = db.execute(
            """
            SELECT 
                a.*, m.name AS medicine_name, m.unit, m.dosage_form,
                i.usable_quantity, i.safety_stock, i.avg_daily_consumption
            FROM alerts a
            JOIN medicines m ON m.id = a.medicine_id
            JOIN inventory i ON i.phc_id = a.phc_id AND i.medicine_id = a.medicine_id
            WHERE a.phc_id = ? AND a.status = 'open'
            ORDER BY 
                CASE a.risk_level 
                    WHEN 'Critical' THEN 1 
                    WHEN 'High' THEN 2 
                    WHEN 'Medium' THEN 3 
                    ELSE 4 
                END,
                a.created_at DESC
            """,
            (phc_id,)
        ).fetchall()

        return render_template("alerts.html", phc=phc, alerts=alerts, active_page="alerts")

    @app.route("/phc/transfers")
    @phc_staff_required
    def phc_transfers():
        """Staff emergency transfers dashboard."""
        phc_id = session["phc_id"]
        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()

        outgoing = db.execute(
            """
            SELECT 
                t.*, m.name AS medicine_name, m.dosage_form, m.unit,
                sp.name AS supplying_phc_name, sp.location AS supplying_location
            FROM transfer_requests t
            JOIN medicines m ON m.id = t.medicine_id
            JOIN phcs sp ON sp.id = t.supplying_phc_id
            WHERE t.requesting_phc_id = ?
            ORDER BY t.created_at DESC
            """,
            (phc_id,)
        ).fetchall()

        incoming = db.execute(
            """
            SELECT 
                t.*, m.name AS medicine_name, m.dosage_form, m.unit,
                rp.name AS requesting_phc_name, rp.location AS requesting_location
            FROM transfer_requests t
            JOIN medicines m ON m.id = t.medicine_id
            JOIN phcs rp ON rp.id = t.requesting_phc_id
            WHERE t.supplying_phc_id = ?
            ORDER BY t.created_at DESC
            """,
            (phc_id,)
        ).fetchall()

        return render_template(
            "transfers.html",
            phc=phc,
            outgoing_requests=outgoing,
            incoming_requests=incoming,
            active_page="transfers"
        )

    @app.route("/phc/transfers/recommendations/<int:medicine_id>")
    @phc_staff_required
    def transfer_recommendations(medicine_id):
        """Distance-aware surplus matching recommendation viewer."""
        phc_id = session["phc_id"]
        req_qty = request.args.get("qty", type=int)

        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()
        med = db.execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
        if not med:
            abort(404, description="Medicine catalogue item not found.")

        inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (phc_id, medicine_id)
        ).fetchone()

        if not inv:
            flash("This medicine is not yet tracked in your dispensary inventory.", "warning")
            return redirect(url_for("phc_inventory"))

        pred = calculate_stock_prediction(
            inv["usable_quantity"], inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"]
        )

        default_needed = max(50, inv["safety_stock"] - inv["usable_quantity"])
        target_qty = req_qty if req_qty and req_qty > 0 else default_needed

        matches = find_surplus_matches(db, phc_id, medicine_id, target_qty)

        return render_template(
            "transfer_recommendations.html",
            phc=phc,
            medicine=med,
            inventory=inv,
            prediction=pred,
            matches=matches,
            requested_qty=target_qty,
            active_page="transfers"
        )

    @app.route("/phc/transfers/request", methods=["POST"])
    @phc_staff_required
    def phc_transfer_request():
        """Submit an emergency inter-facility transfer request."""
        requesting_phc_id = session["phc_id"]
        supplying_phc_id = request.form.get("supplying_phc_id", type=int)
        medicine_id = request.form.get("medicine_id", type=int)
        requested_quantity = request.form.get("requested_quantity", type=int)
        distance_km = request.form.get("distance_km", type=float)
        reason = request.form.get("reason", "").strip()

        if not (supplying_phc_id and medicine_id and requested_quantity and requested_quantity > 0):
            flash("All transfer parameters must be valid positive values.", "danger")
            return redirect(url_for("phc_transfers"))

        if supplying_phc_id == requesting_phc_id:
            flash("A healthcare facility cannot request an inter-facility transfer from itself.", "danger")
            return redirect(url_for("phc_transfers"))

        db = get_db()
        db.execute(
            """
            INSERT INTO transfer_requests (
                requesting_phc_id, supplying_phc_id, medicine_id, requested_quantity,
                distance_km, reason, status
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
            """,
            (requesting_phc_id, supplying_phc_id, medicine_id, requested_quantity, distance_km, reason)
        )
        db.commit()

        log_audit("TRANSFER_SUBMITTED", "transfer_requests", None, f"Req #{requesting_phc_id} from Supp #{supplying_phc_id}, Med #{medicine_id}, Qty {requested_quantity}")
        flash(f"Emergency transfer request for {requested_quantity} units submitted successfully! Awaiting District Administrator review.", "success")
        return redirect(url_for("phc_transfers"))

    @app.route("/phc/transfers/dispatch/<int:transfer_id>", methods=["POST"])
    @phc_staff_required
    def phc_transfer_dispatch(transfer_id):
        """Supplying PHC records physical dispatch of approved transfer."""
        user_phc_id = session["phc_id"]
        db = get_db()

        transfer = db.execute("SELECT * FROM transfer_requests WHERE id = ?", (transfer_id,)).fetchone()
        if not transfer:
            flash("Transfer record not found.", "danger")
            return redirect(url_for("phc_transfers"))

        if transfer["supplying_phc_id"] != user_phc_id:
            flash("Unauthorized: Only the assigned supplying health centre may dispatch stock.", "danger")
            return abort(403)

        if transfer["status"] != "approved":
            flash("Only officially approved transfers can be dispatched.", "danger")
            return redirect(url_for("phc_transfers"))

        qty_to_dispatch = transfer["approved_quantity"] or transfer["requested_quantity"]

        sup_inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (user_phc_id, transfer["medicine_id"])
        ).fetchone()

        if not sup_inv or sup_inv["usable_quantity"] < qty_to_dispatch:
            flash("Cannot dispatch: Insufficient stock currently available in supplying inventory.", "danger")
            return redirect(url_for("phc_transfers"))

        prev_qty = sup_inv["usable_quantity"]
        new_qty = prev_qty - qty_to_dispatch

        db.execute(
            "UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
            (new_qty, sup_inv["id"])
        )

        db.execute(
            """
            INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, related_transfer_id, notes)
            VALUES (?, ?, 'transfer_dispatch', ?, ?, ?, ?, ?, ?)
            """,
            (user_phc_id, transfer["medicine_id"], qty_to_dispatch, prev_qty, new_qty, session["user_id"], transfer_id, f"Dispatched for transfer #{transfer_id}")
        )

        db.execute(
            """
            UPDATE transfer_requests 
            SET status = 'dispatched', dispatched_at = CURRENT_TIMESTAMP, dispatched_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (session["user_id"], transfer_id)
        )

        pred = calculate_stock_prediction(
            new_qty, sup_inv["safety_stock"], sup_inv["avg_daily_consumption"], sup_inv["replenishment_lead_time_days"]
        )
        sync_inventory_alerts(db, user_phc_id, transfer["medicine_id"], pred)

        db.commit()

        log_audit("TRANSFER_DISPATCHED", "transfer_requests", transfer_id, f"Dispatched {qty_to_dispatch} units. Supplier stock: {prev_qty} -> {new_qty}")
        flash(f"Transfer #{transfer_id} dispatched successfully. {qty_to_dispatch} units deducted from inventory and marked in transit.", "success")
        return redirect(url_for("phc_transfers"))

    @app.route("/phc/transfers/receive/<int:transfer_id>", methods=["POST"])
    @phc_staff_required
    def phc_transfer_receive(transfer_id):
        """Receiving PHC confirms physical receipt, atomically adding stock."""
        user_phc_id = session["phc_id"]
        db = get_db()

        transfer = db.execute("SELECT * FROM transfer_requests WHERE id = ?", (transfer_id,)).fetchone()
        if not transfer:
            flash("Transfer record not found.", "danger")
            return redirect(url_for("phc_transfers"))

        if transfer["requesting_phc_id"] != user_phc_id:
            flash("Unauthorized: Only the designated recipient health centre may confirm receipt.", "danger")
            return abort(403)

        if transfer["status"] != "dispatched":
            flash("Transfer must be in 'dispatched' status to confirm receipt.", "danger")
            return redirect(url_for("phc_transfers"))

        qty_received = transfer["approved_quantity"] or transfer["requested_quantity"]

        rec_inv = db.execute(
            "SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (user_phc_id, transfer["medicine_id"])
        ).fetchone()

        if rec_inv:
            prev_qty = rec_inv["usable_quantity"]
            new_qty = prev_qty + qty_received
            db.execute(
                "UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?",
                (new_qty, rec_inv["id"])
            )
            safety = rec_inv["safety_stock"]
            usage = rec_inv["avg_daily_consumption"]
            lead = rec_inv["replenishment_lead_time_days"]
        else:
            prev_qty = 0
            new_qty = qty_received
            db.execute(
                """
                INSERT INTO inventory (phc_id, medicine_id, usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days)
                VALUES (?, ?, ?, 50, 0.0, 7)
                """,
                (user_phc_id, transfer["medicine_id"], new_qty)
            )
            safety, usage, lead = 50, 0.0, 7

        db.execute(
            """
            INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, related_transfer_id, notes)
            VALUES (?, ?, 'transfer_receipt', ?, ?, ?, ?, ?, ?)
            """,
            (user_phc_id, transfer["medicine_id"], qty_received, prev_qty, new_qty, session["user_id"], transfer_id, f"Received from transfer #{transfer_id}")
        )

        db.execute(
            """
            UPDATE transfer_requests 
            SET status = 'received', received_at = CURRENT_TIMESTAMP, received_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (session["user_id"], transfer_id)
        )

        pred = calculate_stock_prediction(new_qty, safety, usage, lead)
        sync_inventory_alerts(db, user_phc_id, transfer["medicine_id"], pred)

        db.commit()

        log_audit("TRANSFER_RECEIVED", "transfer_requests", transfer_id, f"Confirmed receipt of {qty_received} units. Receiver stock: {prev_qty} -> {new_qty}")
        flash(f"Transfer #{transfer_id} confirmed and completed! {qty_received} units added to usable stock. New balance: {new_qty} units.", "success")
        return redirect(url_for("phc_transfers"))

    @app.route("/phc/deliveries")
    @phc_staff_required
    def phc_deliveries():
        """Staff review of delivery requests assigned to their PHC."""
        phc_id = session["phc_id"]
        selected_status = request.args.get("status", "").strip()

        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()

        query = """
            SELECT 
                d.*, m.name AS medicine_name, m.unit
            FROM delivery_requests d
            JOIN medicines m ON m.id = d.medicine_id
            WHERE d.phc_id = ?
        """
        params = [phc_id]

        if selected_status:
            query += " AND d.status = ?"
            params.append(selected_status)

        query += " ORDER BY d.created_at DESC"
        deliveries = db.execute(query, params).fetchall()

        return render_template(
            "deliveries.html",
            phc=phc,
            deliveries=deliveries,
            selected_status=selected_status,
            active_page="deliveries"
        )

    @app.route("/phc/deliveries/accept/<int:delivery_id>", methods=["POST"])
    @phc_staff_required
    def phc_delivery_accept(delivery_id):
        """Pharmacist accepts a pending delivery request."""
        phc_id = session["phc_id"]
        db = get_db()

        deliv = db.execute("SELECT * FROM delivery_requests WHERE id = ? AND phc_id = ?", (delivery_id, phc_id)).fetchone()
        if not deliv:
            flash("Delivery request not found.", "danger")
            return redirect(url_for("phc_deliveries"))

        if deliv["status"] != "Pending":
            flash(f"Cannot accept order in '{deliv['status']}' status.", "warning")
            return redirect(url_for("phc_deliveries"))

        db.execute(
            "UPDATE delivery_requests SET status = 'Accepted', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (delivery_id,)
        )
        db.commit()

        log_audit("DELIVERY_ACCEPTED", "delivery_requests", delivery_id, f"Accepted delivery {deliv['tracking_code']}")
        flash(f"Delivery request #{deliv['tracking_code']} accepted.", "success")
        return redirect(url_for("phc_deliveries"))

    @app.route("/phc/deliveries/reject/<int:delivery_id>", methods=["POST"])
    @phc_staff_required
    def phc_delivery_reject(delivery_id):
        """Pharmacist rejects a delivery request and releases reserved stock back into inventory."""
        phc_id = session["phc_id"]
        notes = request.form.get("notes", "Rejected by dispensary staff").strip()
        db = get_db()

        deliv = db.execute("SELECT * FROM delivery_requests WHERE id = ? AND phc_id = ?", (delivery_id, phc_id)).fetchone()
        if not deliv:
            flash("Delivery request not found.", "danger")
            return redirect(url_for("phc_deliveries"))

        if deliv["status"] in ("Rejected", "Cancelled"):
            flash("Order is already rejected or cancelled.", "warning")
            return redirect(url_for("phc_deliveries"))

        # Release stock back to inventory if not already delivered
        if deliv["status"] != "Delivered":
            inv = db.execute("SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?", (phc_id, deliv["medicine_id"])).fetchone()
            if inv:
                prev_qty = inv["usable_quantity"]
                new_qty = prev_qty + deliv["quantity"]
                db.execute("UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?", (new_qty, inv["id"]))
                db.execute(
                    """
                    INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                    VALUES (?, ?, 'received', ?, ?, ?, ?, ?)
                    """,
                    (phc_id, deliv["medicine_id"], deliv["quantity"], prev_qty, new_qty, session["user_id"], f"Delivery {deliv['tracking_code']} rejected (restocked)")
                )
                pred = calculate_stock_prediction(new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"])
                sync_inventory_alerts(db, phc_id, deliv["medicine_id"], pred)

        db.execute(
            "UPDATE delivery_requests SET status = 'Rejected', notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (notes, delivery_id)
        )
        db.commit()

        log_audit("DELIVERY_REJECTED", "delivery_requests", delivery_id, f"Rejected delivery {deliv['tracking_code']}. Reason: {notes}")
        flash(f"Delivery request #{deliv['tracking_code']} rejected and stock returned to inventory.", "warning")
        return redirect(url_for("phc_deliveries"))

    @app.route("/phc/deliveries/update/<int:delivery_id>", methods=["POST"])
    @phc_staff_required
    def phc_delivery_update(delivery_id):
        """Update delivery request status (Pending, Accepted, Preparing, Out for delivery, Delivered, Rejected)."""
        phc_id = session["phc_id"]
        status = request.form.get("status", "").strip()
        notes = request.form.get("notes", "").strip()

        db = get_db()
        deliv = db.execute("SELECT * FROM delivery_requests WHERE id = ? AND phc_id = ?", (delivery_id, phc_id)).fetchone()
        if not deliv:
            flash("Delivery request not found or does not belong to your health centre.", "danger")
            return redirect(url_for("phc_deliveries"))

        valid_statuses = ("Pending", "Accepted", "Approved", "Assigned", "Preparing", "Out for delivery", "Delivered", "Rejected")
        if status not in valid_statuses:
            flash("Invalid delivery status transition.", "danger")
            return redirect(url_for("phc_deliveries"))

        # If transitioning to Rejected, release stock
        if status == "Rejected" and deliv["status"] not in ("Rejected", "Cancelled", "Delivered"):
            inv = db.execute("SELECT * FROM inventory WHERE phc_id = ? AND medicine_id = ?", (phc_id, deliv["medicine_id"])).fetchone()
            if inv:
                prev_qty = inv["usable_quantity"]
                new_qty = prev_qty + deliv["quantity"]
                db.execute("UPDATE inventory SET usable_quantity = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?", (new_qty, inv["id"]))
                db.execute(
                    """
                    INSERT INTO stock_transactions (phc_id, medicine_id, transaction_type, quantity, previous_quantity, new_quantity, user_id, notes)
                    VALUES (?, ?, 'received', ?, ?, ?, ?, ?)
                    """,
                    (phc_id, deliv["medicine_id"], deliv["quantity"], prev_qty, new_qty, session["user_id"], f"Delivery {deliv['tracking_code']} rejected via update (restocked)")
                )
                pred = calculate_stock_prediction(new_qty, inv["safety_stock"], inv["avg_daily_consumption"], inv["replenishment_lead_time_days"])
                sync_inventory_alerts(db, phc_id, deliv["medicine_id"], pred)

        db.execute(
            """
            UPDATE delivery_requests 
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, notes or deliv["notes"], delivery_id)
        )
        db.commit()

        log_audit("DELIVERY_STATUS_UPDATED", "delivery_requests", delivery_id, f"Status updated to '{status}'. Notes: {notes}")
        flash(f"Delivery request #{deliv['tracking_code']} status updated to '{status}'.", "success")
        return redirect(url_for("phc_deliveries"))

    @app.route("/phc/replenishment")
    @phc_staff_required
    def phc_replenishment():
        """View and submit provider stock replenishment requests to District Administrator."""
        phc_id = session["phc_id"]
        db = get_db()
        phc = db.execute("SELECT * FROM phcs WHERE id = ?", (phc_id,)).fetchone()

        all_medicines = db.execute("SELECT id, name, dosage_form, unit FROM medicines WHERE active_status = 1 ORDER BY name").fetchall()

        requests = db.execute(
            """
            SELECT 
                r.*, m.name AS medicine_name, m.dosage_form, m.unit
            FROM provider_stock_requests r
            JOIN medicines m ON m.id = r.medicine_id
            WHERE r.phc_id = ?
            ORDER BY r.created_at DESC
            """,
            (phc_id,)
        ).fetchall()

        return render_template(
            "phc_replenishment.html",
            phc=phc,
            all_medicines=all_medicines,
            requests=requests,
            active_page="phc_replenishment"
        )

    @app.route("/phc/replenishment/submit", methods=["POST"])
    @phc_staff_required
    def phc_replenishment_submit():
        """Submit a provider stock replenishment request to District Administrator."""
        phc_id = session["phc_id"]
        medicine_id = request.form.get("medicine_id", type=int)
        requested_quantity = request.form.get("requested_quantity", type=int)
        reason = request.form.get("reason", "").strip()

        if not (medicine_id and requested_quantity and requested_quantity > 0 and reason):
            flash("Please provide all required details for the replenishment request.", "danger")
            return redirect(url_for("phc_replenishment"))

        db = get_db()
        db.execute(
            """
            INSERT INTO provider_stock_requests (phc_id, medicine_id, requested_quantity, reason, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (phc_id, medicine_id, requested_quantity, reason)
        )
        db.commit()

        log_audit("REPLENISHMENT_REQUESTED", "provider_stock_requests", None, f"PHC #{phc_id} requested {requested_quantity} of med #{medicine_id}")
        flash(f"Replenishment request for {requested_quantity} units submitted to District Administrator.", "success")
        return redirect(url_for("phc_replenishment"))

    # ---------------------------------------------------------
    # View C: District Administrator Portal Routes
    # ---------------------------------------------------------
    @app.route("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        """District command centre overview with KPIs and action queues."""
        db = get_db()

        total_phcs = db.execute("SELECT COUNT(*) FROM phcs").fetchone()[0]
        approved_phcs = db.execute("SELECT COUNT(*) FROM phcs WHERE approval_status = 'approved'").fetchone()[0]
        pending_phcs = db.execute("SELECT COUNT(*) FROM phcs WHERE approval_status = 'pending'").fetchone()[0]
        total_meds = db.execute("SELECT COUNT(*) FROM medicines WHERE active_status = 1").fetchone()[0]

        all_inv = db.execute(
            """
            SELECT i.usable_quantity, i.safety_stock, i.avg_daily_consumption, i.replenishment_lead_time_days
            FROM inventory i
            JOIN phcs p ON p.id = i.phc_id
            WHERE p.approval_status = 'approved'
            """
        ).fetchall()

        crit_c = 0
        high_c = 0
        med_c = 0
        safe_c = 0
        for row in all_inv:
            p = calculate_stock_prediction(
                row["usable_quantity"], row["safety_stock"], row["avg_daily_consumption"], row["replenishment_lead_time_days"]
            )
            rl = p["risk_level"]
            if rl == "Critical":
                crit_c += 1
            elif rl == "High":
                high_c += 1
            elif rl == "Medium":
                med_c += 1
            else:
                safe_c += 1

        pending_transfers = db.execute("SELECT COUNT(*) FROM transfer_requests WHERE status = 'pending'").fetchone()[0]
        completed_transfers = db.execute("SELECT COUNT(*) FROM transfer_requests WHERE status = 'received'").fetchone()[0]
        pending_requests = db.execute("SELECT COUNT(*) FROM provider_stock_requests WHERE status = 'pending'").fetchone()[0]

        stats = {
            "total_phcs": total_phcs,
            "approved_phcs": approved_phcs,
            "pending_phcs": pending_phcs,
            "total_medicines": total_meds,
            "critical_alerts": crit_c,
            "high_risk": high_c,
            "medium_risk": med_c,
            "safe_count": safe_c,
            "pending_transfers": pending_transfers,
            "completed_transfers": completed_transfers,
            "pending_requests": pending_requests,
        }

        # Pending Provider Replenishment Requests
        pending_provider_requests = db.execute(
            """
            SELECT 
                r.*, m.name AS medicine_name, p.name AS phc_name
            FROM provider_stock_requests r
            JOIN medicines m ON m.id = r.medicine_id
            JOIN phcs p ON p.id = r.phc_id
            WHERE r.status = 'pending'
            ORDER BY r.created_at DESC
            LIMIT 5
            """
        ).fetchall()

        # Pending transfers list
        pending_transfers_list = db.execute(
            """
            SELECT 
                t.*, m.name AS medicine_name,
                rp.name AS requesting_phc_name,
                sp.name AS supplying_phc_name
            FROM transfer_requests t
            JOIN medicines m ON m.id = t.medicine_id
            JOIN phcs rp ON rp.id = t.requesting_phc_id
            JOIN phcs sp ON sp.id = t.supplying_phc_id
            WHERE t.status = 'pending'
            ORDER BY t.created_at DESC
            LIMIT 5
            """
        ).fetchall()

        # Active Critical Alerts
        active_alerts = db.execute(
            """
            SELECT 
                a.*, p.name AS phc_name, p.location AS phc_location,
                m.name AS medicine_name,
                i.usable_quantity, i.avg_daily_consumption,
                ROUND(CASE WHEN i.avg_daily_consumption > 0 THEN i.usable_quantity / i.avg_daily_consumption ELSE 0 END, 1) AS days_remaining
            FROM alerts a
            JOIN phcs p ON p.id = a.phc_id
            JOIN medicines m ON m.id = a.medicine_id
            JOIN inventory i ON i.phc_id = a.phc_id AND i.medicine_id = a.medicine_id
            WHERE a.status = 'open' AND a.risk_level = 'Critical'
            ORDER BY a.created_at DESC
            LIMIT 6
            """
        ).fetchall()

        return render_template(
            "admin_dashboard.html",
            stats=stats,
            pending_provider_requests=pending_provider_requests,
            pending_transfers_list=pending_transfers_list,
            active_alerts=active_alerts,
            active_page="admin_dashboard"
        )

    @app.route("/admin/phcs")
    @admin_required
    def admin_phcs():
        """PHC Registry, approval actions, and status management."""
        status = request.args.get("status", "").strip()
        db = get_db()
        query = """
            SELECT 
                p.*,
                (SELECT COUNT(*) FROM inventory WHERE phc_id = p.id) AS total_medicines
            FROM phcs p
        """
        params = []
        if status:
            query += " WHERE p.approval_status = ?"
            params.append(status)

        query += " ORDER BY p.name"
        phcs = db.execute(query, params).fetchall()

        return render_template("phcs.html", phcs=phcs, selected_status=status, active_page="admin_phcs")

    @app.route("/admin/phcs/approve/<int:phc_id>", methods=["POST"])
    @admin_required
    def admin_phc_approve(phc_id):
        """Approve a primary health centre for full network participation."""
        db = get_db()
        db.execute("UPDATE phcs SET approval_status = 'approved', active_status = 1 WHERE id = ?", (phc_id,))
        db.commit()
        log_audit("PHC_APPROVED", "phcs", phc_id, f"Approved PHC #{phc_id} for district stock operations.")
        flash("Primary Health Centre approved successfully.", "success")
        return redirect(url_for("admin_phcs"))

    @app.route("/admin/phcs/reject/<int:phc_id>", methods=["POST"])
    @admin_required
    def admin_phc_reject(phc_id):
        """Reject an application from a primary health centre."""
        db = get_db()
        db.execute("UPDATE phcs SET approval_status = 'rejected', active_status = 0 WHERE id = ?", (phc_id,))
        db.commit()
        log_audit("PHC_REJECTED", "phcs", phc_id, f"Rejected PHC #{phc_id}.")
        flash("Primary Health Centre registration rejected.", "warning")
        return redirect(url_for("admin_phcs"))

    @app.route("/admin/phcs/suspend/<int:phc_id>", methods=["POST"])
    @admin_required
    def admin_phc_suspend(phc_id):
        """Suspend an approved primary health centre."""
        db = get_db()
        db.execute("UPDATE phcs SET approval_status = 'suspended', active_status = 0 WHERE id = ?", (phc_id,))
        db.commit()
        log_audit("PHC_SUSPENDED", "phcs", phc_id, f"Suspended PHC #{phc_id}.")
        flash("Primary Health Centre suspended.", "warning")
        return redirect(url_for("admin_phcs"))

    @app.route("/admin/phcs/reactivate/<int:phc_id>", methods=["POST"])
    @admin_required
    def admin_phc_reactivate(phc_id):
        """Reactivate a suspended primary health centre."""
        db = get_db()
        db.execute("UPDATE phcs SET approval_status = 'approved', active_status = 1 WHERE id = ?", (phc_id,))
        db.commit()
        log_audit("PHC_REACTIVATED", "phcs", phc_id, f"Reactivated PHC #{phc_id}.")
        flash("Primary Health Centre reactivated successfully.", "success")
        return redirect(url_for("admin_phcs"))

    @app.route("/admin/provider-requests")
    @admin_required
    def admin_provider_requests():
        """Review and manage stock replenishment requests from different registered providers."""
        phc_id = request.args.get("phc_id", type=int)
        med_id = request.args.get("medicine_id", type=int)
        status = request.args.get("status", "").strip()

        db = get_db()
        all_phcs = db.execute("SELECT id, name FROM phcs WHERE approval_status = 'approved' ORDER BY name").fetchall()
        all_meds = db.execute("SELECT id, name FROM medicines WHERE active_status = 1 ORDER BY name").fetchall()

        query = """
            SELECT 
                r.*, m.name AS medicine_name, p.name AS phc_name, p.location AS phc_location
            FROM provider_stock_requests r
            JOIN medicines m ON m.id = r.medicine_id
            JOIN phcs p ON p.id = r.phc_id
            WHERE 1=1
        """
        params = []
        if phc_id:
            query += " AND r.phc_id = ?"
            params.append(phc_id)
        if med_id:
            query += " AND r.medicine_id = ?"
            params.append(med_id)
        if status:
            query += " AND r.status = ?"
            params.append(status)

        query += " ORDER BY r.created_at DESC"
        requests = db.execute(query, params).fetchall()

        return render_template(
            "admin_provider_requests.html",
            requests=requests,
            all_phcs=all_phcs,
            all_medicines=all_meds,
            selected_phc_id=phc_id,
            selected_med_id=med_id,
            selected_status=status,
            active_page="admin_provider_requests"
        )

    @app.route("/admin/provider-requests/approve/<int:request_id>", methods=["POST"])
    @admin_required
    def admin_provider_request_approve(request_id):
        """District Administrator authorizes a provider replenishment request."""
        admin_notes = request.form.get("admin_notes", "Approved for central replenishment").strip()
        db = get_db()
        req = db.execute("SELECT * FROM provider_stock_requests WHERE id = ?", (request_id,)).fetchone()
        if not req:
            flash("Replenishment request not found.", "danger")
            return redirect(url_for("admin_provider_requests"))

        db.execute(
            """
            UPDATE provider_stock_requests 
            SET status = 'approved', admin_notes = ?, reviewed_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (admin_notes, session["user_id"], request_id)
        )
        db.commit()

        log_audit("REPLENISHMENT_APPROVED", "provider_stock_requests", request_id, f"Approved request #{request_id}")
        flash(f"Replenishment request #REQ-{request_id} approved.", "success")
        return redirect(url_for("admin_provider_requests"))

    @app.route("/admin/provider-requests/reject/<int:request_id>", methods=["POST"])
    @admin_required
    def admin_provider_request_reject(request_id):
        """District Administrator rejects a provider replenishment request."""
        admin_notes = request.form.get("admin_notes", "Declined by District Administrator").strip()
        db = get_db()
        req = db.execute("SELECT * FROM provider_stock_requests WHERE id = ?", (request_id,)).fetchone()
        if not req:
            flash("Replenishment request not found.", "danger")
            return redirect(url_for("admin_provider_requests"))

        db.execute(
            """
            UPDATE provider_stock_requests 
            SET status = 'rejected', admin_notes = ?, reviewed_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (admin_notes, session["user_id"], request_id)
        )
        db.commit()

        log_audit("REPLENISHMENT_REJECTED", "provider_stock_requests", request_id, f"Rejected request #{request_id}")
        flash(f"Replenishment request #REQ-{request_id} rejected.", "warning")
        return redirect(url_for("admin_provider_requests"))

    @app.route("/admin/deliveries")
    @admin_required
    def admin_deliveries():
        """District-wide patient delivery monitoring (privacy-preserving)."""
        phc_id = request.args.get("phc_id", type=int)
        status = request.args.get("status", "").strip()

        db = get_db()
        all_phcs = db.execute("SELECT id, name FROM phcs WHERE approval_status = 'approved' ORDER BY name").fetchall()

        query = """
            SELECT 
                d.id, d.tracking_code, d.quantity, d.status, d.created_at, d.updated_at,
                m.name AS medicine_name,
                p.name AS phc_name
            FROM delivery_requests d
            JOIN medicines m ON m.id = d.medicine_id
            JOIN phcs p ON p.id = d.phc_id
            WHERE 1=1
        """
        params = []
        if phc_id:
            query += " AND d.phc_id = ?"
            params.append(phc_id)
        if status:
            query += " AND d.status = ?"
            params.append(status)

        query += " ORDER BY d.created_at DESC"
        deliveries = db.execute(query, params).fetchall()

        return render_template(
            "admin_deliveries.html",
            deliveries=deliveries,
            all_phcs=all_phcs,
            selected_phc_id=phc_id,
            selected_status=status,
            active_page="admin_deliveries"
        )

    @app.route("/admin/stock-monitor")
    @admin_required
    def admin_stock_monitor():
        """District-wide stock monitoring matrix with risk filter and predictions."""
        phc_id = request.args.get("phc_id", type=int)
        med_id = request.args.get("medicine_id", type=int)
        risk = request.args.get("risk", "").strip()

        db = get_db()
        all_phcs = db.execute("SELECT id, name FROM phcs WHERE approval_status = 'approved' ORDER BY name").fetchall()
        all_meds = db.execute("SELECT id, name FROM medicines WHERE active_status = 1 ORDER BY name").fetchall()

        query = """
            SELECT 
                i.*, 
                p.name AS phc_name, p.location AS phc_location,
                m.name AS medicine_name, m.dosage_form, m.unit
            FROM inventory i
            JOIN phcs p ON p.id = i.phc_id
            JOIN medicines m ON m.id = i.medicine_id
            WHERE p.approval_status = 'approved'
        """
        params = []
        if phc_id:
            query += " AND i.phc_id = ?"
            params.append(phc_id)
        if med_id:
            query += " AND i.medicine_id = ?"
            params.append(med_id)

        query += " ORDER BY p.name, m.name"
        rows = db.execute(query, params).fetchall()

        items = []
        for r in rows:
            pred = calculate_stock_prediction(
                r["usable_quantity"], r["safety_stock"], r["avg_daily_consumption"], r["replenishment_lead_time_days"]
            )
            d = dict(r)
            d["prediction"] = pred
            if risk:
                if pred["risk_level"].lower() == risk.lower():
                    items.append(d)
            else:
                items.append(d)

        return render_template(
            "admin_stock_monitor.html",
            items=items,
            all_phcs=all_phcs,
            all_medicines=all_meds,
            selected_phc_id=phc_id,
            selected_med_id=med_id,
            selected_risk=risk,
            active_page="stock_monitor"
        )

    @app.route("/admin/transfers")
    @admin_required
    def admin_transfers():
        """District-wide emergency transfer governance and authorizations."""
        status = request.args.get("status", "").strip()
        db = get_db()

        query = """
            SELECT 
                t.*, m.name AS medicine_name, m.dosage_form, m.unit,
                rp.name AS requesting_phc_name,
                sp.name AS supplying_phc_name
            FROM transfer_requests t
            JOIN medicines m ON m.id = t.medicine_id
            JOIN phcs rp ON rp.id = t.requesting_phc_id
            JOIN phcs sp ON sp.id = t.supplying_phc_id
        """
        params = []
        if status:
            query += " WHERE t.status = ?"
            params.append(status)

        query += " ORDER BY t.created_at DESC"
        transfers = db.execute(query, params).fetchall()

        return render_template(
            "admin_transfers.html",
            transfers=transfers,
            selected_status=status,
            active_page="admin_transfers"
        )

    @app.route("/admin/transfers/approve/<int:transfer_id>", methods=["POST"])
    @admin_required
    def admin_transfer_approve(transfer_id):
        """District Administrator authorizes an emergency transfer request."""
        approved_qty = request.form.get("approved_quantity", type=int)
        admin_notes = request.form.get("admin_notes", "").strip()

        db = get_db()
        t = db.execute("SELECT * FROM transfer_requests WHERE id = ?", (transfer_id,)).fetchone()
        if not t:
            flash("Transfer request not found.", "danger")
            return redirect(url_for("admin_transfers"))

        if t["status"] != "pending":
            flash("Only pending transfer requests can be approved.", "danger")
            return redirect(url_for("admin_transfers"))

        qty = approved_qty if approved_qty and approved_qty > 0 else t["requested_quantity"]

        sup_inv = db.execute(
            "SELECT usable_quantity, safety_stock FROM inventory WHERE phc_id = ? AND medicine_id = ?",
            (t["supplying_phc_id"], t["medicine_id"])
        ).fetchone()

        if sup_inv and (sup_inv["usable_quantity"] - qty < 0):
            flash("Approval blocked: Requested transfer would cause negative inventory at supplying clinic.", "danger")
            return redirect(url_for("admin_transfers"))

        db.execute(
            """
            UPDATE transfer_requests 
            SET status = 'approved', approved_quantity = ?, admin_notes = ?, reviewed_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (qty, admin_notes or "Approved by District Administrator", session["user_id"], transfer_id)
        )
        db.commit()

        log_audit("TRANSFER_APPROVED", "transfer_requests", transfer_id, f"Approved {qty} units for transfer #{transfer_id}. Notes: {admin_notes}")
        flash(f"Emergency transfer #{transfer_id} approved for {qty} units! Supplying PHC has been authorized for dispatch.", "success")
        return redirect(url_for("admin_transfers"))

    @app.route("/admin/transfers/reject/<int:transfer_id>", methods=["POST"])
    @admin_required
    def admin_transfer_reject(transfer_id):
        """District Administrator rejects an emergency transfer request."""
        admin_notes = request.form.get("admin_notes", "").strip()

        db = get_db()
        t = db.execute("SELECT * FROM transfer_requests WHERE id = ?", (transfer_id,)).fetchone()
        if not t:
            flash("Transfer request not found.", "danger")
            return redirect(url_for("admin_transfers"))

        if t["status"] != "pending":
            flash("Only pending transfer requests can be rejected.", "danger")
            return redirect(url_for("admin_transfers"))

        db.execute(
            """
            UPDATE transfer_requests 
            SET status = 'rejected', admin_notes = ?, reviewed_by_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (admin_notes or "Declined by District Administrator", session["user_id"], transfer_id)
        )
        db.commit()

        log_audit("TRANSFER_REJECTED", "transfer_requests", transfer_id, f"Rejected transfer #{transfer_id}. Reason: {admin_notes}")
        flash(f"Emergency transfer #{transfer_id} rejected.", "warning")
        return redirect(url_for("admin_transfers"))

    @app.route("/admin/reports")
    @admin_required
    def admin_reports():
        """District analytics, vulnerability rankings, and summary aggregates."""
        db = get_db()

        phcs = db.execute("SELECT id, name, location FROM phcs WHERE approval_status = 'approved'").fetchall()
        vulnerable_phcs = []
        for p in phcs:
            inv_rows = db.execute(
                "SELECT usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days FROM inventory WHERE phc_id = ?",
                (p["id"],)
            ).fetchall()
            crit_c = 0
            high_c = 0
            for r in inv_rows:
                pred = calculate_stock_prediction(r["usable_quantity"], r["safety_stock"], r["avg_daily_consumption"], r["replenishment_lead_time_days"])
                if pred["risk_level"] == "Critical":
                    crit_c += 1
                elif pred["risk_level"] == "High":
                    high_c += 1

            vulnerable_phcs.append({
                "id": p["id"],
                "name": p["name"],
                "location": p["location"],
                "critical_count": crit_c,
                "high_count": high_c,
                "total_alerts": crit_c + high_c
            })
        vulnerable_phcs.sort(key=lambda x: x["total_alerts"], reverse=True)

        med_rows = db.execute("SELECT id, name, category, unit FROM medicines WHERE active_status = 1").fetchall()
        top_depleted = []
        for m in med_rows:
            invs = db.execute(
                "SELECT usable_quantity, safety_stock, avg_daily_consumption, replenishment_lead_time_days FROM inventory WHERE medicine_id = ?",
                (m["id"],)
            ).fetchall()
            short_phcs = 0
            total_stock = 0
            for r in invs:
                total_stock += r["usable_quantity"]
                pred = calculate_stock_prediction(r["usable_quantity"], r["safety_stock"], r["avg_daily_consumption"], r["replenishment_lead_time_days"])
                if pred["risk_level"] in ("Critical", "High"):
                    short_phcs += 1

            if short_phcs > 0:
                top_depleted.append({
                    "name": m["name"],
                    "category": m["category"],
                    "unit": m["unit"],
                    "shortage_phcs": short_phcs,
                    "district_stock": total_stock,
                })
        top_depleted.sort(key=lambda x: x["shortage_phcs"], reverse=True)

        tot_transfers = db.execute("SELECT COUNT(*) FROM transfer_requests").fetchone()[0]
        comp_transfers = db.execute("SELECT COUNT(*) FROM transfer_requests WHERE status = 'received'").fetchone()[0]
        units_moved = db.execute("SELECT SUM(approved_quantity) FROM transfer_requests WHERE status IN ('dispatched', 'received')").fetchone()[0]
        avg_dist = db.execute("SELECT ROUND(AVG(distance_km), 1) FROM transfer_requests WHERE distance_km IS NOT NULL").fetchone()[0]

        transfer_stats = {
            "total": tot_transfers,
            "completed": comp_transfers,
            "total_units_moved": units_moved or 0,
            "avg_distance": avg_dist or "5.2"
        }

        return render_template(
            "reports.html",
            vulnerable_phcs=vulnerable_phcs,
            top_depleted=top_depleted,
            transfer_stats=transfer_stats,
            active_page="admin_reports"
        )

    @app.route("/admin/reports/export/stock")
    @admin_required
    def admin_reports_export_stock():
        """Export district-wide stock matrix as CSV."""
        db = get_db()
        rows = db.execute(
            """
            SELECT 
                p.name AS phc_name, p.location AS phc_location,
                m.name AS medicine_name, m.dosage_form, m.unit,
                i.usable_quantity, i.safety_stock, i.avg_daily_consumption,
                i.replenishment_lead_time_days, i.last_updated
            FROM inventory i
            JOIN phcs p ON p.id = i.phc_id
            JOIN medicines m ON m.id = i.medicine_id
            ORDER BY p.name, m.name
            """
        ).fetchall()

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow([
            "PHC Name", "Location", "Medicine", "Dosage Form", "Unit",
            "Usable Stock", "Safety Stock", "Daily Consumption Velocity",
            "Lead Time (Days)", "Days Remaining", "Predicted Stock-out Date", "Risk Level", "Safe Surplus", "Last Updated"
        ])

        for r in rows:
            pred = calculate_stock_prediction(r["usable_quantity"], r["safety_stock"], r["avg_daily_consumption"], r["replenishment_lead_time_days"])
            cw.writerow([
                r["phc_name"], r["phc_location"], r["medicine_name"], r["dosage_form"], r["unit"],
                r["usable_quantity"], r["safety_stock"], r["avg_daily_consumption"],
                r["replenishment_lead_time_days"],
                pred["days_remaining_display"], pred["predicted_stockout_display"], pred["risk_level"], pred["surplus_available"],
                r["last_updated"]
            ])

        response = make_response(si.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=smart_phc_stock_matrix_{datetime.now().strftime('%Y%m%d')}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    @app.route("/admin/reports/export/transfers")
    @admin_required
    def admin_reports_export_transfers():
        """Export inter-facility transfer transactions as CSV."""
        db = get_db()
        rows = db.execute(
            """
            SELECT 
                t.id, m.name AS medicine_name,
                rp.name AS requesting_phc,
                sp.name AS supplying_phc,
                t.requested_quantity, t.approved_quantity,
                t.distance_km, t.status, t.reason, t.admin_notes,
                t.created_at, t.dispatched_at, t.received_at
            FROM transfer_requests t
            JOIN medicines m ON m.id = t.medicine_id
            JOIN phcs rp ON rp.id = t.requesting_phc_id
            JOIN phcs sp ON sp.id = t.supplying_phc_id
            ORDER BY t.created_at DESC
            """
        ).fetchall()

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow([
            "Transfer ID", "Medicine", "Requesting PHC", "Supplying PHC",
            "Requested Qty", "Approved Qty", "Distance (km)", "Status",
            "Reason", "Admin Notes", "Created At", "Dispatched At", "Received At"
        ])

        for r in rows:
            cw.writerow([
                f"#TR-{r['id']}", r["medicine_name"], r["requesting_phc"], r["supplying_phc"],
                r["requested_quantity"], r["approved_quantity"] or "", r["distance_km"] or "",
                r["status"], r["reason"], r["admin_notes"] or "",
                r["created_at"], r["dispatched_at"] or "", r["received_at"] or ""
            ])

        response = make_response(si.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=smart_phc_transfers_{datetime.now().strftime('%Y%m%d')}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    @app.route("/admin/reports/export/audit")
    @admin_required
    def admin_reports_export_audit():
        """Export system audit log as CSV."""
        db = get_db()
        rows = db.execute("SELECT * FROM audit_logs ORDER BY created_at DESC").fetchall()

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(["Timestamp", "User ID", "Username", "Role", "Action", "Entity Type", "Entity ID", "Details", "IP Address"])
        for r in rows:
            cw.writerow([r["created_at"], r["user_id"], r["username"], r["role"], r["action"], r["entity_type"], r["entity_id"], r["details"], r["ip_address"]])

        response = make_response(si.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=smart_phc_audit_log_{datetime.now().strftime('%Y%m%d')}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    @app.route("/admin/audit-logs")
    @admin_required
    def admin_audit_logs():
        """Searchable audit trail view."""
        action_filter = request.args.get("action", "").strip()
        db = get_db()

        query = "SELECT * FROM audit_logs"
        params = []
        if action_filter:
            query += " WHERE action LIKE ?"
            params.append(f"%{action_filter}%")

        query += " ORDER BY created_at DESC LIMIT 150"
        logs = db.execute(query, params).fetchall()

        return render_template(
            "audit_logs.html",
            logs=logs,
            selected_action=action_filter,
            active_page="audit_logs"
        )

    # ---------------------------------------------------------
    # Error Handlers
    # ---------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("403.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("500.html"), 500

    return app

# Application Entry Point
app = create_app()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 3000)))
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"))
    args, _ = parser.parse_known_args()

    # Ensure database is initialized
    init_db()
    print(f"[*] Smart PHC System starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=True)
