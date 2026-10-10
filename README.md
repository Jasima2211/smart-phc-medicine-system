# Smart PHC — Medicine Stock Prediction & Early Warning System

A healthcare supply-chain decision-support system for Primary Health Centres (PHCs) featuring **predictive stock monitoring**, **early warnings**, **distance-aware surplus matching**, **authorized emergency transfers**, and **public medicine availability searches**.

---

## 1. Problem Statement & Core Innovations

Primary Health Centres (PHCs) provide essential life-saving medicines to rural and semi-urban populations. However, patients frequently travel long distances only to discover stock-outs. The fundamental issue is twofold:
1. **Shortages are identified too late** because staff monitor static inventory numbers instead of daily consumption velocity.
2. **Nearby PHCs with surplus medicines are disconnected** and lack distance-aware matching tools to coordinate emergency transfers safely.

**Smart PHC answers three critical questions:**
* **What medicine is likely to run out, and when?** (Rule-based velocity forecasting)
* **Which nearby PHC could safely provide that medicine?** (Distance-aware surplus matching with strict safety-stock preservation)
* **Can a patient verify reported availability before travelling?** (Public availability transparency portal)

---

## 2. Technology Stack

* **Backend:** Python 3 (3.10+ / 3.11+), Flask, Flask Sessions, Session-based CSRF protection, Werkzeug password hashing.
* **Database:** SQLite3 (`instance/phc.db`) with Foreign Keys (`PRAGMA foreign_keys = ON;`), CHECK constraints, transactions, and indexes.
* **Frontend:** HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons, Vanilla JavaScript, Chart.js.
* **Testing:** pytest.

---

## 3. Project File Structure

```text
smart-phc-medicine-system/
├── app.py                   # Main Flask application and route handlers
├── config.py                # Environment configurations and risk parameters
├── database.py              # SQLite connection management & query helpers
├── schema.sql               # Relational database schema with constraints
├── seed.py                  # Idempotent fictional seed demonstration data
├── prediction.py            # Days-remaining & risk prediction engine
├── matching.py              # Haversine distance & surplus recommendation engine
├── requirements.txt         # Minimal production & test dependencies
├── .env.example             # Documented environment variable template
├── .gitignore               # Secrets, SQLite databases, and cache ignores
├── README.md                # Windows PowerShell setup & demonstration guide
├── instance/
│   └── phc.db              # SQLite database (auto-generated)
├── static/
│   ├── css/
│   │   └── style.css        # Professional healthcare UI design tokens
│   └── js/
│       └── app.js           # Client modals, search filters, and Chart.js integration
├── templates/
│   ├── base.html            # Shared layout with healthcare navigation & toasts
│   ├── landing.html         # Hero, mission, and live demonstration guide
│   ├── patient.html         # Public medicine availability search
│   ├── patient_delivery.html# Patient delivery request submission
│   ├── patient_track.html   # Privacy-preserving delivery tracking
│   ├── login.html           # Authorized portal login with demo autofill
│   ├── phc_dashboard.html   # Staff operations dashboard & risk charts
│   ├── inventory.html       # Inventory manager, modals & prediction explainers
│   ├── alerts.html          # Staff early warning alerts
│   ├── transfers.html       # Staff incoming/outgoing transfer ledger
│   ├── transfer_recommendations.html # Distance-aware surplus matching UI
│   ├── deliveries.html      # Staff delivery fulfillment
│   ├── admin_dashboard.html # District command centre & approval queue
│   ├── phcs.html            # District PHC registry & approvals
│   ├── admin_stock_monitor.html # District-wide stock surveillance matrix
│   ├── admin_transfers.html # District emergency transfer review
│   ├── reports.html         # Shortage analytics & CSV data exports
│   ├── audit_logs.html      # Immutable audit trail
│   ├── 403.html             # Access denied error template
│   ├── 404.html             # Page not found error template
│   └── 500.html             # Server error template
└── tests/
    └── test_app.py          # 21 comprehensive automated tests
```

---

## 4. Windows PowerShell Setup & Local Execution Guide

Open **Windows PowerShell** and execute the following commands step by step:

### Step 1: Open the Project Directory
```powershell
cd C:\Users\ADMIN\smart-phc-medicine-system
```

### Step 2: Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and re-run the activation script)*

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the example file to `.env`:
```powershell
Copy-Item .env.example .env
```

### Step 5: Initialize SQLite Database & Load Fictional Demonstration Data
```powershell
python seed.py
```
*Output: `[OK] Smart PHC database seeded successfully with 8 PHCs, 14 Medicines, Inventory, Transfers, and Audit Logs.`*

### Step 6: Run Automated Test Suite
Verify that all 21 acceptance tests pass:
```powershell
pytest -v
```

### Step 7: Run the Flask Application
```powershell
python app.py
```
Access the application in your web browser:
```text
http://127.0.0.1:3000   (or http://localhost:3000)
```

---

## 5. Pre-Configured Demo Accounts (For Hackathon Demonstration)

| Role | Username | Password | Scope & Assigned PHC |
| :--- | :--- | :--- | :--- |
| **District Admin** | `admin` | `Admin@123` | Full district oversight, approvals, and reports |
| **Shortage PHC Staff** | `green_valley_staff` | `Staff@123` | Green Valley PHC (Amoxicillin shortage: 1.2 days left) |
| **Surplus PHC Staff** | `sunrise_staff` | `Staff@123` | Sunrise Lake PHC (Holds 360 units safe surplus) |

*(Quick autofill buttons are built directly into the login screen for seamless live demonstrations).*

---

## 6. Complete 10-Step Hackathon Demonstration Workflow

1. **Step 1 — Public Availability Search:**
   Open `http://localhost:3000/patient/search`. Search for **Amoxicillin**. Notice Green Valley PHC displays *"Limited Stock — Call Ahead"* while Sunrise Lake displays *"In Stock"*.
2. **Step 2 — PHC Staff Log In:**
   Log in as `green_valley_staff` (`Staff@123`). The dashboard highlights **Amoxicillin 500mg** in **Critical** depletion state with **1.2 days remaining**.
3. **Step 3 — Inspect Prediction Rationale:**
   In the inventory table, click the **Info** button on Amoxicillin. The modal shows the rule-based calculation: 18 units usable / 15 daily consumption = 1.2 days buffer vs 7-day replenishment lead time.
4. **Step 4 — Algorithmic Surplus Matching:**
   Click **Surplus Matches** on Amoxicillin. The distance-aware engine evaluates all approved PHCs, ranks **Sunrise Lake PHC** as #1 (4.8 km away, 360 units safe surplus above its 60-unit safety reserve).
5. **Step 5 — Submit Emergency Transfer:**
   Submit an emergency transfer request for 100 units from Sunrise Lake.
6. **Step 6 — District Administrator Approval:**
   Log in as `admin` (`Admin@123`). Open the Command Centre queue and click **Approve** on the pending transfer.
7. **Step 7 — Supplying PHC Dispatch:**
   Log in as `sunrise_staff` (`Staff@123`). Navigate to **Emergency Transfers** and click **Dispatch Stock**. Sunrise Lake's inventory is atomically deducted from 420 to 320 units.
8. **Step 8 — Receiving PHC Confirms Receipt:**
   Log back in as `green_valley_staff` (`Staff@123`). Navigate to **Emergency Transfers** and click **Confirm Receipt**. Green Valley's inventory increases from 18 to 118 units. The Critical alert resolves automatically!
9. **Step 9 — Verify Audit Trail & Reports:**
   Log in as `admin` (`Admin@123`). View **Audit Trail** to see logged records for submission, approval, dispatch, and receipt.
10. **Step 10 — Public Patient Delivery:**
    Submit a patient delivery request on the public portal and view the live status with masked privacy protection using the tracking code.

---

## 7. Mathematical Formulas & Prediction Logic

### Days Remaining
$$\text{Days Remaining} = \frac{\text{Usable Stock}}{\text{Average Daily Consumption}}$$
*(When average daily consumption is zero or unrecorded, the system explicitly displays "Insufficient consumption data" rather than inventing a date).*

### Predicted Stock-out Date
$$\text{Stock-out Date} = \text{Today} + \lfloor \text{Days Remaining} \rfloor$$

### Risk Classification Thresholds
* **Critical:** $\text{Days Remaining} \le \text{Lead Time (Days)}$ OR $\le 3.0 \text{ days}$ OR $\text{Usable Stock} = 0$.
* **High:** $\text{Days Remaining} \le \text{Lead Time} \times 1.5$ OR $\text{Usable Stock} \le \text{Safety Stock} \times 0.5$.
* **Medium:** $\text{Days Remaining} \le \text{Lead Time} \times 2.5$ OR $\text{Usable Stock} < \text{Safety Stock}$.
* **Safe:** Stock exceeds medium threshold and provides comfortable buffer.

### Safe Surplus Preservation
$$\text{Safe Surplus} = \max(0, \text{Supplying Usable Stock} - \text{Supplying Safety Stock})$$
*(A supplying clinic is never permitted to transfer medicine that would deplete its own local safety stock).*

### Distance Calculation (Haversine Formula)
$$a = \sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)$$
$$d = 2 R \cdot \text{atan2}(\sqrt{a}, \sqrt{1-a})$$
Where $R = 6371\text{ km}$.

---

## 8. Resetting the Demo Database

To reset the database back to clean demonstration state at any time:
```powershell
python seed.py
```

## 9. Git Commit & Repository Push

The `.gitignore` is pre-configured to ensure no secrets (`.env`), SQLite databases (`instance/phc.db`), or virtual environments (`venv/`) are committed.
```powershell
git status
git add .
git commit -m "Complete Smart PHC medicine stock prediction and early warning system"
git push origin main
```
