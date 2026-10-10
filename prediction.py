import math
from datetime import datetime, timedelta

def calculate_stock_prediction(usable_stock, safety_stock, avg_daily_consumption, lead_time_days=7):
    """
    Core Rule-Based Stock Prediction & Risk Assessment Engine.
    
    Formulas:
      - days_remaining = usable_stock / avg_daily_consumption (when consumption > 0)
      - predicted_stockout_date = today + floor(days_remaining)
      - risk_level = Critical | High | Medium | Safe
      - surplus = max(0, usable_stock - safety_stock)
    """
    usable_stock = max(0, int(usable_stock or 0))
    safety_stock = max(0, int(safety_stock or 0))
    lead_time_days = max(1, int(lead_time_days or 7))
    avg_daily_consumption = float(avg_daily_consumption or 0.0)

    # 1. Zero Usable Stock
    if usable_stock == 0:
        return {
            "usable_stock": 0,
            "safety_stock": safety_stock,
            "avg_daily_consumption": avg_daily_consumption,
            "lead_time_days": lead_time_days,
            "days_remaining": 0.0,
            "days_remaining_display": "0.0 days (Depleted)",
            "predicted_stockout_date": datetime.now().strftime("%Y-%m-%d"),
            "predicted_stockout_display": "Immediate (Already Stocked Out)",
            "risk_level": "Critical",
            "risk_badge_class": "danger",
            "explanation": f"Stock is completely exhausted (0 units). Replenishment lead time is {lead_time_days} days.",
            "surplus_available": 0,
            "alert_type": "zero_stock",
        }

    # 2. Insufficient Consumption Data
    if avg_daily_consumption <= 0:
        if usable_stock < safety_stock:
            risk = "Medium"
            badge = "warning"
            explanation = f"Stock ({usable_stock}) is below safety threshold ({safety_stock}). Insufficient daily consumption data to forecast depletion date."
            alert_type = "below_safety_stock"
        else:
            risk = "Safe"
            badge = "success"
            explanation = f"Stock ({usable_stock}) is above safety threshold ({safety_stock}). No active daily consumption rate recorded."
            alert_type = None

        return {
            "usable_stock": usable_stock,
            "safety_stock": safety_stock,
            "avg_daily_consumption": 0.0,
            "lead_time_days": lead_time_days,
            "days_remaining": None,
            "days_remaining_display": "Insufficient consumption data",
            "predicted_stockout_date": None,
            "predicted_stockout_display": "Insufficient consumption data",
            "risk_level": risk,
            "risk_badge_class": badge,
            "explanation": explanation,
            "surplus_available": max(0, usable_stock - safety_stock),
            "alert_type": alert_type,
        }

    # 3. Valid Consumption Calculation
    days_remaining = round(usable_stock / avg_daily_consumption, 1)
    target_date = datetime.now() + timedelta(days=math.floor(days_remaining))
    predicted_stockout_date = target_date.strftime("%Y-%m-%d")
    predicted_stockout_display = target_date.strftime("%b %d, %Y")

    # Risk Classification Rules
    # Critical: days_remaining <= lead_time OR days_remaining <= 3.0
    if days_remaining <= lead_time_days or days_remaining <= 3.0:
        risk_level = "Critical"
        risk_badge_class = "danger"
        alert_type = "lead_time_breach" if days_remaining <= lead_time_days else "stockout_imminent"
        explanation = (
            f"CRITICAL WARNING: Stock will run out in {days_remaining:.1f} days ({predicted_stockout_display}), "
            f"which is within or below the replenishment lead time of {lead_time_days} days. "
            f"Emergency stock transfer or priority reorder required immediately."
        )
    # High: days_remaining <= lead_time * 1.5 OR usable_stock <= safety_stock * 0.5
    elif days_remaining <= (lead_time_days * 1.5) or usable_stock <= (safety_stock * 0.5):
        risk_level = "High"
        risk_badge_class = "warning"
        alert_type = "stockout_imminent"
        explanation = (
            f"HIGH RISK: Stock will deplete in {days_remaining:.1f} days ({predicted_stockout_display}). "
            f"Buffer is closely approaching the {lead_time_days}-day replenishment window."
        )
    # Medium: days_remaining <= lead_time * 2.5 OR usable_stock < safety_stock
    elif days_remaining <= (lead_time_days * 2.5) or usable_stock < safety_stock:
        risk_level = "Medium"
        risk_badge_class = "info"
        alert_type = "below_safety_stock"
        explanation = (
            f"MEDIUM ADVISORY: Stock ({usable_stock} units) has dropped below safety stock ({safety_stock} units) "
            f"or will reach warning levels in {days_remaining:.1f} days."
        )
    # Safe
    else:
        risk_level = "Safe"
        risk_badge_class = "success"
        alert_type = None
        explanation = (
            f"SAFE: Adequate stock for {days_remaining:.1f} days at current consumption rate of "
            f"{avg_daily_consumption:.1f} units/day. Well exceeds {lead_time_days}-day lead time."
        )

    surplus = max(0, usable_stock - safety_stock)

    return {
        "usable_stock": usable_stock,
        "safety_stock": safety_stock,
        "avg_daily_consumption": avg_daily_consumption,
        "lead_time_days": lead_time_days,
        "days_remaining": days_remaining,
        "days_remaining_display": f"{days_remaining:.1f} days",
        "predicted_stockout_date": predicted_stockout_date,
        "predicted_stockout_display": predicted_stockout_display,
        "risk_level": risk_level,
        "risk_badge_class": risk_badge_class,
        "explanation": explanation,
        "surplus_available": surplus,
        "alert_type": alert_type,
    }

def sync_inventory_alerts(conn, phc_id, medicine_id, prediction):
    """
    Synchronize the alerts table for a given PHC and medicine based on calculated prediction.
    Prevents duplicate open alerts by updating existing open alerts or resolving them when safe.
    """
    risk_level = prediction["risk_level"]
    alert_type = prediction.get("alert_type") or "stockout_imminent"
    message = prediction["explanation"]
    pred_date = prediction.get("predicted_stockout_date")

    # Check for existing open alerts for this phc and medicine
    cur = conn.execute(
        "SELECT id, risk_level, status FROM alerts WHERE phc_id = ? AND medicine_id = ? AND status = 'open'",
        (phc_id, medicine_id)
    )
    existing_alert = cur.fetchone()

    if risk_level in ("Critical", "High", "Medium"):
        if existing_alert:
            # Update existing open alert to avoid duplicates
            conn.execute(
                """
                UPDATE alerts 
                SET alert_type = ?, risk_level = ?, message = ?, predicted_stockout_date = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (alert_type, risk_level, message, pred_date, existing_alert["id"])
            )
        else:
            # Insert new open alert
            conn.execute(
                """
                INSERT INTO alerts (phc_id, medicine_id, alert_type, risk_level, message, predicted_stockout_date, status)
                VALUES (?, ?, ?, ?, ?, ?, 'open')
                """,
                (phc_id, medicine_id, alert_type, risk_level, message, pred_date)
            )
    else:
        # Risk is Safe: resolve any open alerts for this medicine at this PHC
        if existing_alert:
            conn.execute(
                "UPDATE alerts SET status = 'resolved', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (existing_alert["id"],)
            )
