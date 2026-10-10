import math

def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two points on the Earth (in km)
    using the Haversine formula. Returns float km or None if coordinates are missing.
    """
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None
    try:
        lat1, lon1, lat2, lon2 = float(lat1), float(lon1), float(lat2), float(lon2)
    except (ValueError, TypeError):
        return None

    # Earth radius in kilometers
    r = 6371.0

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return round(r * c, 2)

def find_surplus_matches(conn, requesting_phc_id, medicine_id, requested_qty=None):
    """
    Identify nearby approved PHCs with safe surplus of the required medicine.
    
    Rules:
      1. Exclude the requesting PHC.
      2. Must be approved and active PHC.
      3. Surplus = usable_quantity - safety_stock. Only candidates with surplus > 0 considered.
      4. Calculates Haversine distance if coordinates are present.
      5. Evaluates supplier buffer after hypothetical transfer to ensure supplier safety.
      6. Ranks candidates by optimal combination of distance and surplus availability.
    """
    # 1. Fetch requesting PHC coordinates & details
    req_cur = conn.execute(
        "SELECT id, name, latitude, longitude FROM phcs WHERE id = ?",
        (requesting_phc_id,)
    )
    req_phc = req_cur.fetchone()
    if not req_phc:
        return []

    req_lat = req_phc["latitude"]
    req_lon = req_phc["longitude"]

    # 2. Query all other approved, active PHCs stocking this medicine
    query = """
        SELECT 
            p.id AS phc_id,
            p.name AS phc_name,
            p.location AS phc_location,
            p.contact_phone,
            p.latitude,
            p.longitude,
            i.usable_quantity,
            i.safety_stock,
            i.avg_daily_consumption,
            i.replenishment_lead_time_days
        FROM inventory i
        JOIN phcs p ON p.id = i.phc_id
        WHERE i.medicine_id = ?
          AND p.id != ?
          AND p.approval_status = 'approved'
          AND p.active_status = 1
    """
    rows = conn.execute(query, (medicine_id, requesting_phc_id)).fetchall()

    candidates = []
    target_qty = int(requested_qty) if requested_qty and requested_qty > 0 else 50

    for row in rows:
        usable = row["usable_quantity"]
        safety = row["safety_stock"]
        avg_usage = row["avg_daily_consumption"] or 0.0
        lead_time = row["replenishment_lead_time_days"] or 7
        surplus = max(0, usable - safety)

        # Skip PHCs with no surplus to spare beyond their safety stock
        if surplus <= 0:
            continue

        # Distance calculation
        dist_km = haversine_distance(req_lat, req_lon, row["latitude"], row["longitude"])

        # Recommended quantity they can safely supply
        recommended_transfer_qty = min(target_qty, surplus)
        remaining_stock_after = usable - recommended_transfer_qty

        # Supplier health after hypothetical transfer
        if avg_usage > 0:
            supplier_days_after = round(remaining_stock_after / avg_usage, 1)
        else:
            supplier_days_after = None

        # Build recommendation rationale
        dist_text = f"{dist_km} km away" if dist_km is not None else "distance not mapped"
        if recommended_transfer_qty >= target_qty:
            rationale = (
                f"Can fully supply requested {target_qty} units. Holds {surplus} surplus above safety reserve ({safety}). "
                f"Located {dist_text}. Supplying leaves {remaining_stock_after} units intact."
            )
        else:
            rationale = (
                f"Can partially supply {recommended_transfer_qty} units (maximum safe surplus). "
                f"Located {dist_text}. Leaves safety reserve ({safety}) fully protected."
            )

        # Ranking score: closer is better, higher surplus is better
        # Score = (surplus / target_qty) * 50 - (dist_km if dist_km else 20) * 1.5
        dist_penalty = (dist_km * 1.2) if dist_km is not None else 30.0
        score = (min(surplus, target_qty * 2) * 2.0) - dist_penalty

        candidates.append({
            "phc_id": row["phc_id"],
            "phc_name": row["phc_name"],
            "phc_location": row["phc_location"],
            "contact_phone": row["contact_phone"],
            "usable_quantity": usable,
            "safety_stock": safety,
            "surplus_available": surplus,
            "distance_km": dist_km,
            "distance_display": f"{dist_km:.1f} km" if dist_km is not None else "Unknown distance",
            "recommended_transfer_qty": recommended_transfer_qty,
            "remaining_stock_after": remaining_stock_after,
            "supplier_days_after": supplier_days_after,
            "rationale": rationale,
            "score": round(score, 2),
        })

    # Sort descending by score (best match first)
    candidates.sort(key=lambda c: c["score"], reverse=True)
    return candidates
