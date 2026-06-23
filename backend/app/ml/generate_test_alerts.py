import json
import numpy as np
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
import joblib
from app.config import settings

def run_integration_test():
    print("=" * 70)
    print("        END-TO-END BACKEND API INTEGRATION & JWT AUTH VERIFIER")
    print("=" * 70)
    
    # 1. Load scaler, selected features
    cache_dir = Path(settings.DATA_CACHE_DIR)
    scaler_path = cache_dir / "scaler.joblib"
    features_path = cache_dir / "features.json"
    npz_path = cache_dir / "processed_data.npz"
    
    if not (scaler_path.exists() and features_path.exists() and npz_path.exists()):
        print("Error: Cached data files are missing. Run prepare_data first.")
        return
        
    scaler = joblib.load(scaler_path)
    with open(features_path, "r") as f:
        selected_features = json.load(f)
        
    print("Loading test dataset splits from cache...")
    with np.load(npz_path) as data:
        X_test = data["X_test"]
        y_test = data["y_test"]
        
    # Initialize CascadeDetector singleton logic to fetch labels
    from app.ml.cascade import get_detector
    detector = get_detector()
    
    # Inspect test samples to find threat samples
    threat_indices = []
    for idx in range(min(5000, len(y_test))):
        true_encoded = y_test[idx]
        true_label = detector.label_encoder.inverse_transform([true_encoded])[0]
        if true_label != "BENIGN":
            threat_indices.append((idx, true_label))
            if len(threat_indices) >= 2:
                break
                
    if not threat_indices:
        print("Could not find any non-BENIGN threat samples in the first 5000 test set elements.")
        return
        
    print(f"Found threat samples in test set: {threat_indices}")
    
    # Unscale threat samples
    indices_to_test = [item[0] for item in threat_indices]
    unscaled_threats = scaler.inverse_transform(X_test[indices_to_test])
    
    # Setup connection parameters
    base_url = "http://127.0.0.1:8000"
    
    # 2. Register a new user
    username = "analyst_jack"
    password = "securepassword123"
    print(f"\n1. Registering new analyst: '{username}'...")
    
    register_url = f"{base_url}/api/auth/register"
    register_data = {
        "username": username,
        "password": password
    }
    
    try:
        req = urllib.request.Request(
            register_url,
            data=json.dumps(register_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as res:
            res_body = json.loads(res.read().decode("utf-8"))
            print(f"   Success! User registered: {res_body}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        if "Username already registered" in body:
            print("   Analyst jack is already registered. Proceeding to login...")
        else:
            print(f"   Registration failed: {e.code} - {body}")
            return
    except Exception as e:
        print(f"   Connection failed: {e}")
        return
        
    # 3. Log in to get JWT token
    print(f"\n2. Logging in as '{username}' to retrieve JWT...")
    login_url = f"{base_url}/api/auth/login"
    login_data = urllib.parse.urlencode({
        "username": username,
        "password": password
    }).encode("utf-8")
    
    token = None
    try:
        req = urllib.request.Request(
            login_url,
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST"
        )
        with urllib.request.urlopen(req) as res:
            res_body = json.loads(res.read().decode("utf-8"))
            token = res_body["access_token"]
            print(f"   Success! JWT Token acquired: {token[:30]}...")
    except Exception as e:
        print(f"   Login failed: {e}")
        return
        
    # 4. Send prediction requests for threat samples
    print("\n3. Sending threat flows to '/api/predict'...")
    predict_url = f"{base_url}/api/predict"
    
    scenario_name = "botnet_bruteforce_scenario"
    for idx, (test_idx, true_label) in enumerate(threat_indices):
        flow_dict = dict(zip(selected_features, unscaled_threats[idx]))
        payload = {
            "features": flow_dict,
            "source_scenario": scenario_name
        }
        
        try:
            req = urllib.request.Request(
                predict_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}"
                },
                method="POST"
            )
            with urllib.request.urlopen(req) as res:
                res_body = json.loads(res.read().decode("utf-8"))
                predicted = res_body["predicted_label"]
                conf = res_body["confidence"]
                tier = res_body["tier"]
                alert_id = res_body.get("alert_id")
                
                print(f"   - Sent {true_label} Sample | Predicted: {predicted} ({conf:.4f}) | resolved at Tier {tier}")
                if alert_id:
                    print(f"     [ALERT CREATED] ID: {alert_id} | Scenario: {res_body.get('source_scenario')}")
        except Exception as e:
            print(f"   Prediction request failed: {e}")
            
    # 5. Fetch alerts using JWT Token
    print("\n4. Fetching active alerts using JWT token...")
    alerts_url = f"{base_url}/api/alerts"
    
    try:
        req = urllib.request.Request(
            alerts_url,
            headers={"Authorization": f"Bearer {token}"},
            method="GET"
        )
        with urllib.request.urlopen(req) as res:
            alerts = json.loads(res.read().decode("utf-8"))
            print(f"   Success! Found {len(alerts)} alerts in SQLite database:")
            for alert in alerts[:5]:
                print(f"     - Alert #{alert['id']}: {alert['predicted_label']} | Tier: {alert['tier']} | Scenario: {alert['source_scenario']}")
    except Exception as e:
        print(f"   Failed to fetch alerts: {e}")
        
    # 6. Fetch filtered alerts (filter by attack type)
    if threat_indices:
        target_attack = threat_indices[0][1]
        print(f"\n5. Fetching alerts filtered by attack_type='{target_attack}'...")
        query_params = urllib.parse.urlencode({"attack_type": target_attack})
        filtered_url = f"{alerts_url}?{query_params}"
        
        try:
            req = urllib.request.Request(
                filtered_url,
                headers={"Authorization": f"Bearer {token}"},
                method="GET"
            )
            with urllib.request.urlopen(req) as res:
                filtered_alerts = json.loads(res.read().decode("utf-8"))
                print(f"   Success! Found {len(filtered_alerts)} filtered alerts:")
                for alert in filtered_alerts:
                    print(f"     - Alert #{alert['id']}: {alert['predicted_label']} | Scenario: {alert['source_scenario']}")
        except Exception as e:
            print(f"   Failed to fetch filtered alerts: {e}")
            
    # 7. Fetch statistics
    print("\n6. Fetching alert statistics from '/api/alerts/stats'...")
    stats_url = f"{base_url}/api/alerts/stats"
    
    try:
        req = urllib.request.Request(
            stats_url,
            headers={"Authorization": f"Bearer {token}"},
            method="GET"
        )
        with urllib.request.urlopen(req) as res:
            stats = json.loads(res.read().decode("utf-8"))
            print("   Success! Alert statistics:")
            print(f"     - Grouped by Attack Type: {stats.get('by_attack_type')}")
            print(f"     - Grouped by Tier:        {stats.get('by_tier')}")
    except Exception as e:
        print(f"   Failed to fetch stats: {e}")
        
    # 8. Test simulation endpoint
    print("\n7. Fetching simulation engine status from '/api/simulate'...")
    simulate_url = f"{base_url}/api/simulate"
    
    try:
        req = urllib.request.Request(
            simulate_url,
            headers={"Authorization": f"Bearer {token}"},
            method="GET"
        )
        with urllib.request.urlopen(req) as res:
            sim_status = json.loads(res.read().decode("utf-8"))
            print("   Success! Simulation Status:")
            print(f"     - Engine Status: {sim_status.get('status')}")
            print(f"     - Triggered By:  {sim_status.get('triggered_by')} (Role: {sim_status.get('analyst_role')})")
    except Exception as e:
        print(f"   Failed to fetch simulation status: {e}")
        
    print("=" * 70)

if __name__ == "__main__":
    run_integration_test()
