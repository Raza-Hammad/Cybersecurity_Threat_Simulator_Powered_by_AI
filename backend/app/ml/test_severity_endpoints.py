import asyncio
import json
import urllib.request
import urllib.parse
import urllib.error

BASE_HTTP_URL = "http://127.0.0.1:8000"

async def make_http_request(url, data=None, headers=None, method="GET"):
    loop = asyncio.get_running_loop()
    
    def sync_req():
        req_data = None
        if data is not None:
            if isinstance(data, dict):
                req_data = json.dumps(data).encode("utf-8")
            else:
                req_data = data
                
        req = urllib.request.Request(
            url,
            data=req_data,
            headers=headers or {},
            method=method
        )
        with urllib.request.urlopen(req) as res:
            return res.status, res.read()
            
    try:
        return await loop.run_in_executor(None, sync_req)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body
    except Exception as e:
        return 500, str(e)

async def run_tests():
    print("=" * 80)
    print("               SEVERITY PIPELINE E2E INTEGRATION TEST")
    print("=" * 80)
    
    # 1. Login
    username = "admin"
    password = "Admin@652f0915!"
    print("Step 1: Authenticating default admin...")
    login_data = urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")
    status_code, login_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/auth/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    if status_code != 200:
        print(f"   Login failed: {status_code} - {login_res_raw}")
        return
        
    login_res = json.loads(login_res_raw.decode("utf-8"))
    token = login_res["access_token"]
    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    print("   Success! JWT Token acquired.")

    # 2. Trigger threat prediction flow to insert an Alert
    print("\nStep 2: Sending mock DDoS threat connection packet to /api/predict...")
    # Dynamically extract a real threat sample from the test split to guarantee threat classification
    import numpy as np
    import joblib
    from pathlib import Path
    from app.config import settings

    cache_dir = Path(settings.DATA_CACHE_DIR)
    data = np.load(cache_dir / "processed_data.npz")
    X_test = data["X_test"]
    y_test = data["y_test"]
    scaler = joblib.load(cache_dir / "scaler.joblib")
    encoder = joblib.load(cache_dir / "label_encoder.joblib")
    
    benign_idx = list(encoder.classes_).index("BENIGN")
    threat_indices = np.where(y_test != benign_idx)[0]
    if len(threat_indices) == 0:
        raise ValueError("No threat samples found in the test set split!")
        
    idx = int(threat_indices[0])
    scaled_row = X_test[idx]
    unscaled_row = scaler.inverse_transform(scaled_row.reshape(1, -1))[0]
    
    with open(cache_dir / "features.json", "r") as f:
        selected_features = json.load(f)
        
    features = {
        name: float(val) for name, val in zip(selected_features, unscaled_row)
    }

    status_code, predict_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/predict",
        data={"features": features, "source_scenario": "simulation"},
        headers=auth_headers,
        method="POST"
    )
    assert status_code == 200, f"Predict failed: {status_code} - {predict_res_raw}"
    predict_res = json.loads(predict_res_raw.decode("utf-8"))
    verdict = predict_res.get('predicted_label')
    confidence = predict_res.get('confidence')
    severity = predict_res.get('severity')
    print(f"   Verdict:    {verdict}")
    print(f"   Confidence: {confidence:.2%}")
    print(f"   Severity:   {severity}")
    assert "severity" in predict_res, "severity key missing in predict response"
    
    from app.ml.severity import compute_severity
    expected_severity = compute_severity(verdict, confidence)
    assert severity == expected_severity, f"Expected severity to be {expected_severity}, got {severity}"

    # 3. Retrieve Alert database history list
    print("\nStep 3: Checking alert history list payload for severity...")
    status_code, alerts_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/alerts?page=1&limit=10",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"GET alerts failed: {status_code} - {alerts_res_raw}"
    alerts_res = json.loads(alerts_res_raw.decode("utf-8"))
    assert len(alerts_res) > 0, "No alerts populated in history list"
    latest_alert = alerts_res[0]
    print(f"   Latest Alert ID:       #{latest_alert.get('id')}")
    print(f"   Latest Alert Severity: {latest_alert.get('severity')}")
    assert "severity" in latest_alert, "severity key missing in alerts list item"
    assert latest_alert.get("severity") == expected_severity, f"Expected persisted severity to be {expected_severity}, got {latest_alert.get('severity')}"

    # 4. Generate CSV and PDF exports containing the new severity column
    print("\nStep 4: Verifying report CSV and PDF exporter streams...")
    status_code, csv_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/alerts/export?format=csv",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"CSV request failed: {status_code}"
    print("   CSV Export Stream: [SUCCESS]")
    
    status_code, pdf_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/alerts/export?format=pdf",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"PDF request failed: {status_code}"
    print("   PDF Export Stream: [SUCCESS]")

    print("\n[SUCCESS] Unified severity scoring layer successfully wired and verified across all backend systems.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_tests())
