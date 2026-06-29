import asyncio
import json
import urllib.request
import urllib.parse
import urllib.error

# Setup connection parameters
BASE_HTTP_URL = "http://127.0.0.1:8000"

async def make_http_request(url, data=None, headers=None, method="GET"):
    """Helper to perform synchronous-looking HTTP requests inside async loop."""
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
            return res.status, json.loads(res.read().decode("utf-8"))
            
    try:
        return await loop.run_in_executor(None, sync_req)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body
    except Exception as e:
        return 500, str(e)

async def run_xai_test():
    print("=" * 80)
    print("                 EXPLAINABLE AI (XAI) ATTRIBUTION VERIFIER")
    print("=" * 80)
    
    # 1. Authenticate to get JWT token
    username = "analyst_sam"
    password = "securepassword123"
    print("Step 1: Authenticating analyst sam...")
    
    # Try registration first in case the DB is fresh
    status_code, body = await make_http_request(
        f"{BASE_HTTP_URL}/api/auth/register",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    if status_code == 201:
        print("   Analyst registered successfully.")
    elif status_code == 400 and "Username already registered" in str(body):
        print("   Analyst already exists, proceeding to login.")
    else:
        print(f"   Registration error: {status_code} - {body}")
        return

    # Login to retrieve token
    login_data = urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")
    status_code, login_res = await make_http_request(
        f"{BASE_HTTP_URL}/api/auth/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    if status_code != 200:
        print(f"   Login failed: {status_code} - {login_res}")
        return
        
    token = login_res["access_token"]
    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    print("   Success! JWT Token acquired.")

    # 2. Prepare a sample packet flow features payload matching 30 selected features
    print("\nStep 2: Preparing mock threat packet flow (DDoS scenario features)...")
    mock_features = {
        "Max Packet Length": 435.0,
        "Packet Length Variance": 2240.5,
        "Packet Length Std": 47.33,
        "Avg Bwd Segment Size": 128.5,
        "Bwd Packet Length Max": 350.0,
        "Total Length of Bwd Packets": 1000.0,
        "Subflow Fwd Bytes": 150.0,
        "Subflow Bwd Bytes": 1000.0,
        "Average Packet Size": 95.0,
        "Total Length of Fwd Packets": 150.0,
        "Fwd Packet Length Max": 150.0,
        "Init_Win_bytes_forward": 29200.0,
        "Total Fwd Packets": 3.0,
        "Bwd Packet Length Std": 20.0,
        "Packet Length Mean": 95.0,
        "Avg Fwd Segment Size": 50.0,
        "Fwd Packet Length Mean": 50.0,
        "Bwd Packet Length Mean": 125.0,
        "Flow Bytes/s": 4500.0,
        "Fwd Header Length.1": 60.0,
        "Bwd Packets/s": 15.0,
        "Bwd Header Length": 60.0,
        "Fwd IAT Max": 100000.0,
        "PSH Flag Count": 1.0,
        "Idle Min": 0.0,
        "Init_Win_bytes_backward": 29200.0,
        "Fwd Header Length": 60.0,
        "Flow IAT Max": 100000.0,
        "act_data_pkt_fwd": 2.0,
        "Fwd IAT Std": 25000.0
    }

    # 3. Call POST /api/xai/explain
    print("\nStep 3: Querying secure XAI explain endpoint...")
    payload = {
        "predicted_label": "DDoS",
        "confidence": 0.985,
        "tier": 1,
        "features": mock_features
    }
    
    status_code, res = await make_http_request(
        f"{BASE_HTTP_URL}/api/xai/explain",
        data=payload,
        headers=auth_headers,
        method="POST"
    )
    
    if status_code != 200:
        print(f"   XAI Request failed: {status_code} - {res}")
        return
        
    print(f"\nStep 4: Asserting response format correctness...")
    print(f"   Verdict: {res.get('verdict')}")
    print(f"   Confidence: {res.get('confidence')}")
    print(f"   Deciding ML Tier Name: {res.get('tier_name')}")
    
    print("\n   Top Attributing Features with Benign Averages:")
    top_features = res.get("top_features", [])
    for feat in top_features:
        name = feat.get("feature")
        val = feat.get("value")
        benign_avg = feat.get("benign_avg")
        importance = feat.get("importance")
        print(f"     - {name}: Value = {val:.2f} | Benign Avg = {benign_avg:.2f} | RF Importance = {importance:.4f}")
        assert "benign_avg" in feat, "benign_avg is missing from feature dict!"

    print("\n   Plain-English AI Explanation:")
    explanation = res.get("explanation")
    print(f"     \"{explanation}\"")
    
    assert explanation, "explanation string is missing or empty!"
    assert len(top_features) >= 3, "should return at least 3 attributing features"
    
    print("\n[SUCCESS] All Explainable AI (XAI) validations passed successfully.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_xai_test())
