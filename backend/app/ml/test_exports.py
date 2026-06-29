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

async def run_export_tests():
    print("=" * 80)
    print("                 SMOTE & EXPORTS TELEMETRY VERIFIER")
    print("=" * 80)
    
    # 1. Login
    username = "analyst_export"
    password = "securepassword321"
    print("Step 1: Authenticating analyst_export...")
    
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
        "Authorization": f"Bearer {token}"
    }
    print("   Success! JWT Token acquired.")

    # 2. Test SMOTE Stats
    print("\nStep 2: Querying SMOTE statistics...")
    status_code, smote_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/data/smote-stats",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"SMOTE request failed: {status_code}"
    smote_res = json.loads(smote_res_raw.decode("utf-8"))
    print("   Response Keys:", list(smote_res.keys()))
    assert "before_smote" in smote_res, "before_smote missing"
    assert "after_smote" in smote_res, "after_smote missing"
    print("   SMOTE stats verification: [SUCCESS]")

    # 3. Test CSV Export
    print("\nStep 3: Querying CSV Alert Report Export...")
    status_code, csv_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/alerts/export?format=csv",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"CSV request failed: {status_code}"
    csv_text = csv_res_raw.decode("utf-8")
    first_line = csv_text.split("\n")[0]
    print(f"   First Line: {first_line.strip()}")
    assert "--- AI SOC TELEMETRY EXPORT REPORT ---" in first_line, "Unexpected CSV header"
    print("   CSV Export verification: [SUCCESS]")

    # 4. Test PDF Export
    print("\nStep 4: Querying PDF Alert Report Export...")
    status_code, pdf_res_raw = await make_http_request(
        f"{BASE_HTTP_URL}/api/alerts/export?format=pdf",
        headers=auth_headers,
        method="GET"
    )
    assert status_code == 200, f"PDF request failed: {status_code}"
    pdf_magic = pdf_res_raw[:4]
    print(f"   PDF Magic Bytes: {pdf_magic}")
    assert pdf_magic == b"%PDF", f"Expected PDF format, got {pdf_magic}"
    print("   PDF Export verification: [SUCCESS]")

    print("\n[SUCCESS] SMOTE and export endpoints verified successfully.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_export_tests())
