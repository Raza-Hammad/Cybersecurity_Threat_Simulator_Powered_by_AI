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
            return res.status, json.loads(res.read().decode("utf-8"))
            
    try:
        return await loop.run_in_executor(None, sync_req)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return e.code, body
    except Exception as e:
        return 500, str(e)

async def run_chat_test():
    print("=" * 80)
    print("                 AI SOC ASSISTANT TELEMETRY VERIFIER")
    print("=" * 80)
    
    # 1. Login/Authentication
    username = "analyst_chat"
    password = "securepassword321"
    print("Step 1: Authenticating analyst_chat...")
    
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

    # 2. Test Rule-Based Q&A Mapping
    print("\nStep 2: Testing Rule-Based Q&A Mapping...")
    status_code, res = await make_http_request(
        f"{BASE_HTTP_URL}/api/chat",
        data={"message": "how does the cascade work?"},
        headers=auth_headers,
        method="POST"
    )
    assert status_code == 200, f"Q&A request failed: {status_code}"
    print(f"   Query: \"how does the cascade work?\"")
    print(f"   Response Source: {res.get('source')}")
    print(f"   Answer: \"{res.get('answer').replace('\u03bc', 'u')}\"")
    assert res.get("source") == "Rule-Based", f"Expected Rule-Based source, got {res.get('source')}"

    # 3. Test Explain Last Alert Trigger
    print("\nStep 3: Testing 'explain the last alert' feature...")
    status_code, res = await make_http_request(
        f"{BASE_HTTP_URL}/api/chat",
        data={"message": "can you explain the latest alert?"},
        headers=auth_headers,
        method="POST"
    )
    assert status_code == 200, f"Last alert request failed: {status_code}"
    print(f"   Query: \"can you explain the latest alert?\"")
    print(f"   Response Source: {res.get('source')}")
    print(f"   Answer:\n   {res.get('answer').replace('\u03bc', 'u')}")
    assert "latest logged alert" in res.get("answer").lower() or "no alerts have been recorded" in res.get("answer").lower(), "Should output alert context details."

    print("\n[SUCCESS] AI Chat Assistant backend endpoints verified successfully.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_chat_test())
