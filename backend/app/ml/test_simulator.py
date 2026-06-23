import asyncio
import json
import urllib.request
import urllib.parse
import urllib.error
import websockets

# Setup connection parameters
BASE_HTTP_URL = "http://127.0.0.1:8000"
BASE_WS_URL = "ws://127.0.0.1:8000"

async def read_websocket_messages(websocket):
    """Listens for and counts incoming telemetry messages."""
    detections_received = 0
    heartbeats_received = 0
    try:
        async for message in websocket:
            data = json.loads(message)
            event_type = data.get("event")
            if event_type == "detection":
                detections_received += 1
                det = data.get("data", {})
                print(f"   [Telemetry Receive #{detections_received}] Label: {det.get('predicted_label')} | Conf: {det.get('confidence'):.4f} | Tier: {det.get('tier')}")
            elif event_type == "heartbeat":
                heartbeats_received += 1
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"[WS ERROR] Connection reader exception: {e}")
    return detections_received, heartbeats_received

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

async def run_simulator_test():
    print("=" * 80)
    print("                 MID-EVAL DATA-REPLAY SIMULATOR VERIFIER")
    print("=" * 80)
    
    # 1. Authenticate to get JWT token
    username = "analyst_jack"
    password = "securepassword123"
    print("Step 1: Authenticating analyst jack...")
    
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

    # 2. Check initial simulator status
    print("\nStep 2: Checking initial simulator status...")
    status_code, status_res = await make_http_request(
        f"{BASE_HTTP_URL}/api/simulate/status",
        headers=auth_headers,
        method="GET"
    )
    if status_code != 200:
        print(f"   Failed to get simulator status: {status_code} - {status_res}")
        return
    print(f"   Status: Running={status_res.get('running')}, Preset Scenarios={status_res.get('scenario')}")

    # 3. Connect to WebSocket `/ws/live`
    print(f"\nStep 3: Connecting to WebSocket at {BASE_WS_URL}/ws/live ...")
    try:
        async with websockets.connect(f"{BASE_WS_URL}/ws/live", origin="http://localhost:5173") as websocket:
            print("   Connected! Spawning telemetry listener...")
            
            # Start background listener task
            listener_task = asyncio.create_task(read_websocket_messages(websocket))
            
            # 4. Start `ddos_storm` simulation at 5 packets/sec for 3 seconds
            print("\nStep 4: Starting 'ddos_storm' simulation (5 packets/sec, 3s duration)...")
            start_payload = {
                "scenario": "ddos_storm",
                "rate": 5,
                "duration_seconds": 3
            }
            status_code, start_res = await make_http_request(
                f"{BASE_HTTP_URL}/api/simulate/start",
                data=start_payload,
                headers=auth_headers,
                method="POST"
            )
            if status_code != 200:
                print(f"   Failed to start simulation: {status_code} - {start_res}")
                listener_task.cancel()
                return
            print(f"   Response: {start_res}")
            
            # Wait 1.5 seconds and query status mid-run
            await asyncio.sleep(1.5)
            print("\nStep 5: Inspecting simulator status mid-run...")
            status_code, running_status = await make_http_request(
                f"{BASE_HTTP_URL}/api/simulate/status",
                headers=auth_headers,
                method="GET"
            )
            if status_code == 200:
                print(f"   Mid-run stats: Running={running_status.get('running')}, Packets Sent={running_status.get('packets_sent')}, Attacks Detected={running_status.get('attacks_detected')}, Tier Breakdown={running_status.get('tier_breakdown')}")
                
            # Wait another 2.5 seconds for completion
            print("\nWaiting for simulation scenario to complete...")
            await asyncio.sleep(2.5)
            
            # 5. Check post-run simulator status
            print("\nStep 6: Verifying final simulator status (should be completed)...")
            status_code, final_status = await make_http_request(
                f"{BASE_HTTP_URL}/api/simulate/status",
                headers=auth_headers,
                method="GET"
            )
            if status_code == 200:
                print(f"   Final stats: Running={final_status.get('running')}, Total Packets={final_status.get('packets_sent')}, Total Attacks={final_status.get('attacks_detected')}, Tier Breakdown={final_status.get('tier_breakdown')}")
            
            # Clean up WS listener
            print("\nShutting down WS listener...")
            listener_task.cancel()
            packets_received, heartbeats = await listener_task
            print(f"   WebSocket telemetry summary: Received {packets_received} detections, {heartbeats} heartbeats.")
            
            # 6. Verify SQLite database alerts persistence
            print("\nStep 7: Verifying alerts persisted to SQLite database...")
            alerts_url = f"{BASE_HTTP_URL}/api/alerts?page=1&limit=5"
            status_code, alerts_res = await make_http_request(
                alerts_url,
                headers=auth_headers,
                method="GET"
            )
            if status_code == 200:
                print(f"   Success! Retreived {len(alerts_res)} recent database alerts:")
                for alert in alerts_res:
                    print(f"     - Alert #{alert.get('id')}: {alert.get('predicted_label')} (Confidence: {alert.get('confidence'):.4f}, Scenario: {alert.get('source_scenario')})")
            else:
                print(f"   Failed to retrieve SQLite alerts: {status_code} - {alerts_res}")

    except Exception as e:
        print(f"WebSocket client connection or setup failed: {e}")
        
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_simulator_test())
