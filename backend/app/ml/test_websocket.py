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
    """Listens for and prints incoming WebSocket events in real-time."""
    try:
        async for message in websocket:
            data = json.loads(message)
            event_type = data.get("event")
            timestamp = data.get("timestamp")
            print(f"\n[WS EVENT] Received '{event_type}' at {timestamp}")
            if event_type == "detection":
                det = data.get("data", {})
                print(f"   Label:      {det.get('predicted_label')}")
                print(f"   Confidence: {det.get('confidence'):.4f}")
                print(f"   Tier:       {det.get('tier_name')} (Tier {det.get('tier')})")
                if "alert_id" in det:
                    print(f"   Alert ID:   {det.get('alert_id')}")
                print("   Top Features:")
                for i, feat in enumerate(det.get("top_features", [])[:3]):
                    print(f"     - {feat['feature']}: {feat['value']:.2f} (importance={feat['importance']:.4f})")
            elif event_type == "heartbeat":
                print("   Heartbeat ping received successfully.")
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"[WS ERROR] Connection reader exception: {e}")

async def test_websocket_flow():
    print("=" * 80)
    print("                WEBSOCKET LIVE TELEMETRY & HEARTBEAT VERIFIER")
    print("=" * 80)
    
    # 1. Register / Login Jack to get JWT token
    username = "analyst_jack"
    password = "securepassword123"
    print(f"Step 1: Logging in/Registering analyst '{username}'...")
    
    # Register user (in case they don't exist yet)
    register_url = f"{BASE_HTTP_URL}/api/auth/register"
    register_data = {"username": username, "password": password}
    try:
        req = urllib.request.Request(
            register_url,
            data=json.dumps(register_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as res:
            print("   Analyst registered successfully.")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        if "Username already registered" in body:
            print("   Analyst already exists, proceeding to login.")
        else:
            print(f"   Registration error: {e.code} - {body}")
            return
    except Exception as e:
        print(f"   Registration failed: {e}")
        return

    # Login
    login_url = f"{BASE_HTTP_URL}/api/auth/login"
    login_data = urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")
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
            print("   Success! JWT Token acquired.")
    except Exception as e:
        print(f"   Login failed: {e}")
        return

    # 2. Connect to WebSocket /ws/live
    print(f"\nStep 2: Connecting to live WebSocket at {BASE_WS_URL}/ws/live ...")
    try:
        async with websockets.connect(f"{BASE_WS_URL}/ws/live", origin="http://localhost:5173") as websocket:
            print("   Connected! Spawning real-time event listener...")
            
            # Start background listener task
            listener_task = asyncio.create_task(read_websocket_messages(websocket))
            
            # Wait a few seconds to capture at least one heartbeat
            print("\nWaiting 6 seconds to capture periodic heartbeat loop event...")
            await asyncio.sleep(6)
            
            # 3. Send threat-like prediction payload to trigger broadcast
            print("\nStep 3: Triggering a Threat-Like Flow Prediction via JWT-secured POST /api/predict...")
            predict_url = f"{BASE_HTTP_URL}/api/predict"
            threat_payload = {
                "features": {
                    "Max Packet Length": 1500.0,
                    "Packet Length Variance": 25000.0,
                    "Packet Length Std": 158.0,
                    "Avg Bwd Segment Size": 750.0,
                    "Bwd Packet Length Max": 1500.0,
                    "Total Length of Bwd Packets": 30000.0,
                    "Subflow Fwd Bytes": 1500.0,
                    "Subflow Bwd Bytes": 30000.0,
                    "Average Packet Size": 700.0,
                    "Total Length of Fwd Packets": 1500.0,
                    "Fwd Packet Length Max": 1500.0,
                    "Init_Win_bytes_forward": 29200.0,
                    "Total Fwd Packets": 10.0,
                    "Bwd Packet Length Std": 100.0,
                    "Packet Length Mean": 500.0,
                    "Avg Fwd Segment Size": 150.0,
                    "Fwd Packet Length Mean": 150.0,
                    "Bwd Packet Length Mean": 750.0,
                    "Flow Bytes/s": 5000000.0,
                    "Fwd Header Length.1": 200.0,
                    "Bwd Packets/s": 5000.0,
                    "Bwd Header Length": 200.0,
                    "Fwd IAT Max": 5.0,
                    "PSH Flag Count": 1.0,
                    "Idle Min": 0.0,
                    "Init_Win_bytes_backward": 29200.0,
                    "Fwd Header Length": 200.0,
                    "Flow IAT Max": 5.0,
                    "act_data_pkt_fwd": 8.0,
                    "Fwd IAT Std": 1.0
                },
                "source_scenario": "websocket_live_unit_test"
            }
            
            try:
                req = urllib.request.Request(
                    predict_url,
                    data=json.dumps(threat_payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req) as res:
                    response_data = json.loads(res.read().decode("utf-8"))
                    print(f"   HTTP Predict Response Status: 200 (Alert generated: {response_data.get('predicted_label')})")
            except Exception as e:
                print(f"   HTTP Predict Request failed: {e}")
                
            # Wait another 2 seconds to make sure WebSocket gets the broadcast message
            print("\nWaiting for WebSocket broadcast receipt...")
            await asyncio.sleep(2)
            
            # Clean up
            print("\nShutting down WS listener...")
            listener_task.cancel()
            await asyncio.gather(listener_task, return_exceptions=True)
            
    except Exception as e:
        print(f"WebSocket client connection or setup failed: {e}")
        
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_websocket_flow())
