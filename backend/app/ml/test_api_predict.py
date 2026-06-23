import json
import urllib.request
import urllib.error

def test_api():
    print("=" * 60)
    print("           FASTAPI /api/predict ENDPOINT VERIFIER")
    print("=" * 60)
    
    benign_payload = {
        "features": {
            "Max Packet Length": 64.0,
            "Packet Length Variance": 0.0,
            "Packet Length Std": 0.0,
            "Avg Bwd Segment Size": 0.0,
            "Bwd Packet Length Max": 0.0,
            "Total Length of Bwd Packets": 0.0,
            "Subflow Fwd Bytes": 128.0,
            "Subflow Bwd Bytes": 0.0,
            "Average Packet Size": 32.0,
            "Total Length of Fwd Packets": 128.0,
            "Fwd Packet Length Max": 64.0,
            "Init_Win_bytes_forward": 256.0,
            "Total Fwd Packets": 2.0,
            "Bwd Packet Length Std": 0.0,
            "Packet Length Mean": 32.0,
            "Avg Fwd Segment Size": 64.0,
            "Fwd Packet Length Mean": 64.0,
            "Bwd Packet Length Mean": 0.0,
            "Flow Bytes/s": 1000.0,
            "Fwd Header Length.1": 40.0,
            "Bwd Packets/s": 0.0,
            "Bwd Header Length": 0.0,
            "Fwd IAT Max": 10.0,
            "PSH Flag Count": 0.0,
            "Idle Min": 0.0,
            "Init_Win_bytes_backward": 0.0,
            "Fwd Header Length": 40.0,
            "Flow IAT Max": 10.0,
            "act_data_pkt_fwd": 1.0,
            "Fwd IAT Std": 0.0
        }
    }
    
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
        }
    }
    
    url = "http://127.0.0.1:8000/api/predict"
    
    for name, payload in [("Benign Flow", benign_payload), ("Threat-Like Flow", threat_payload)]:
        print(f"\n---> Sending {name} to {url}...")
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req) as response:
                res_body = response.read().decode("utf-8")
                res_dict = json.loads(res_body)
                print(f"Status Code: 200")
                print(f"Predicted Label:      {res_dict.get('predicted_label')}")
                print(f"Confidence:           {res_dict.get('confidence'):.4f}")
                print(f"Resolution Tier:      {res_dict.get('tier_name')} (Tier {res_dict.get('tier')})")
                if "alert_id" in res_dict:
                    print(f"Alert ID Created:     {res_dict.get('alert_id')}")
                    print(f"Alert Severity:       {res_dict.get('severity')}")
                print("Top Feature Attributions:")
                for i, feat in enumerate(res_dict.get("top_features", [])):
                    print(f"  {i+1}. {feat['feature']}: raw_val={feat['value']:.2f}, importance={feat['importance']:.4f}, impact={feat['impact']:.4f}")
        except urllib.error.URLError as e:
            print(f"Network error while connecting to server: {e}")
            print("Please make sure the Uvicorn server is running locally (e.g. at http://127.0.0.1:8000)")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            break
    print("=" * 60)

if __name__ == "__main__":
    test_api()
