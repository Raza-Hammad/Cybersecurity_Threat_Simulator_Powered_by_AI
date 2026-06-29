"""Unified severity scoring layer for threat alerts."""

BASE_SEVERITY_MAP = {
    "BENIGN": "Info",
    "Bot": "Critical",
    "DDoS": "Critical",
    "DoS GoldenEye": "Critical",
    "DoS Hulk": "Critical",
    "DoS Slowhttptest": "High",
    "DoS slowloris": "High",
    "FTP-Patator": "High",
    "Heartbleed": "Critical",
    "Infiltration": "Critical",
    "PortScan": "Medium",
    "SSH-Patator": "High",
    "Web Attack - Brute Force": "High",
    "Web Attack - Sql Injection": "Critical",
    "Web Attack - XSS": "High"
}

SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
}

def compute_severity(attack_type: str, confidence: float) -> str:
    """Computes packet severity using a base map and confidence-based downgrades.
    
    Start from the base severity:
      - If confidence < 0.70, downgrade severity by ONE level (Critical->High->Medium->Low),
        capped at Low. Do not downgrade Benign/Info.
      - Otherwise keep the base severity.
    """
    base = BASE_SEVERITY_MAP.get(attack_type, "High")
    if base == "Info":
        return "Info"
        
    if confidence < 0.70:
        if base == "Critical":
            return "High"
        elif base == "High":
            return "Medium"
        elif base == "Medium":
            return "Low"
        elif base == "Low":
            return "Low"
            
    return base

if __name__ == "__main__":
    # Sanity-check test cases
    test_cases = [
        ("BENIGN", 0.99),
        ("BENIGN", 0.45),
        ("DDoS", 0.98),
        ("DDoS", 0.65), # Downgrade to High
        ("DoS Slowhttptest", 0.85),
        ("DoS Slowhttptest", 0.55), # Downgrade to Medium
        ("PortScan", 0.88),
        ("PortScan", 0.50), # Downgrade to Low
        ("Infiltration", 0.90),
        ("UnknownMalware", 0.95), # Default to High
        ("UnknownMalware", 0.50)  # Default High -> Downgrade to Medium
    ]
    
    print("=" * 60)
    print("                 SEVERITY MAPPING SANITY CHECK")
    print("=" * 60)
    print(f"{'Attack Type':<30} | {'Confidence':<10} | {'Severity':<10}")
    print("-" * 60)
    for attack, conf in test_cases:
        sev = compute_severity(attack, conf)
        print(f"{attack:<30} | {conf:<10.2%} | {sev:<10}")
    print("=" * 60)
