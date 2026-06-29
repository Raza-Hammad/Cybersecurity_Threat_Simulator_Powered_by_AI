import numpy as np

def get_raw_flow_metadata(idx: int, label: str):
    """Generates realistic, deterministic IP and Port addresses based on flow index and attack labels.
    
    Illustrative Network Nodes:
      - Left: "Attacker Pool" (External WAN block e.g. 10.0.0.x, 172.16.0.x) or "Clients" (192.168.10.x)
      - Right: "Internal Network"
        - Web Server: 192.168.10.50
        - DB Server:  192.168.10.51
        - Workstation:192.168.10.100
    """
    # Seed numpy random locally using flow index for determinism
    rng = np.random.default_rng(idx)
    
    if label == "BENIGN":
        # Benign clients inside the local network or coming from a benign range
        src_ip = f"192.168.10.{rng.integers(101, 250)}"
        dest_ip = "192.168.10.50" # Web Server
        src_port = int(rng.integers(49152, 65535))
        dest_port = 80 # HTTP
    elif "DDoS" in label or "Hulk" in label or "GoldenEye" in label or "slowloris" in label or "Slowhttptest" in label:
        # DDoS attack: many external source IPs targeting Web Server
        src_ip = f"10.0.0.{rng.integers(2, 254)}"
        dest_ip = "192.168.10.50" # Web Server
        src_port = int(rng.integers(1024, 65535))
        dest_port = 80 # HTTP
    elif "PortScan" in label:
        # PortScan: scan sequential ports on DB Server or Web Server
        src_ip = "172.16.0.15"
        dest_ip = "192.168.10.51" # DB Server
        src_port = int(rng.integers(30000, 50000))
        dest_port = int((idx % 1000) + 1)
    elif "Brute" in label or "Patator" in label:
        # Brute Force attack: FTP (21) or SSH (22)
        src_ip = "172.16.0.22"
        dest_ip = "192.168.10.50" # Web Server
        src_port = int(rng.integers(1024, 65535))
        dest_port = 22 if "SSH" in label else 21
    elif "Sql Injection" in label:
        src_ip = "172.16.0.88"
        dest_ip = "192.168.10.51" # DB Server
        src_port = int(rng.integers(1024, 65535))
        dest_port = 3306 # MySQL
    else:
        # Generic attack
        src_ip = f"172.16.0.{rng.integers(2, 254)}"
        dest_ip = "192.168.10.100" # Workstation
        src_port = int(rng.integers(1024, 65535))
        dest_port = 8080
        
    return src_ip, dest_ip, src_port, dest_port
