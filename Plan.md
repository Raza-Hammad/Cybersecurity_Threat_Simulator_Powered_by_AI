# Project: Cybersecurity Threat Simulator Powered by AI (FYP)

## Team & Context
- Bahria University Karachi, BS(IT) Final Year Project. Supervisor: Mr. Muhammad Shahzad.
- Team: Muhammad Hammad Raza, Yasir Hussain, Muhammad Izhan Khan.
- Mid-evaluation: ~mid-2026 (target 60-70% complete). Final eval: ~13 Dec 2026.

## What the system does (three pillars, from the approved proposal)
1. SIMULATE network attacks (DDoS, Port Scan, Brute Force, Malware-related) in a controlled, OFFLINE/isolated environment.
2. DETECT them using an AI/ML cascade analyzing network traffic.
3. VISUALIZE results in a real-time, educational web dashboard with Explainable AI.

## SCOPE GUARDRAILS (do not cross these — they are in the approved proposal)
- This is DETECTION + ANALYSIS + AWARENESS. It does NOT auto-block attacks (no active defense).
- Attacks are produced by REPLAYING recorded traffic, NOT by running live attack tools against live systems.
  Live penetration testing is explicitly OUT of scope.
- Network-level threats only (TCP/IP enterprise "General IT" scope). Not IoT-specific, not application-layer pentest.

## Architecture
- Backend: Python + FastAPI (REST + WebSocket). Frontend: React + Vite + Tailwind + Recharts.
- Database: SQLite via SQLModel. Auth: bcrypt-hashed passwords + JWT.
- ML cascade (3 tiers; escalate when confidence < 0.85):
  - Tier 1: LightGBM      -> fast screener (~95% of packets).
  - Tier 2: Random Forest -> verifier with explainability (~4%).
  - Tier 3: XGBoost       -> expert; weighted vote across all three (~1%).
- AI chat: Smart Hybrid = rule-based answers for common questions + Google Gemini API fallback.

## DATASET ARCHITECTURE (critical — two datasets, two layers, NEVER merged for training)
- DETECTION layer trains on CSV:
  - Mid-eval: original CIC-IDS2017 "GeneratedLabelledFlows" CSVs.
  - Final: upgrade to BCCC-CIC-IDS2017 (2024, cleaned) for a measurable accuracy gain.
- SIMULATION layer:
  - Mid-eval: replay labelled CSV flows in "simulated streaming" mode.
  - Final: replay raw CIC-IDS2017 PCAP files over a virtual interface in an isolated environment.
- KNOWN DATA BUGS in GeneratedLabelledFlows (handle in the loader):
  - ~288,602 fully-empty padding rows in the Thursday WebAttacks file -> drop them.
  - UTF-8 failure on byte 0x96 (Windows en-dash) -> read with latin-1 fallback (a safe_read_csv helper).
  - Inf/NaN present -> clean before training. Drop ID/IP/port columns before training (no IP memorization).

## Folder structure
- /backend  -> FastAPI app, ML, DB, simulator, (later) pcap processing
- /frontend -> React app
- /data     -> /data/raw (CSVs + PCAPs, gitignored), /data/cache (processed data + saved models)
- /backend/.env -> GEMINI_API_KEY, JWT_SECRET (gitignored)

## Working conventions
- Type hints + docstrings, PEP8, small testable functions.
- Never commit .env, datasets, or model files. Maintain a .gitignore.
- After every feature, the app must still run. Explain what you built in plain, simple English.
- Code quality is graded and must be defendable in a viva — comment non-obvious logic.