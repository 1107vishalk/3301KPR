# 3301 File Integrity Tool

## Flow
1. Landing page shows **3301 File Integrity Tool** and **START TOOL**.
2. Start calls `POST /api/start`.
3. Backend creates a fresh SHA-256 baseline from `monitored/` and starts Watchdog.
4. Dashboard opens only after baseline/monitor initialization succeeds.
5. Every file event is hashed and classified.
6. The API correlates recent events using a 30-second temporal + behavioural correlation window.
7. Dashboard shows overall risk, classification, correlation signals and forensic timeline.

## Run backend
```powershell
cd backend
pip install -r requirements.txt
uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

## Run frontend
```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL, normally `http://127.0.0.1:5173`.

## Important
The baseline is recreated whenever **START TOOL** is pressed. Put only the files you want to monitor inside `monitored/` before starting.
