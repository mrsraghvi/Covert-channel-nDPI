
---

## 🛠️ Step 1: Start the Backend, Database & Dashboard (WSL Terminal)

Make sure **Docker Desktop is running** on Windows before executing these commands.

1. Open WSL (Windows Subsystem for Linux) and navigate to the project root (the directory containing `docker-compose.yml`):
```bash
cd "/mnt/c/Users/mrsra/OneDrive/Desktop/New folder/covertscope"
```

2. Create `.env` and generate strong local secrets the first time you start the project:
```bash
if [ ! -f .env ]; then
  cp .env.example .env
  sed -i \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" \
    -e "s/^COVERTSCOPE_API_KEY=.*/COVERTSCOPE_API_KEY=$(openssl rand -hex 32)/" \
    -e "s/^COVERTSCOPE_INGEST_SECRET=.*/COVERTSCOPE_INGEST_SECRET=$(openssl rand -hex 32)/" \
    .env
fi
```

If `.env` already exists, keep its values and confirm that `POSTGRES_PASSWORD`, `COVERTSCOPE_API_KEY`, and `COVERTSCOPE_INGEST_SECRET` are set to real values (not empty or the `changeme-generate-a-real-secret` placeholder). Generate a value with `openssl rand -hex 32` and put it in `.env` for any missing or placeholder entry. **Do not regenerate valid values when starting again**; changing the database password can prevent an existing database volume from starting.

3. Start the Docker containers:
```bash
docker compose up -d
```

4. Verify that the containers are up and running:
```bash
docker compose ps
```



* **Frontend Dashboard:** Accessible in your browser at `http://localhost:3000`. Enter the `COVERTSCOPE_API_KEY` value from `.env` when prompted.
* **Backend API Docs:** Accessible at `http://localhost:8000/docs`.

---

## 🔬 Step 2: Set Up & Compile the nDPI C Engine (WSL Terminal)

The packet capture engine compiles and runs inside **WSL2 (Linux/Ubuntu)**.

1. Open your **WSL / Ubuntu Terminal**.
2. Install required build dependencies *(only needed once)*:
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libjson-c-dev autoconf automake libtool pkg-config git python3-venv python3-full

```


3. Navigate to the C engine folder and compile:
```bash
cd "/mnt/c/Users/mrsra/OneDrive/Desktop/New folder/covertscope/ndpi-engine"
make

```


4. Run the detector targeting your desired network interface:
* **For Loopback / Local Testing:**
```bash
sudo ./covert_detector lo

```


* **For External / Live Network Capture:**
```bash
sudo ./covert_detector eth0

```





---

## 🧪 Step 3: Run the Covert Traffic Generator (WSL Terminal)

To generate test signatures for the detector to analyze:

1. Open a **new WSL Terminal window**.
2. Navigate to the project root and activate the Python virtual environment:
```bash
cd "/mnt/c/Users/mrsra/OneDrive/Desktop/New folder/covertscope"

# Create and activate venv (if not already created)
python3 -m venv venv
source venv/bin/activate

```


3. Install Python requirements *(only needed once)*:
```bash
pip install -r backend/requirements.txt

```


4. Run traffic generation tests against loopback (`127.0.0.1`):
* **Timing / DNS / HTTP Tests:**
```bash
python3 generator/generator.py --target 127.0.0.1

```


* **ICMP Raw Socket Test (Requires Elevated Privileges):**
```bash
sudo ./venv/bin/python generator/generator.py --target 127.0.0.1 --technique icmp

```





---

## 💻 Optional: Run Dashboard Standalone (UI Demo Mode)

If you ever want to preview or inspect the React Dashboard without starting Docker or the C engine:

```cmd
cd "C:\Users\mrsra\OneDrive\Desktop\New folder\covertscope\frontend"
npm install
npm run dev

```

---

## 📊 Summary Checklist

```
┌──────────────────────────┬─────────────────────────┬────────────────────────────────────────────────┐
│ Service                  │ Location / Shell        │ Command                                        │
├──────────────────────────┼─────────────────────────┼────────────────────────────────────────────────┤
│ 1. Docker Services       │ WSL Terminal            │ docker compose up -d                           │
│ 2. nDPI C Engine         │ WSL Terminal            │ cd ndpi-engine && make && sudo ./covert_detector lo │
│ 3. Traffic Generator     │ WSL Terminal (venv)     │ python3 generator/generator.py --target 127.0.0.1 │
└──────────────────────────┴─────────────────────────┴────────────────────────────────────────────────┘

```