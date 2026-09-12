# IBM Cloud Deployment Guide — NetGuard AI

**IBM Cloud Deployment Status:** `Configuration: Prepared | Live Deployment: Not Completed`

> [!NOTE]
> **Deployment Status Notice**: The application has been containerized and configured for IBM Cloud Code Engine deployment (`Dockerfile`, `.dockerignore`, dynamic `$PORT` environment variable binding). A live IBM Cloud deployment was not completed.

---

## 1. Selected IBM Cloud Service

- **Service:** **IBM Cloud Code Engine (Lite Tier)**
- **Service Description:** Fully managed serverless container platform running containerized web applications without requiring cluster infrastructure management.
- **Lite Plan Features:**
  - 100,000 vCPU-seconds / month (Free)
  - 200,000 GB-seconds memory / month (Free)
  - Scale-to-zero capability during inactivity (0 cost).

---

## 2. Deployment Prerequisites

1. Active **IBM Cloud Account**.
2. **IBM Cloud CLI** installed:
   ```powershell
   # Windows (PowerShell)
   iex (New-Object Net.WebClient).DownloadString('https://clis.cloud.ibm.com/install/powershell')
   ```
3. IBM Cloud Code Engine plugin:
   ```bash
   ibmcloud plugin install code-engine
   ```

---

## 3. Step-by-Step Deployment Steps

### Step 1: Authenticate CLI
```bash
ibmcloud login --apikey YOUR_IBM_CLOUD_API_KEY -r us-south
ibmcloud target -g Default
```

### Step 2: Create Code Engine Project
```bash
ibmcloud ce project create --name netguard-ai-project
ibmcloud ce project select --name netguard-ai-project
```

### Step 3: Configure Environment Secrets
```bash
ibmcloud ce secret create --name netguard-env-secrets \
  --from-literal ENVIRONMENT=production \
  --from-literal PORT=8000
```

### Step 4: Deploy Container Application from Source
```bash
ibmcloud ce app create --name netguard-ai-app \
  --src . \
  --port 8000 \
  --env-from-secret netguard-env-secrets \
  --min-scale 0 \
  --max-scale 1 \
  --cpu 0.5 \
  --memory 1G
```

### Step 5: Verify Public Endpoint
```bash
ibmcloud ce app get --name netguard-ai-app --output url
```

Test containerized health endpoint:
```bash
curl https://netguard-ai-app.us-south.codeengine.appdomain.cloud/health
```
