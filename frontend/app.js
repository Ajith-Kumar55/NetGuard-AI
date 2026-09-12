/**
 * NetGuard AI - Security Operations Center Dashboard JavaScript
 * Full-Stack OAuth2 JWT, Scapy PCAP File Analysis, Threat Triage & DB History Implementation
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements - Authentication
  const loginView = document.getElementById("login-view");
  const appView = document.getElementById("app-view");
  const loginForm = document.getElementById("login-form");
  const loginUsername = document.getElementById("login-username");
  const loginPassword = document.getElementById("login-password");
  const loginError = document.getElementById("login-error");
  const loginErrorMsg = document.getElementById("login-error-msg");
  const btnTogglePassword = document.getElementById("btn-toggle-password");
  const btnLogout = document.getElementById("btn-logout");
  const userDisplayName = document.getElementById("user-display-name");

  // DOM Elements - Status & Navigation
  const navTabBtns = document.querySelectorAll(".nav-tab-btn");
  const tabPages = document.querySelectorAll(".tab-page");

  // DOM Elements - File Dropzone & Ingestion
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const btnBrowseFile = document.getElementById("btn-browse-file");
  const uploadStatusBar = document.getElementById("upload-status-bar");
  const uploadFilename = document.getElementById("upload-filename");
  const uploadStageBadge = document.getElementById("upload-stage-badge");
  const uploadProgress = document.getElementById("upload-progress");
  const uploadStatusText = document.getElementById("upload-status-text");

  // DOM Elements - Analysis Summaries & Triage
  const summaryCard = document.getElementById("summary-card");
  const triageCard = document.getElementById("triage-card");
  const triageTbody = document.getElementById("triage-tbody");

  // DOM Elements - Debug Accordion & Form
  const accordionToggle = document.getElementById("accordion-toggle-debug");
  const accordionContent = document.getElementById("accordion-content-debug");
  const accordionArrow = document.getElementById("accordion-arrow");
  const trafficForm = document.getElementById("traffic-analysis-form");
  const btnPresetNormal = document.getElementById("btn-preset-normal");
  const btnPresetAnomaly = document.getElementById("btn-preset-anomaly");
  const btnResetForm = document.getElementById("btn-reset-form");

  // DOM Elements - Database History & Modal
  const historyTbody = document.getElementById("history-tbody");
  const btnClearHistory = document.getElementById("btn-clear-history");
  const btnHistPrev = document.getElementById("btn-hist-prev");
  const btnHistNext = document.getElementById("btn-hist-next");
  const histPageInfo = document.getElementById("hist-page-info");
  const btnDashHistoryLink = document.getElementById("btn-dash-history-link");
  const modalBackdrop = document.getElementById("modal-backdrop");
  const modalTitle = document.getElementById("modal-title");
  const modalBodyContent = document.getElementById("modal-body-content");
  const btnCloseModal = document.getElementById("btn-close-modal");

  // State
  let predictionChart = null;
  let sampleData = { normal: null, anomaly: null };
  let currentPage = 1;
  const pageSize = 15;
  let lastAnalysisResults = [];

  // =========================================================================
  // 1. INITIALIZATION & AUTHENTICATION
  // =========================================================================
  checkAuthSession();
  initAuthHandlers();
  initNavigationHandlers();
  initDropzoneHandlers();
  initAccordionHandlers();
  initFormHandlers();
  initPresetHandlers();
  initHistoryHandlers();
  initModalHandlers();

  function getAuthToken() {
    return localStorage.getItem("netguard_jwt_token");
  }

  function checkAuthSession() {
    const token = getAuthToken();
    if (token) {
      fetchUserProfile();
    } else {
      showLoginView();
    }
  }

  function showLoginView() {
    loginView.classList.remove("hidden");
    appView.classList.add("hidden");
  }

  function showAppView(username = "admin") {
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
    if (userDisplayName) userDisplayName.textContent = username;
    fetchDbHistory(1);
    fetchSampleRecords();
  }

  function initAuthHandlers() {
    if (btnTogglePassword) {
      btnTogglePassword.addEventListener("click", () => {
        const type = loginPassword.getAttribute("type") === "password" ? "text" : "password";
        loginPassword.setAttribute("type", type);
      });
    }

    if (loginForm) {
      loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = loginUsername.value.trim();
        const password = loginPassword.value.trim();

        const formData = new FormData();
        formData.append("username", username);
        formData.append("password", password);

        try {
          const resp = await fetch("/api/auth/login", {
            method: "POST",
            body: formData,
          });

          if (!resp.ok) {
            loginError.classList.remove("hidden");
            loginErrorMsg.textContent = "Invalid username or password credentials.";
            return;
          }

          const data = await resp.json();
          localStorage.setItem("netguard_jwt_token", data.access_token);
          loginError.classList.add("hidden");
          showAppView(username);
        } catch (err) {
          loginError.classList.remove("hidden");
          loginErrorMsg.textContent = "Failed to communicate with authentication server.";
        }
      });
    }

    if (btnLogout) {
      btnLogout.addEventListener("click", () => {
        localStorage.removeItem("netguard_jwt_token");
        showLoginView();
      });
    }
  }

  async function fetchUserProfile() {
    const token = getAuthToken();
    try {
      const resp = await fetch("/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (resp.ok) {
        const user = await resp.json();
        showAppView(user.username);
      } else {
        localStorage.removeItem("netguard_jwt_token");
        showLoginView();
      }
    } catch (e) {
      showAppView("admin");
    }
  }

  // =========================================================================
  // 2. NAVIGATION HANDLERS
  // =========================================================================
  function initNavigationHandlers() {
    navTabBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetTabId = btn.getAttribute("data-tab");
        navTabBtns.forEach((b) => b.classList.remove("active"));
        tabPages.forEach((p) => p.classList.remove("active"));

        btn.classList.add("active");
        const page = document.getElementById(targetTabId);
        if (page) page.classList.add("active");

        if (targetTabId === "tab-history" || targetTabId === "tab-dashboard") {
          fetchDbHistory(currentPage);
        }
      });
    });

    if (btnDashHistoryLink) {
      btnDashHistoryLink.addEventListener("click", () => {
        const histBtn = document.querySelector('.nav-tab-btn[data-tab="tab-history"]');
        if (histBtn) histBtn.click();
      });
    }
  }

  // =========================================================================
  // 3. FILE DROPZONE & INGESTION (CSV / PCAP / PCAPNG)
  // =========================================================================
  function initDropzoneHandlers() {
    if (!dropzone || !fileInput) return;

    btnBrowseFile.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFileUpload(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
      }
    });
  }

  async function handleFileUpload(file) {
    const name = file.name;
    const ext = name.split(".").pop().toLowerCase();

    if (!["csv", "pcap", "pcapng"].includes(ext)) {
      alert("Unsupported file format. Please upload a .csv, .pcap, or .pcapng file.");
      return;
    }

    uploadStatusBar.classList.remove("hidden");
    uploadFilename.textContent = name;
    uploadStageBadge.className = "badge blue";
    updateUploadProgress("Analyzing...", 50, "Running vectorized batch ML prediction & high-risk SHAP analysis...");

    const formData = new FormData();
    formData.append("file", file);

    const token = getAuthToken();
    const headers = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;

    try {
      const resp = await fetch("/api/analyze/file", {
        method: "POST",
        headers: headers,
        body: formData,
      });

      if (!resp.ok) {
        let errMsg = "Analysis failed.";
        try {
          const errData = await resp.json();
          errMsg = errData.detail || errMsg;
        } catch (e) {}
        updateUploadProgress("Error", 100, errMsg);
        uploadStageBadge.className = "badge red";
        alert(`File Analysis Error: ${errMsg}`);
        return;
      }

      const data = await resp.json();
      const timeText = data.summary && data.summary.processing_time_seconds ? ` in ${data.summary.processing_time_seconds}s` : "";

      updateUploadProgress("Complete", 100, `Successfully analyzed ${data.summary.total_records} network records${timeText}.`);
      uploadStageBadge.className = "badge green";

      renderAnalysisResults(data);
      fetchDbHistory(1);
    } catch (err) {
      updateUploadProgress("Error", 100, "Network connection error during file analysis.");
      uploadStageBadge.className = "badge red";
      alert("Network connection error during file analysis.");
    }
  }

  function updateUploadProgress(stage, percent, text) {
    uploadStageBadge.textContent = stage;
    uploadProgress.style.width = `${percent}%`;
    uploadStatusText.textContent = text;
  }

  // =========================================================================
  // 4. RENDER ANALYSIS & TRIAGE RESULTS
  // =========================================================================
  function renderAnalysisResults(data) {
    summaryCard.classList.remove("hidden");
    triageCard.classList.remove("hidden");

    document.getElementById("summary-filetype-badge").textContent = data.file_type;
    document.getElementById("sum-total-records").textContent = data.summary.total_records;
    document.getElementById("sum-normal-count").textContent = data.summary.normal_count;
    document.getElementById("sum-anomaly-count").textContent = data.summary.anomaly_count;
    document.getElementById("sum-avg-risk").textContent = `${data.summary.average_risk_score}%`;
    document.getElementById("sum-max-risk").textContent = `${data.summary.max_risk_score}%`;

    lastAnalysisResults = data.results;
    triageTbody.innerHTML = "";

    data.results.forEach((res, index) => {
      const tr = document.createElement("tr");

      const isAnomaly = res.prediction === "anomaly";
      const classBadge = isAnomaly ? '<span class="badge red">ANOMALY</span>' : '<span class="badge green">NORMAL</span>';

      const familyText = res.attack_family ? `<span class="badge purple">${res.attack_family}</span>` : '<span class="text-muted">-</span>';

      let riskBadgeClass = "blue";
      if (res.risk_level === "Critical") riskBadgeClass = "red";
      else if (res.risk_level === "High") riskBadgeClass = "orange";
      else if (res.risk_level === "Medium") riskBadgeClass = "yellow";

      const riskBadge = `<span class="badge ${riskBadgeClass}">${res.risk_score}% (${res.risk_level})</span>`;

      const topFeat = res.top_features && res.top_features.length > 0 ? `<code>${res.top_features[0].feature}</code>` : '<span class="text-muted">-</span>';

      tr.innerHTML = `
        <td>${res.timestamp}</td>
        <td><code>${res.source_ip}</code></td>
        <td><code>${res.destination_ip}</code></td>
        <td>${res.protocol}</td>
        <td>${classBadge}</td>
        <td>${familyText}</td>
        <td>${riskBadge}</td>
        <td>${(res.probability * 100).toFixed(1)}%</td>
        <td>${topFeat}</td>
        <td><button class="btn btn-xs btn-outline btn-inspect" data-index="${index}">🔍 Inspect</button></td>
      `;

      triageTbody.appendChild(tr);
    });

    // Attach inspect click handlers
    document.querySelectorAll(".btn-inspect").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = parseInt(btn.getAttribute("data-index"));
        showInspectModal(lastAnalysisResults[idx]);
      });
    });

    updateDashboardKPIs(data.summary);
    updatePredictionChart(data.summary);
  }

  function updateDashboardKPIs(summary) {
    if (!summary) return;
    const totalEl = document.getElementById("kpi-total-preds");
    const normalEl = document.getElementById("kpi-normal-preds");
    const anomalyEl = document.getElementById("kpi-anomaly-preds");
    const latencyEl = document.getElementById("kpi-avg-latency");

    if (totalEl) totalEl.textContent = summary.total_records || 0;
    if (normalEl) normalEl.textContent = summary.normal_count || 0;
    if (anomalyEl) anomalyEl.textContent = summary.anomaly_count || 0;

    if (latencyEl) {
      if (typeof summary.average_flow_latency_ms === "number" && !isNaN(summary.average_flow_latency_ms)) {
        latencyEl.textContent = `${summary.average_flow_latency_ms.toFixed(2)} ms`;
      } else if (typeof summary.total_processing_time_ms === "number" && !isNaN(summary.total_processing_time_ms)) {
        const calculatedLat = summary.total_processing_time_ms / Math.max(1, summary.total_records || 1);
        latencyEl.textContent = `${calculatedLat.toFixed(2)} ms`;
      }
    }
  }

  function updatePredictionChart(summary) {
    const emptyMsg = document.getElementById("chart-empty-msg");
    const chartWrapper = document.getElementById("chart-wrapper");
    const canvas = document.getElementById("predictionChart");

    if (!canvas) return;

    const totalRecords = summary ? summary.total_records || 0 : 0;

    if (totalRecords === 0) {
      if (emptyMsg) emptyMsg.classList.remove("hidden");
      if (chartWrapper) chartWrapper.classList.add("hidden");
      if (predictionChart) {
        predictionChart.destroy();
        predictionChart = null;
      }
      return;
    }

    if (emptyMsg) emptyMsg.classList.add("hidden");
    if (chartWrapper) chartWrapper.classList.remove("hidden");

    const labels = ["DoS Attack", "Probe Scan", "R2L Access", "U2R Escalation"];
    const dist = (summary && summary.attack_distribution) || {};

    const dataValues = [
      dist["DoS"] || 0,
      dist["Probe"] || 0,
      dist["R2L"] || 0,
      dist["U2R"] || 0,
    ];

    if (predictionChart) {
      predictionChart.destroy();
    }

    const ctx = canvas.getContext("2d");
    predictionChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: dataValues,
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#a855f7"],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8" } },
        },
      },
    });
  }

  // =========================================================================
  // 5. ACCORDION & DEBUG FORM
  // =========================================================================
  function initAccordionHandlers() {
    if (!accordionToggle || !accordionContent) return;
    accordionToggle.addEventListener("click", () => {
      const isHidden = accordionContent.classList.contains("hidden");
      if (isHidden) {
        accordionContent.classList.remove("hidden");
        accordionArrow.textContent = "▲";
      } else {
        accordionContent.classList.add("hidden");
        accordionArrow.textContent = "▼";
      }
    });
  }

  function initFormHandlers() {
    if (!trafficForm) return;

    trafficForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const formData = new FormData(trafficForm);
      const payload = {};

      formData.forEach((val, key) => {
        if (key === "protocol_type" || key === "service" || key === "flag") {
          payload[key] = String(val);
        } else {
          payload[key] = parseFloat(val) || 0;
        }
      });

      const token = getAuthToken();
      const headers = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      try {
        const resp = await fetch("/predict", {
          method: "POST",
          headers: headers,
          body: JSON.stringify(payload),
        });

        if (!resp.ok) {
          alert("Failed to analyze manual feature payload.");
          return;
        }

        const res = await resp.json();
        showInspectModal(res);
        fetchDbHistory(1);
      } catch (err) {
        alert("Server connection error during prediction.");
      }
    });
  }

  function initPresetHandlers() {
    if (btnPresetNormal) {
      btnPresetNormal.addEventListener("click", () => populateFormPreset(sampleData.normal));
    }
    if (btnPresetAnomaly) {
      btnPresetAnomaly.addEventListener("click", () => populateFormPreset(sampleData.anomaly));
    }
    if (btnResetForm) {
      btnResetForm.addEventListener("click", () => trafficForm.reset());
    }
  }

  async function fetchSampleRecords() {
    try {
      const resp = await fetch("/api/samples");
      if (resp.ok) {
        sampleData = await resp.json();
      }
    } catch (e) {}
  }

  function populateFormPreset(preset) {
    if (!preset) return;
    Object.keys(preset).forEach((key) => {
      const input = trafficForm.querySelector(`[name="${key}"]`);
      if (input) input.value = preset[key];
    });
  }

  // =========================================================================
  // 6. DATABASE HISTORY (SQLite Persistent)
  // =========================================================================
  function initHistoryHandlers() {
    const btnExportCsv = document.getElementById("btn-export-csv");
    if (btnExportCsv) {
      btnExportCsv.addEventListener("click", async () => {
        const token = getAuthToken();
        if (!token) {
          alert("Authentication required to export audit logs.");
          return;
        }

        try {
          const resp = await fetch("/api/history/export?format=csv", {
            headers: { Authorization: `Bearer ${token}` },
          });

          if (!resp.ok) {
            let errMsg = "Failed to export audit log CSV.";
            try {
              const errData = await resp.json();
              errMsg = errData.detail || errMsg;
            } catch (e) {}
            alert(errMsg);
            return;
          }

          const blob = await resp.blob();
          const downloadUrl = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = downloadUrl;

          let filename = "netguard_threat_triage_audit.csv";
          const disposition = resp.headers.get("Content-Disposition");
          if (disposition && disposition.includes("filename=")) {
            const matches = disposition.match(/filename=["']?([^"';]+)["']?/);
            if (matches && matches[1]) filename = matches[1];
          }
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(downloadUrl);
        } catch (err) {
          alert("Error downloading audit log CSV.");
        }
      });
    }

    if (btnHistPrev) {
      btnHistPrev.addEventListener("click", () => {
        if (currentPage > 1) fetchDbHistory(currentPage - 1);
      });
    }
    if (btnHistNext) {
      btnHistNext.addEventListener("click", () => {
        fetchDbHistory(currentPage + 1);
      });
    }
    if (btnClearHistory) {
      btnClearHistory.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to clear all persistent detection history from the database?")) return;

        const token = getAuthToken();
        try {
          const resp = await fetch("/api/history", {
            method: "DELETE",
            headers: { Authorization: `Bearer ${token}` },
          });

          if (resp.ok) {
            alert("Database history cleared successfully.");
            fetchDbHistory(1);
          } else {
            alert("Failed to clear history.");
          }
        } catch (e) {
          alert("Error clearing history.");
        }
      });
    }
  }

  async function fetchDbHistory(page = 1) {
    const token = getAuthToken();
    if (!token) return;

    try {
      const resp = await fetch(`/api/history?page=${page}&page_size=${pageSize}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!resp.ok) return;

      const data = await resp.json();
      currentPage = data.page;
      const totalPages = Math.ceil(data.total / data.page_size) || 1;

      if (histPageInfo) {
        histPageInfo.textContent = `Page ${currentPage} of ${totalPages} (Total: ${data.total})`;
      }
      if (btnHistPrev) btnHistPrev.disabled = currentPage <= 1;
      if (btnHistNext) btnHistNext.disabled = currentPage >= totalPages;

      renderDbHistoryTable(data.results);
      renderDashRecentTable((data.results || []).slice(0, 5));

      let summary = data.summary;
      if (!summary && data.results) {
        let normalCount = 0;
        let anomalyCount = 0;
        const dist = {};

        data.results.forEach((rec) => {
          if (rec.classification === "anomaly") {
            anomalyCount++;
            if (rec.attack_family) {
              dist[rec.attack_family] = (dist[rec.attack_family] || 0) + 1;
            }
          } else {
            normalCount++;
          }
        });

        summary = {
          total_records: data.total || data.results.length,
          normal_count: normalCount,
          anomaly_count: anomalyCount,
          attack_distribution: dist,
        };
      }

      if (summary) {
        updateDashboardKPIs(summary);
        updatePredictionChart(summary);
      }
    } catch (e) {
      console.error("Failed to fetch database history:", e);
    }
  }

  function renderDbHistoryTable(logs) {
    if (!historyTbody) return;

    if (!logs || logs.length === 0) {
      historyTbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No detection logs recorded in database.</td></tr>';
      return;
    }

    historyTbody.innerHTML = "";
    logs.forEach((log) => {
      const tr = document.createElement("tr");
      const isAnomaly = log.classification === "anomaly";
      const classBadge = isAnomaly ? '<span class="badge red">ANOMALY</span>' : '<span class="badge green">NORMAL</span>';
      const familyBadge = log.attack_family ? `<span class="badge purple">${log.attack_family}</span>` : '<span class="text-muted">-</span>';

      tr.innerHTML = `
        <td>#${log.id}</td>
        <td>${new Date(log.timestamp).toLocaleString()}</td>
        <td><code>${log.source_ip}</code></td>
        <td><code>${log.destination_ip}</code></td>
        <td>${classBadge}</td>
        <td>${familyBadge}</td>
        <td><span class="badge ${log.risk_score > 60 ? "red" : "blue"}">${log.risk_score}%</span></td>
        <td>${(log.confidence * 100).toFixed(1)}%</td>
      `;
      historyTbody.appendChild(tr);
    });
  }

  function renderDashRecentTable(logs) {
    const tbody = document.getElementById("dash-recent-tbody");
    if (!tbody) return;

    if (!logs || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No recent detections recorded.</td></tr>';
      return;
    }

    tbody.innerHTML = "";
    logs.forEach((log) => {
      const tr = document.createElement("tr");
      const classBadge = log.classification === "anomaly" ? '<span class="badge red">ANOMALY</span>' : '<span class="badge green">NORMAL</span>';
      const familyBadge = log.attack_family ? `<span class="badge purple">${log.attack_family}</span>` : '<span class="text-muted">-</span>';

      tr.innerHTML = `
        <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
        <td><code>${log.source_ip}</code></td>
        <td>${classBadge}</td>
        <td>${familyBadge}</td>
        <td><span class="badge ${log.risk_score > 60 ? "red" : "blue"}">${log.risk_score}%</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // =========================================================================
  // 7. INSPECT & SHAP EXPLANATION MODAL
  // =========================================================================
  function initModalHandlers() {
    if (btnCloseModal) {
      btnCloseModal.addEventListener("click", () => modalBackdrop.classList.add("hidden"));
    }
    if (modalBackdrop) {
      modalBackdrop.addEventListener("click", (e) => {
        if (e.target === modalBackdrop) modalBackdrop.classList.add("hidden");
      });
    }
  }

  function showInspectModal(res) {
    if (!res || !modalBackdrop || !modalBodyContent) return;

    modalTitle.textContent = `Threat Inspection (${res.source_ip} → ${res.destination_ip})`;

    const isAnomaly = res.prediction === "anomaly";
    const statusBox = isAnomaly ? "warning-box" : "success-box";

    let featuresHtml = "";
    if (res.top_features && res.top_features.length > 0) {
      featuresHtml = res.top_features
        .map(
          (f) => `
          <div class="shap-card">
            <div class="shap-header">
              <span class="shap-name">${f.feature}</span>
              <span class="shap-impact">+${f.impact} impact</span>
            </div>
            <p class="shap-detail">Observed Value: <code>${f.value}</code> (${f.direction.replace(/_/g, " ")})</p>
          </div>
        `
        )
        .join("");
    } else {
      if (isAnomaly) {
        featuresHtml = "<p class='text-muted'>SHAP feature attribution unavailable for this batch record (calculated for top high-risk anomalies).</p>";
      } else {
        featuresHtml = "<p class='text-muted'>Normal baseline network traffic; all feature indicators are within expected operational parameters.</p>";
      }
    }

    let mitigationHtml = "";
    if (res.mitigation && res.mitigation.length > 0) {
      mitigationHtml = `<ul class="bullet-list">${res.mitigation.map((m) => `<li>${m}</li>`).join("")}</ul>`;
    } else {
      mitigationHtml = "<p class='text-muted'>Standard network monitoring; no special mitigation required.</p>";
    }

    const classifierLabel = res.classifier_type === "stage2_ml" ? "Stage 2 ML" : (res.classifier_type === "heuristic_fallback" ? "Heuristic Fallback" : "N/A");
    const s2ConfText = res.stage2_confidence ? `${(res.stage2_confidence * 100).toFixed(2)}%` : "N/A";

    modalBodyContent.innerHTML = `
      <div class="alert-box ${statusBox} mb-15">
        <div class="alert-title">${isAnomaly ? "⚠️ ANOMALY DETECTED" : "✅ NORMAL TRAFFIC"}</div>
        <div class="alert-body">
          Stage 1 Detection: <strong>${res.prediction.toUpperCase()}</strong> |
          Anomaly Prob: <strong>${(res.probability * 100).toFixed(2)}%</strong> |
          Risk Score: <strong>${res.risk_score}% (${res.risk_level})</strong>
          ${isAnomaly ? `<br/>Stage 2 Family: <strong>${res.attack_family || "None"}</strong> | Stage 2 Conf: <strong>${s2ConfText}</strong> | Classifier: <strong>${classifierLabel}</strong>` : ""}
        </div>
      </div>

      <h4 class="mt-15 mb-10">🧠 SHAP Feature Attribution (Explainable AI - Stage 1)</h4>
      <div class="shap-container">
        ${featuresHtml}
      </div>

      <h4 class="mt-20 mb-10">🛡️ Rule-Based Defensive Mitigation Guidance</h4>
      <div class="callout-box info-box">
        ${mitigationHtml}
      </div>
    `;

    modalBackdrop.classList.remove("hidden");
  }
});
