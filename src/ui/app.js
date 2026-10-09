/**
 * InboxSentinel Frontend Application Logic
 * Simple, Subtle, Humanized Email & SMS Safety Checker
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  const state = {
    activeTab: "single",
    singleMode: "email",
    batchMode: "email",
    presets: [],
    batchResults: [],
    activeBatchFilter: "all",
  };

  // DOM Elements - Navigation & Modes
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const modeBtnEmail = document.getElementById("modeBtnEmail");
  const modeBtnSms = document.getElementById("modeBtnSms");
  const batchModeEmail = document.getElementById("batchModeEmail");
  const batchModeSms = document.getElementById("batchModeSms");

  // DOM Elements - Single Inspector Input
  const messageInput = document.getElementById("messageInput");
  const charCount = document.getElementById("charCount");
  const btnScan = document.getElementById("btnScan");
  const btnScanText = document.getElementById("btnScanText");
  const scanSpinner = document.getElementById("scanSpinner");
  const btnClear = document.getElementById("btnClear");
  const btnPaste = document.getElementById("btnPaste");
  const presetChipsContainer = document.getElementById("presetChipsContainer");
  const inputCardTitle = document.getElementById("inputCardTitle");
  const inputCardDesc = document.getElementById("inputCardDesc");

  // DOM Elements - Single Results Panel
  const emptyState = document.getElementById("emptyState");
  const verdictContent = document.getElementById("verdictContent");
  const verdictBanner = document.getElementById("verdictBanner");
  const verdictTitle = document.getElementById("verdictTitle");
  const verdictClassification = document.getElementById("verdictClassification");
  const verdictIconSvg = document.getElementById("verdictIconSvg");
  const gaugePercent = document.getElementById("gaugePercent");
  const spamProbVal = document.getElementById("spamProbVal");
  const spamProbFill = document.getElementById("spamProbFill");
  const heuristicRiskPill = document.getElementById("heuristicRiskPill");
  const warningBox = document.getElementById("warningBox");
  const warningText = document.getElementById("warningText");
  const forensicSummaryText = document.getElementById("forensicSummaryText");

  // Indicator Containers
  const urgencyCount = document.getElementById("urgencyCount");
  const urgencyTags = document.getElementById("urgencyTags");
  const financialCount = document.getElementById("financialCount");
  const financialTags = document.getElementById("financialTags");
  const credentialCount = document.getElementById("credentialCount");
  const credentialTags = document.getElementById("credentialTags");
  const urlsCount = document.getElementById("urlsCount");
  const urlsList = document.getElementById("urlsList");

  // DOM Elements - Batch Scanner
  const fileDropzone = document.getElementById("fileDropzone");
  const batchFileInput = document.getElementById("batchFileInput");
  const batchTextInput = document.getElementById("batchTextInput");
  const btnLoadTestBatch = document.getElementById("btnLoadTestBatch");
  const btnBatchScan = document.getElementById("btnBatchScan");
  const btnBatchScanText = document.getElementById("btnBatchScanText");
  const batchSpinner = document.getElementById("batchSpinner");
  const batchTotalCount = document.getElementById("batchTotalCount");
  const batchSafeCount = document.getElementById("batchSafeCount");
  const batchThreatCount = document.getElementById("batchThreatCount");
  const batchThreatRate = document.getElementById("batchThreatRate");
  const batchTableBody = document.getElementById("batchTableBody");
  const filterBtns = document.querySelectorAll(".filter-pill");
  const countFilterAll = document.getElementById("countFilterAll");
  const countFilterThreat = document.getElementById("countFilterThreat");
  const countFilterSafe = document.getElementById("countFilterSafe");
  const btnExportCsv = document.getElementById("btnExportCsv");
  const btnExportJson = document.getElementById("btnExportJson");

  // Sample batch test cases
  const DEFAULT_BATCH_SAMPLES = [
    "Hi John, please find attached the Q3 financial report. Let me know if you have any questions.",
    "Congratulations! You have been selected as a winner of $1,000,000 in our international lottery! Click here to claim.",
    "Team meeting has been moved to 3pm today. Please update your calendars.",
    "Dear Valued Customer, your bank account will be deactivated. Verify your identity now at this link: http://fake-bank-login.xyz",
    "Reminder: your dental appointment is scheduled for next Tuesday at 2pm.",
    "Get rich quick! Invest in our revolutionary crypto scheme and earn 1000% returns in one week!",
    "Can you review the document I sent over yesterday? Looking forward to your feedback.",
    "FREE VIAGRA! Lowest prices online, no prescription needed. Order now!",
    "Thanks for the presentation yesterday, it was very informative.",
    "Nigerian prince needs your help to transfer $50 million dollars. You will receive 30% commission."
  ];

  /* --------------------------------------------------------------------------
     1. TAB NAVIGATION
     -------------------------------------------------------------------------- */
  navTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetTab = tab.getAttribute("data-tab");
      state.activeTab = targetTab;

      navTabs.forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");

      tabPanels.forEach((panel) => {
        panel.classList.remove("active");
      });
      const activePanel = document.getElementById(`panel${capitalize(targetTab)}`);
      if (activePanel) activePanel.classList.add("active");
    });
  });

  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  /* --------------------------------------------------------------------------
     2. DETECTION TYPE TOGGLE (EMAIL VS SMS)
     -------------------------------------------------------------------------- */
  modeBtnEmail.addEventListener("click", () => setSingleMode("email"));
  modeBtnSms.addEventListener("click", () => setSingleMode("sms"));

  function setSingleMode(mode) {
    state.singleMode = mode;
    if (mode === "email") {
      modeBtnEmail.classList.add("active");
      modeBtnEmail.setAttribute("aria-checked", "true");
      modeBtnSms.classList.remove("active");
      modeBtnSms.setAttribute("aria-checked", "false");
      inputCardTitle.textContent = "Email message content";
      inputCardDesc.textContent = "Paste the email subject or body to verify.";
      messageInput.placeholder = "Paste email subject and body text here to check for scams or spam...";
    } else {
      modeBtnSms.classList.add("active");
      modeBtnSms.setAttribute("aria-checked", "true");
      modeBtnEmail.classList.remove("active");
      modeBtnEmail.setAttribute("aria-checked", "false");
      inputCardTitle.textContent = "SMS / Text message content";
      inputCardDesc.textContent = "Paste short SMS messages, delivery texts, or lottery notifications.";
      messageInput.placeholder = "Paste SMS text (e.g., postal delivery alert, bank verification text) here...";
    }
    renderPresetChips();
  }

  batchModeEmail.addEventListener("click", () => {
    state.batchMode = "email";
    batchModeEmail.classList.add("active");
    batchModeSms.classList.remove("active");
  });

  batchModeSms.addEventListener("click", () => {
    state.batchMode = "sms";
    batchModeSms.classList.add("active");
    batchModeEmail.classList.remove("active");
  });

  /* --------------------------------------------------------------------------
     3. TEXTAREA INTERACTIONS & CHARACTER COUNT
     -------------------------------------------------------------------------- */
  messageInput.addEventListener("input", () => {
    const len = messageInput.value.length;
    charCount.textContent = `${len.toLocaleString()} character${len === 1 ? "" : "s"}`;
  });

  btnClear.addEventListener("click", () => {
    messageInput.value = "";
    charCount.textContent = "0 characters";
    messageInput.focus();
    resetVerdict();
  });

  btnPaste.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      messageInput.value = text;
      charCount.textContent = `${text.length.toLocaleString()} characters`;
      messageInput.focus();
    } catch {
      alert("Please paste directly into the box using Ctrl+V.");
    }
  });

  messageInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runScan();
    }
  });

  btnScan.addEventListener("click", runScan);

  /* --------------------------------------------------------------------------
     4. PRESETS FETCH & RENDER
     -------------------------------------------------------------------------- */
  async function loadPresets() {
    try {
      const res = await fetch("/api/presets");
      if (res.ok) {
        state.presets = await res.json();
        renderPresetChips();
      }
    } catch (e) {
      console.warn("Could not load presets from API:", e);
    }
  }

  function renderPresetChips() {
    if (!presetChipsContainer) return;
    presetChipsContainer.innerHTML = "";

    const filtered = state.presets.filter((p) => p.type === state.singleMode);
    const presetsToDisplay = filtered.length > 0 ? filtered : state.presets;

    presetsToDisplay.forEach((p) => {
      const btn = document.createElement("button");
      btn.className = "sample-chip";
      btn.textContent = p.title;
      btn.title = p.description || p.category;
      btn.addEventListener("click", () => {
        if (p.type !== state.singleMode) {
          setSingleMode(p.type);
        }
        messageInput.value = p.text;
        charCount.textContent = `${p.text.length.toLocaleString()} characters`;
        runScan();
      });
      presetChipsContainer.appendChild(btn);
    });
  }

  /* --------------------------------------------------------------------------
     5. SCAN EXECUTION (API CALL)
     -------------------------------------------------------------------------- */
  async function runScan() {
    const text = messageInput.value.trim();
    if (!text) {
      messageInput.focus();
      return;
    }

    setScanningState(true);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonBody({ text, mode: state.singleMode }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to analyze message");
      }

      const result = await res.json();
      renderVerdict(result);
    } catch (err) {
      alert(`Error checking message: ${err.message}`);
    } finally {
      setScanningState(false);
    }
  }

  function setScanningState(isScanning) {
    if (isScanning) {
      btnScan.disabled = true;
      btnScanText.textContent = "Checking...";
      scanSpinner.classList.remove("hidden");
    } else {
      btnScan.disabled = false;
      btnScanText.textContent = "Check Message";
      scanSpinner.classList.add("hidden");
    }
  }

  function jsonBody(obj) {
    return JSON.stringify(obj);
  }

  /* --------------------------------------------------------------------------
     6. VERDICT RENDERING
     -------------------------------------------------------------------------- */
  function resetVerdict() {
    emptyState.classList.remove("hidden");
    verdictContent.classList.add("hidden");
  }

  function renderVerdict(result) {
    emptyState.classList.add("hidden");
    verdictContent.classList.remove("hidden");

    const isThreat = result.is_threat;
    const confidence = Math.round(result.confidence || 0);
    const spamProb = Math.round(result.spam_probability || 0);

    // Friendly Banner
    verdictBanner.className = `verdict-callout ${isThreat ? "threat" : "safe"}`;
    verdictTitle.textContent = isThreat
      ? "Suspicious message detected"
      : "Looks safe";
    verdictClassification.textContent = isThreat
      ? "This message shows strong patterns typical of spam or phishing scams."
      : "No obvious signs of spam or malicious phishing were detected.";

    // Icon update
    if (verdictIconSvg) {
      if (isThreat) {
        verdictIconSvg.innerHTML = `<path stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>`;
      } else {
        verdictIconSvg.innerHTML = `<path stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>`;
      }
    }

    // Confidence badge & bar
    gaugePercent.textContent = `${confidence}% confidence`;
    spamProbVal.textContent = `${spamProb}%`;
    spamProbFill.style.width = `${spamProb}%`;
    spamProbFill.style.backgroundColor = isThreat ? "var(--threat-bar)" : "var(--safe-bar)";

    // Heuristic Risk Level
    const indicators = result.indicators || {};
    const riskLevel = (indicators.risk_level || "CLEAN").toLowerCase();
    const riskTitles = {
      clean: "Clean",
      low: "Low Risk",
      elevated: "Caution",
      high: "High Risk",
      critical: "Critical Risk"
    };
    heuristicRiskPill.textContent = riskTitles[riskLevel] || "Evaluated";
    heuristicRiskPill.className = `risk-badge ${riskLevel}`;

    // Warning
    if (result.warning) {
      warningBox.classList.remove("hidden");
      warningText.textContent = result.warning;
    } else {
      warningBox.classList.add("hidden");
    }

    // Indicator Groups
    renderIndicatorTags(urgencyCount, urgencyTags, indicators.urgency_triggers, "tag-urgency");
    renderIndicatorTags(financialCount, financialTags, indicators.financial_triggers, "tag-financial");
    renderIndicatorTags(credentialCount, credentialTags, indicators.credential_triggers, "tag-credential");
    renderUrls(urlsCount, urlsList, indicators.urls);

    // Summary Text
    forensicSummaryText.textContent = indicators.summary || "No threat markers identified.";
  }

  function renderIndicatorTags(countEl, containerEl, list, tagClass) {
    const items = list || [];
    countEl.textContent = items.length;
    containerEl.innerHTML = "";

    if (items.length === 0) {
      containerEl.innerHTML = `<span class="no-signals">None found</span>`;
      return;
    }

    items.forEach((item) => {
      const tag = document.createElement("span");
      tag.className = `indicator-tag ${tagClass}`;
      tag.textContent = item;
      containerEl.appendChild(tag);
    });
  }

  function renderUrls(countEl, containerEl, urlList) {
    const items = urlList || [];
    countEl.textContent = items.length;
    containerEl.innerHTML = "";

    if (items.length === 0) {
      containerEl.innerHTML = `<span class="no-signals">No links found</span>`;
      return;
    }

    items.forEach((u) => {
      const tag = document.createElement("div");
      tag.className = `indicator-tag tag-url`;
      const flagText = u.flags && u.flags.length > 0 ? ` (⚠️ ${u.flags.join(", ")})` : "";
      tag.textContent = `${u.host || u.url}${flagText}`;
      containerEl.appendChild(tag);
    });
  }

  /* --------------------------------------------------------------------------
     7. BATCH SCANNER
     -------------------------------------------------------------------------- */
  btnLoadTestBatch.addEventListener("click", () => {
    batchTextInput.value = DEFAULT_BATCH_SAMPLES.join("\n");
  });

  // Drag and drop handling
  fileDropzone.addEventListener("click", () => batchFileInput.click());

  fileDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileDropzone.classList.add("dragover");
  });

  fileDropzone.addEventListener("dragleave", () => {
    fileDropzone.classList.remove("dragover");
  });

  fileDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      handleBatchFile(e.dataTransfer.files[0]);
    }
  });

  batchFileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleBatchFile(e.target.files[0]);
    }
  });

  function handleBatchFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      batchTextInput.value = content;
      executeBatchScan();
    };
    reader.readAsText(file);
  }

  btnBatchScan.addEventListener("click", executeBatchScan);

  async function executeBatchScan() {
    const text = batchTextInput.value.trim();
    if (!text) {
      batchTextInput.focus();
      return;
    }

    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return;

    btnBatchScan.disabled = true;
    btnBatchScanText.textContent = "Checking Messages...";
    batchSpinner.classList.remove("hidden");

    try {
      const res = await fetch("/api/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonBody({ items: lines, mode: state.batchMode }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Batch check failed");
      }

      const data = await res.json();
      state.batchResults = data.results || [];
      renderBatchSummary(data.summary);
      renderBatchTable();
    } catch (err) {
      alert(`Batch Error: ${err.message}`);
    } finally {
      btnBatchScan.disabled = false;
      btnBatchScanText.textContent = "Check All Messages";
      batchSpinner.classList.add("hidden");
    }
  }

  function renderBatchSummary(summary) {
    if (!summary) return;
    batchTotalCount.textContent = summary.total.toLocaleString();
    batchSafeCount.textContent = summary.safe_count.toLocaleString();
    batchThreatCount.textContent = summary.threat_count.toLocaleString();
    batchThreatRate.textContent = `${summary.threat_percentage}%`;

    countFilterAll.textContent = summary.total;
    countFilterThreat.textContent = summary.threat_count;
    countFilterSafe.textContent = summary.safe_count;
  }

  // Filter Buttons
  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.activeBatchFilter = btn.getAttribute("data-filter");
      renderBatchTable();
    });
  });

  function renderBatchTable() {
    batchTableBody.innerHTML = "";

    const filtered = state.batchResults.filter((item) => {
      if (state.activeBatchFilter === "threat") return item.is_threat;
      if (state.activeBatchFilter === "safe") return !item.is_threat;
      return true;
    });

    if (filtered.length === 0) {
      batchTableBody.innerHTML = `<tr><td colspan="6" class="table-empty-row">No messages matching this filter.</td></tr>`;
      return;
    }

    filtered.forEach((item) => {
      const tr = document.createElement("tr");

      const statusTag = item.is_threat
        ? `<span class="verdict-tag threat">Suspicious</span>`
        : `<span class="verdict-tag safe">Safe</span>`;

      tr.innerHTML = `
        <td>${item.index}</td>
        <td>${statusTag}</td>
        <td class="table-snippet" title="${escapeHtml(item.text)}">${escapeHtml(item.preview)}</td>
        <td><strong>${Math.round(item.confidence)}%</strong></td>
        <td>${item.indicator_count > 0 ? `<span style="color: #b45309;">${item.indicator_count} signals</span>` : `<span style="color: #94a3b8;">None</span>`}</td>
        <td><button class="table-action-link" data-text="${escapeHtml(item.text)}">Inspect</button></td>
      `;

      tr.querySelector(".table-action-link").addEventListener("click", (e) => {
        const textToInspect = e.target.getAttribute("data-text");
        inspectSingleFromBatch(textToInspect);
      });

      batchTableBody.appendChild(tr);
    });
  }

  function inspectSingleFromBatch(text) {
    // Switch to single tab
    const singleTab = document.getElementById("tabBtnSingle");
    if (singleTab) singleTab.click();

    // Populate and run scan
    messageInput.value = text;
    charCount.textContent = `${text.length.toLocaleString()} characters`;
    runScan();
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /* --------------------------------------------------------------------------
     8. EXPORT CSV & JSON
     -------------------------------------------------------------------------- */
  btnExportJson.addEventListener("click", () => {
    if (state.batchResults.length === 0) {
      alert("No batch data to export.");
      return;
    }
    const jsonStr = JSON.stringify(state.batchResults, null, 2);
    downloadFile(jsonStr, "inbox_sentinel_results.json", "application/json");
  });

  btnExportCsv.addEventListener("click", () => {
    if (state.batchResults.length === 0) {
      alert("No batch data to export.");
      return;
    }
    let csv = "Index,Verdict,Confidence,SpamProbability,SignalsCount,Message\n";
    state.batchResults.forEach((r) => {
      const status = r.is_threat ? "Suspicious" : "Safe";
      const cleanMsg = `"${r.text.replace(/"/g, '""')}"`;
      csv += `${r.index},${status},${r.confidence},${r.spam_probability},${r.indicator_count},${cleanMsg}\n`;
    });
    downloadFile(csv, "inbox_sentinel_results.csv", "text/csv");
  });

  function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Initialize
  loadPresets();
});
