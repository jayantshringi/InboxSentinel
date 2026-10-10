/**
 * InboxSentinel Frontend Application Logic
 * Enhanced with Threat Heatmap Highlighter, Email Header Forensics (.EML),
 * and Local Scan History.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  const state = {
    activeTab: "single",
    singleMode: "email",
    batchMode: "email",
    viewMode: "editor", // "editor" | "heatmap"
    presets: [],
    batchResults: [],
    activeBatchFilter: "all",
    scanHistory: loadHistoryFromStorage(),
    lastScanResult: null,
  };

  // DOM Elements - Navigation & Header
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const btnToggleHistory = document.getElementById("btnToggleHistory");
  const historyCountBadge = document.getElementById("historyCountBadge");

  // DOM Elements - Mode Switcher
  const modeBtnEmail = document.getElementById("modeBtnEmail");
  const modeBtnSms = document.getElementById("modeBtnSms");
  const modeBtnEml = document.getElementById("modeBtnEml");
  const batchModeEmail = document.getElementById("batchModeEmail");
  const batchModeSms = document.getElementById("batchModeSms");

  // DOM Elements - Single Inspector Input & Views
  const messageInput = document.getElementById("messageInput");
  const charCount = document.getElementById("charCount");
  const btnScan = document.getElementById("btnScan");
  const btnScanText = document.getElementById("btnScanText");
  const scanSpinner = document.getElementById("scanSpinner");
  const btnClear = document.getElementById("btnClear");
  const btnPaste = document.getElementById("btnPaste");
  const btnUploadSingle = document.getElementById("btnUploadSingle");
  const singleFileInput = document.getElementById("singleFileInput");
  const presetChipsContainer = document.getElementById("presetChipsContainer");
  const inputCardTitle = document.getElementById("inputCardTitle");
  const inputCardDesc = document.getElementById("inputCardDesc");

  // View Mode Switcher Elements
  const btnViewEditor = document.getElementById("btnViewEditor");
  const btnViewHeatmap = document.getElementById("btnViewHeatmap");
  const heatmapBadge = document.getElementById("heatmapBadge");
  const viewHint = document.getElementById("viewHint");
  const editorContainer = document.getElementById("editorContainer");
  const heatmapContainer = document.getElementById("heatmapContainer");
  const heatmapBody = document.getElementById("heatmapBody");

  // DOM Elements - Results Card
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

  // Header Forensics Elements
  const headerForensicsCard = document.getElementById("headerForensicsCard");
  const headerAuthPill = document.getElementById("headerAuthPill");
  const metaFrom = document.getElementById("metaFrom");
  const metaReplyTo = document.getElementById("metaReplyTo");
  const rowReplyTo = document.getElementById("rowReplyTo");
  const metaSubject = document.getElementById("metaSubject");
  const headerAlertsContainer = document.getElementById("headerAlertsContainer");
  const headerAlertsList = document.getElementById("headerAlertsList");

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

  // History Drawer Elements
  const historyOverlay = document.getElementById("historyOverlay");
  const btnCloseHistory = document.getElementById("btnCloseHistory");
  const historyList = document.getElementById("historyList");
  const historyCountText = document.getElementById("historyCountText");
  const btnClearHistory = document.getElementById("btnClearHistory");
  const btnExportHistoryJson = document.getElementById("btnExportHistoryJson");
  const btnExportHistoryCsv = document.getElementById("btnExportHistoryCsv");

  // Default Batch Sample Emails
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
     2. DETECTION TYPE TOGGLE (EMAIL, SMS, EML)
     -------------------------------------------------------------------------- */
  modeBtnEmail.addEventListener("click", () => setSingleMode("email"));
  modeBtnSms.addEventListener("click", () => setSingleMode("sms"));
  if (modeBtnEml) {
    modeBtnEml.addEventListener("click", () => setSingleMode("eml"));
  }

  function setSingleMode(mode) {
    state.singleMode = mode;
    const modeButtons = [modeBtnEmail, modeBtnSms, modeBtnEml].filter(Boolean);
    modeButtons.forEach((btn) => {
      const isMatch = btn.getAttribute("data-mode") === mode;
      btn.classList.toggle("active", isMatch);
      btn.setAttribute("aria-checked", isMatch ? "true" : "false");
    });

    if (mode === "email") {
      inputCardTitle.textContent = "Email message content";
      inputCardDesc.textContent = "Paste the email subject or body to verify.";
      messageInput.placeholder = "Paste email subject and body text here to check for scams or spam...";
    } else if (mode === "sms") {
      inputCardTitle.textContent = "SMS / Text message content";
      inputCardDesc.textContent = "Paste short SMS messages, delivery texts, or prize alerts.";
      messageInput.placeholder = "Paste SMS text (e.g., postal delivery alert, bank verification text) here...";
    } else if (mode === "eml") {
      inputCardTitle.textContent = ".EML Email with Headers";
      inputCardDesc.textContent = "Inspect raw RFC 822 email headers, sender SPF/DKIM, and body.";
      messageInput.placeholder = "Paste raw .eml text with headers (From:, Subject:, Date:) or drop a .eml file...";
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
     3. VIEW MODE TOGGLE (EDITOR VS HEATMAP)
     -------------------------------------------------------------------------- */
  btnViewEditor.addEventListener("click", () => setViewMode("editor"));
  btnViewHeatmap.addEventListener("click", () => setViewMode("heatmap"));

  function setViewMode(mode) {
    state.viewMode = mode;
    if (mode === "editor") {
      btnViewEditor.classList.add("active");
      btnViewHeatmap.classList.remove("active");
      editorContainer.classList.remove("hidden");
      heatmapContainer.classList.add("hidden");
      viewHint.textContent = "Live text editor";
    } else {
      btnViewHeatmap.classList.add("active");
      btnViewEditor.classList.remove("active");
      editorContainer.classList.add("hidden");
      heatmapContainer.classList.remove("hidden");
      viewHint.textContent = "Highlighted threat tokens";
    }
  }

  /* --------------------------------------------------------------------------
     4. FILE UPLOADS & TEXTAREA INTERACTIONS
     -------------------------------------------------------------------------- */
  messageInput.addEventListener("input", () => {
    const text = messageInput.value;
    charCount.textContent = `${text.length.toLocaleString()} character${text.length === 1 ? "" : "s"}`;

    // Auto-detect EML headers if pasted
    if (state.singleMode !== "eml" && text.length > 30) {
      if (text.startsWith("From: ") || (text.includes("\nFrom: ") && text.includes("\nSubject: "))) {
        setSingleMode("eml");
      }
    }
  });

  btnClear.addEventListener("click", () => {
    messageInput.value = "";
    charCount.textContent = "0 characters";
    messageInput.focus();
    resetVerdict();
    setViewMode("editor");
    btnViewHeatmap.disabled = true;
    heatmapBadge.classList.add("hidden");
  });

  btnPaste.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      messageInput.value = text;
      charCount.textContent = `${text.length.toLocaleString()} characters`;
      messageInput.focus();
      if (text.startsWith("From: ") || (text.includes("\nFrom: ") && text.includes("\nSubject: "))) {
        setSingleMode("eml");
      }
    } catch {
      alert("Please paste directly into the box using Ctrl+V.");
    }
  });

  // Single file upload button & drop on textarea
  btnUploadSingle.addEventListener("click", () => singleFileInput.click());

  singleFileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleSingleUploadFile(e.target.files[0]);
    }
  });

  messageInput.addEventListener("dragover", (e) => {
    e.preventDefault();
    messageInput.style.borderColor = "var(--border-focus)";
  });

  messageInput.addEventListener("dragleave", () => {
    messageInput.style.borderColor = "";
  });

  messageInput.addEventListener("drop", (e) => {
    e.preventDefault();
    messageInput.style.borderColor = "";
    if (e.dataTransfer.files.length > 0) {
      handleSingleUploadFile(e.dataTransfer.files[0]);
    }
  });

  function handleSingleUploadFile(file) {
    const isEml = file.name.toLowerCase().endsWith(".eml") || file.name.toLowerCase().endsWith(".msg");
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      messageInput.value = content;
      charCount.textContent = `${content.length.toLocaleString()} characters`;
      if (isEml) {
        setSingleMode("eml");
      }
      runScan();
    };
    reader.readAsText(file);
  }

  messageInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runScan();
    }
  });

  btnScan.addEventListener("click", runScan);

  /* --------------------------------------------------------------------------
     5. PRESETS FETCH & RENDER
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
     6. SCAN EXECUTION (API CALL)
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
      state.lastScanResult = result;
      renderVerdict(result, text);
      saveScanToHistory(result, text);
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
     7. VERDICT RENDERING & HEATMAP GENERATION
     -------------------------------------------------------------------------- */
  function resetVerdict() {
    emptyState.classList.remove("hidden");
    verdictContent.classList.add("hidden");
    if (headerForensicsCard) headerForensicsCard.classList.add("hidden");
  }

  function renderVerdict(result, rawText) {
    emptyState.classList.add("hidden");
    verdictContent.classList.remove("hidden");

    const isThreat = result.is_threat;
    const confidence = Math.round(result.confidence || 0);
    const spamProb = Math.round(result.spam_probability || 0);

    // Friendly Banner
    verdictBanner.className = `verdict-callout ${isThreat ? "threat" : "safe"}`;
    verdictTitle.textContent = isThreat
      ? "Suspicious threat detected"
      : "Looks safe";
    verdictClassification.textContent = isThreat
      ? "This message displays manipulative urgency, phishing traps, or header spoofing."
      : "No obvious signs of spam, phishing traps, or spoofing detected.";

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

    // Header Forensics Card
    renderHeaderForensics(result);

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

    // Render Threat Heatmap Highlighting
    const spans = result.highlight_spans || [];
    renderHeatmap(rawText, spans);

    // Enable Threat Heatmap Tab
    btnViewHeatmap.disabled = false;
    if (spans.length > 0) {
      heatmapBadge.textContent = spans.length;
      heatmapBadge.classList.remove("hidden");
    } else {
      heatmapBadge.classList.add("hidden");
    }
  }

  function renderHeaderForensics(result) {
    if (!headerForensicsCard) return;

    const hi = result.header_info;
    const alerts = result.header_alerts || [];

    if (!hi && alerts.length === 0) {
      headerForensicsCard.classList.add("hidden");
      return;
    }

    headerForensicsCard.classList.remove("hidden");
    metaFrom.textContent = hi && hi.from_raw ? hi.from_raw : "Not specified in header";
    metaSubject.textContent = hi && hi.subject ? hi.subject : "(No subject header)";

    if (hi && hi.reply_to) {
      rowReplyTo.style.display = "flex";
      metaReplyTo.textContent = hi.reply_to;
    } else {
      rowReplyTo.style.display = "none";
    }

    // Authentication Pill
    if (alerts.length > 0) {
      headerAuthPill.textContent = "Security Flagged";
      headerAuthPill.className = "auth-pill auth-fail";
    } else {
      headerAuthPill.textContent = "Headers Clean";
      headerAuthPill.className = "auth-pill auth-pass";
    }

    // Alerts List
    if (alerts.length > 0) {
      headerAlertsContainer.classList.remove("hidden");
      headerAlertsList.innerHTML = "";
      alerts.forEach((alert) => {
        const item = document.createElement("div");
        item.className = "alert-badge-item";
        item.innerHTML = `
          <span class="alert-severity-tag">${alert.severity || "FLAG"}</span>
          <span>${escapeHtml(alert.message)}</span>
        `;
        headerAlertsList.appendChild(item);
      });
    } else {
      headerAlertsContainer.classList.add("hidden");
      headerAlertsList.innerHTML = "";
    }
  }

  function renderHeatmap(text, spans) {
    if (!text || spans.length === 0) {
      heatmapBody.innerHTML = escapeHtml(text || "No text available");
      return;
    }

    let html = "";
    let lastIdx = 0;

    spans.forEach((span) => {
      // Non-highlighted text before this span
      if (span.start > lastIdx) {
        html += escapeHtml(text.substring(lastIdx, span.start));
      }

      // Highlighted token
      const tokenText = text.substring(span.start, span.end);
      const categoryClass = `threat-${span.category || "urgency"}`;
      html += `<mark class="threat-mark ${categoryClass}" title="${escapeHtml(span.label || "Threat Trigger")}: ${escapeHtml(tokenText)}">${escapeHtml(tokenText)}</mark>`;

      lastIdx = span.end;
    });

    // Remaining text after last span
    if (lastIdx < text.length) {
      html += escapeHtml(text.substring(lastIdx));
    }

    heatmapBody.innerHTML = html;
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
     8. BATCH SCANNER
     -------------------------------------------------------------------------- */
  btnLoadTestBatch.addEventListener("click", () => {
    batchTextInput.value = DEFAULT_BATCH_SAMPLES.join("\n");
  });

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
    const singleTab = document.getElementById("tabBtnSingle");
    if (singleTab) singleTab.click();

    messageInput.value = text;
    charCount.textContent = `${text.length.toLocaleString()} characters`;
    runScan();
  }

  /* --------------------------------------------------------------------------
     9. SCAN HISTORY DRAWER (LOCAL STORAGE)
     -------------------------------------------------------------------------- */
  function loadHistoryFromStorage() {
    try {
      const stored = localStorage.getItem("inbox_sentinel_history");
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  function saveHistoryToStorage(history) {
    try {
      localStorage.setItem("inbox_sentinel_history", JSON.stringify(history));
    } catch (e) {
      console.warn("Storage full or unavailable:", e);
    }
  }

  function saveScanToHistory(result, rawText) {
    const entry = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      date: new Date().toLocaleDateString(),
      text: rawText,
      preview: rawText.substring(0, 140) + (rawText.length > 140 ? "..." : ""),
      is_threat: result.is_threat,
      confidence: Math.round(result.confidence || 0),
      mode: result.mode || state.singleMode,
      signals: (result.indicators && result.indicators.indicator_score) || 0
    };

    // Prepend and limit to 40 recent items
    state.scanHistory.unshift(entry);
    if (state.scanHistory.length > 40) {
      state.scanHistory.pop();
    }
    saveHistoryToStorage(state.scanHistory);
    updateHistoryBadge();
  }

  function updateHistoryBadge() {
    const count = state.scanHistory.length;
    if (historyCountBadge) historyCountBadge.textContent = count;
    if (historyCountText) historyCountText.textContent = `${count} scan${count === 1 ? "" : "s"} logged in history`;
  }

  function renderHistoryDrawer() {
    updateHistoryBadge();
    historyList.innerHTML = "";

    if (state.scanHistory.length === 0) {
      historyList.innerHTML = `<div class="history-empty">No scan history recorded yet. Messages checked in this session will appear here.</div>`;
      return;
    }

    state.scanHistory.forEach((item) => {
      const div = document.createElement("div");
      div.className = "history-item";

      const verdictClass = item.is_threat ? "history-verdict-threat" : "history-verdict-safe";
      const verdictLabel = item.is_threat ? "Threat" : "Safe";

      div.innerHTML = `
        <div class="history-item-top">
          <span class="history-verdict-pill ${verdictClass}">${verdictLabel}</span>
          <span class="history-timestamp">${item.date} ${item.timestamp}</span>
        </div>
        <div class="history-item-preview">${escapeHtml(item.preview)}</div>
        <div class="history-item-footer">
          <span>Mode: ${item.mode.toUpperCase()}</span>
          <span><strong>${item.confidence}%</strong> confidence</span>
        </div>
      `;

      div.addEventListener("click", () => {
        // Load into inspector
        messageInput.value = item.text;
        charCount.textContent = `${item.text.length.toLocaleString()} characters`;
        setSingleMode(item.mode || "email");
        closeHistoryDrawer();
        const singleTab = document.getElementById("tabBtnSingle");
        if (singleTab) singleTab.click();
        runScan();
      });

      historyList.appendChild(div);
    });
  }

  function openHistoryDrawer() {
    renderHistoryDrawer();
    historyOverlay.classList.remove("hidden");
  }

  function closeHistoryDrawer() {
    historyOverlay.classList.add("hidden");
  }

  btnToggleHistory.addEventListener("click", openHistoryDrawer);
  btnCloseHistory.addEventListener("click", closeHistoryDrawer);
  historyOverlay.addEventListener("click", (e) => {
    if (e.target === historyOverlay) {
      closeHistoryDrawer();
    }
  });

  btnClearHistory.addEventListener("click", () => {
    if (confirm("Are you sure you want to clear your local scan history?")) {
      state.scanHistory = [];
      saveHistoryToStorage([]);
      renderHistoryDrawer();
    }
  });

  btnExportHistoryJson.addEventListener("click", () => {
    if (state.scanHistory.length === 0) {
      alert("No history to export.");
      return;
    }
    const jsonStr = JSON.stringify(state.scanHistory, null, 2);
    downloadFile(jsonStr, "inbox_sentinel_history.json", "application/json");
  });

  btnExportHistoryCsv.addEventListener("click", () => {
    if (state.scanHistory.length === 0) {
      alert("No history to export.");
      return;
    }
    let csv = "ID,Date,Time,Mode,Verdict,Confidence,Message\n";
    state.scanHistory.forEach((h) => {
      const status = h.is_threat ? "Suspicious" : "Safe";
      const cleanMsg = `"${h.text.replace(/"/g, '""')}"`;
      csv += `${h.id},${h.date},${h.timestamp},${h.mode},${status},${h.confidence},${cleanMsg}\n`;
    });
    downloadFile(csv, "inbox_sentinel_history.csv", "text/csv");
  });

  /* --------------------------------------------------------------------------
     10. EXPORT BATCH CSV & JSON
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

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initialize
  updateHistoryBadge();
  loadPresets();
});
