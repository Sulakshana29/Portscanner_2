/* =========================================================
   NetScan Pro – Scanner JS
   Handles: async scan polling, live results, filter, export
   ========================================================= */

(function () {
  "use strict";

  // --- State ---
  let scanId = null;
  let pollTimer = null;
  let allResults = {};
  let currentFilter = "all";
  let isScanning = false;

  // --- DOM refs ---
  const form          = document.getElementById("scan-form");
  const btnScan       = document.getElementById("btn-scan");
  const hostInput     = document.getElementById("host-input");
  const portsInput    = document.getElementById("ports-input");
  const timeoutInput  = document.getElementById("timeout-input");
  const bannerCheck   = document.getElementById("banner-check");

  const progressSec   = document.getElementById("progress-section");
  const progressFill  = document.getElementById("progress-fill");
  const progressLabel = document.getElementById("progress-label");
  const progressDone  = document.getElementById("progress-done");
  const progressTotal = document.getElementById("progress-total");
  const progressOpen  = document.getElementById("progress-open");
  const progressSecs  = document.getElementById("progress-secs");

  const statsSec      = document.getElementById("stats-bar");
  const statTotal     = document.getElementById("stat-total");
  const statOpen      = document.getElementById("stat-open");
  const statClosed    = document.getElementById("stat-closed");
  const statTime      = document.getElementById("stat-time");

  const resultsSec    = document.getElementById("results-section");
  const resultsTitle  = document.getElementById("results-title");
  const tableBody     = document.getElementById("results-tbody");

  const flashArea     = document.getElementById("flash-area");
  const historyList   = document.getElementById("history-list");

  const btnFilterAll    = document.getElementById("filter-all");
  const btnFilterOpen   = document.getElementById("filter-open");
  const btnFilterClosed = document.getElementById("filter-closed");
  const btnExportCsv    = document.getElementById("btn-export-csv");
  const btnExportJson   = document.getElementById("btn-export-json");

  // --- Port presets ---
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      portsInput.value = btn.dataset.ports;
    });
  });

  // --- Form submit → async scan ---
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isScanning) return;

    clearFlash();
    const host = hostInput.value.trim();
    if (!host) { showFlash("Please enter a hostname or IP.", "warning"); return; }

    isScanning = true;
    btnScan.disabled = true;
    btnScan.textContent = "⚡ Scanning…";

    allResults = {};
    currentFilter = "all";
    setFilterActive(btnFilterAll);
    tableBody.innerHTML = "";
    resultsSec.classList.remove("visible");
    statsSec.classList.remove("visible");
    progressSec.classList.add("visible");
    setProgress(0, 0, 0, 0, 0);
    updateExportButtons(null);

    const payload = {
      host,
      ports:        portsInput.value.trim(),
      timeout:      timeoutInput.value.trim() || "0.8",
      grab_banner:  bannerCheck.checked ? "true" : "false",
    };

    try {
      const res = await fetch("/scan/async", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (!res.ok) {
        showFlash(data.error || "Scan failed.", "danger");
        resetScanUI();
        return;
      }

      scanId = data.scan_id;
      progressTotal.textContent = data.total;
      updateExportButtons(scanId);
      if (data.warning) { showFlash("⚠️ " + data.warning, "warning"); }
      pollTimer = setTimeout(poll, 300);

    } catch (err) {
      showFlash("Network error: " + err.message, "danger");
      resetScanUI();
    }
  });

  // --- Polling loop ---
  async function poll() {
    if (!scanId) return;
    try {
      const res  = await fetch(`/scan/progress/${scanId}`);
      const data = await res.json();

      if (!res.ok) {
        showFlash(data.error || "Polling error.", "danger");
        resetScanUI();
        return;
      }

      const pct = data.total > 0 ? Math.round((data.done / data.total) * 100) : 0;
      const openCount = Object.values(data.results).filter(r => r.open).length;

      setProgress(pct, data.done, data.total, openCount, data.elapsed);

      // Merge new results into table
      mergeResults(data.results);

      if (data.status === "done") {
        finalizeScan(data);
        return;
      }

      pollTimer = setTimeout(poll, 400);
    } catch (err) {
      pollTimer = setTimeout(poll, 800); // retry on transient error
    }
  }

  function setProgress(pct, done, total, open, elapsed) {
    progressFill.style.width = pct + "%";
    progressLabel.textContent = pct + "%";
    progressDone.textContent  = done;
    if (total) progressTotal.textContent = total;
    progressOpen.textContent  = open;
    progressSecs.textContent  = elapsed.toFixed(1) + "s";
  }

  function finalizeScan(data) {
    allResults = data.results;
    const openCount   = Object.values(allResults).filter(r => r.open).length;
    const closedCount = Object.keys(allResults).length - openCount;

    setProgress(100, data.done, data.total, openCount, data.elapsed);

    // Stats bar
    statTotal.textContent  = data.total;
    statOpen.textContent   = openCount;
    statClosed.textContent = closedCount;
    statTime.textContent   = data.elapsed.toFixed(2) + "s";
    statsSec.classList.add("visible");

    // Results
    resultsTitle.textContent = `Results for ${hostInput.value.trim()}`;
    resultsSec.classList.add("visible");

    renderTable(allResults, currentFilter);
    refreshHistory();
    resetScanUI();
  }

  // --- Result rendering ---
  function mergeResults(incoming) {
    let changed = false;
    for (const [port, r] of Object.entries(incoming)) {
      if (!allResults[port]) {
        allResults[port] = r;
        changed = true;
      }
    }
    if (changed) renderTable(allResults, currentFilter);
  }

  function renderTable(results, filter) {
    const sorted = Object.entries(results)
      .map(([p, r]) => ({ port: parseInt(p), ...r }))
      .sort((a, b) => a.port - b.port);

    const rows = sorted.filter(r => {
      if (filter === "open")   return r.open;
      if (filter === "closed") return !r.open;
      return true;
    });

    tableBody.innerHTML = "";
    if (rows.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" class="no-results">No ports match the current filter.</td></tr>`;
      return;
    }

    rows.forEach((r, idx) => {
      const rowDelay = Math.min(idx * 18, 300);

      // Main row
      const tr = document.createElement("tr");
      tr.dataset.port   = r.port;
      tr.dataset.open   = r.open ? "1" : "0";
      tr.style.animationDelay = rowDelay + "ms";
      tr.innerHTML = `
        <td><strong>${r.port}</strong></td>
        <td><span class="status-dot ${r.open ? "status-open" : "status-closed"}">${r.open ? "Open" : "Closed"}</span></td>
        <td>${escHtml(r.service || "—")}</td>
        <td>${escHtml(r.version || "—")}</td>
        <td>${r.os_hint ? `<span class="os-hint">${escHtml(r.os_hint)}</span>` : "<span style='color:var(--text-dim)'>—</span>"}</td>
        <td><span class="risk-badge risk-${r.risk}">${r.risk}</span></td>
      `;
      tableBody.appendChild(tr);

      // Banner detail row (collapsible)
      if (r.open && r.banner) {
        const bannerTr = document.createElement("tr");
        bannerTr.className = "banner-row";
        bannerTr.dataset.forPort = r.port;
        bannerTr.innerHTML = `
          <td colspan="6">
            <div class="banner-content">${escHtml(r.banner)}</div>
          </td>`;
        tableBody.appendChild(bannerTr);

        tr.addEventListener("click", () => {
          bannerTr.classList.toggle("open");
        });
        tr.title = "Click to toggle banner";
      }
    });
  }

  // --- Filters ---
  [btnFilterAll, btnFilterOpen, btnFilterClosed].forEach(btn => {
    btn.addEventListener("click", () => {
      currentFilter = btn.dataset.filter;
      setFilterActive(btn);
      renderTable(allResults, currentFilter);
    });
  });

  function setFilterActive(activeBtn) {
    [btnFilterAll, btnFilterOpen, btnFilterClosed].forEach(b => b.classList.remove("active"));
    activeBtn.classList.add("active");
  }

  // --- Export ---
  function updateExportButtons(id) {
    if (id) {
      btnExportCsv.href  = `/export/csv/${id}`;
      btnExportJson.href = `/export/json/${id}`;
      btnExportCsv.classList.remove("hidden");
      btnExportJson.classList.remove("hidden");
    } else {
      btnExportCsv.classList.add("hidden");
      btnExportJson.classList.add("hidden");
    }
  }

  // --- History ---
  async function refreshHistory() {
    try {
      const res  = await fetch("/history");
      const data = await res.json();
      historyList.innerHTML = "";
      if (data.length === 0) {
        historyList.innerHTML = `<p style="font-size:0.75rem;color:var(--text-dim);text-align:center">No scans yet</p>`;
        return;
      }
      data.forEach(entry => {
        const div = document.createElement("div");
        div.className = "history-item";
        div.innerHTML = `
          <div class="history-host">${escHtml(entry.host)}</div>
          <div class="history-meta">
            <span class="h-open">${entry.open} open</span>
            <span>${entry.total} ports</span>
            <span>${entry.elapsed}s</span>
            <span>${entry.ts}</span>
          </div>`;
        div.addEventListener("click", () => {
          hostInput.value = entry.host;
        });
        historyList.appendChild(div);
      });
    } catch (_) {}
  }

  // --- Flash messages ---
  function showFlash(msg, type = "warning") {
    const div = document.createElement("div");
    div.className = `flash ${type}`;
    div.textContent = msg;
    flashArea.appendChild(div);
    setTimeout(() => div.remove(), 6000);
  }

  function clearFlash() { flashArea.innerHTML = ""; }

  // --- Reset UI after scan ---
  function resetScanUI() {
    isScanning = false;
    btnScan.disabled  = false;
    btnScan.textContent = "⚡ Start Scan";
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  // --- Escape HTML ---
  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // --- Init: load history on page load ---
  refreshHistory();
})();
