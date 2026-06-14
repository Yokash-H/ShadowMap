/**
 * ShadowBox Extension — Popup Controller
 */

const API_BASE = "http://127.0.0.1:8000";
const DASHBOARD_URL = "http://localhost:5173";

document.addEventListener("DOMContentLoaded", async () => {
  checkConnection();
  loadAnalyses();

  // File upload handler
  document.getElementById("fileInput").addEventListener("change", handleFileUpload);

  // Dashboard button
  document.getElementById("openDashboard").addEventListener("click", () => {
    chrome.tabs.create({ url: DASHBOARD_URL });
  });

  // Drag and drop
  const zone = document.getElementById("uploadZone");
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.style.borderColor = "#6366f1";
    zone.style.background = "rgba(99, 102, 241, 0.08)";
  });
  zone.addEventListener("dragleave", () => {
    zone.style.borderColor = "rgba(99, 102, 241, 0.3)";
    zone.style.background = "rgba(99, 102, 241, 0.02)";
  });
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.style.borderColor = "rgba(99, 102, 241, 0.3)";
    zone.style.background = "rgba(99, 102, 241, 0.02)";
    if (e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });
});

async function checkConnection() {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  try {
    const res = await fetch(`${API_BASE}/`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      dot.classList.remove("offline");
      text.textContent = "ShadowBox engine online";
    } else {
      throw new Error("not ok");
    }
  } catch {
    dot.classList.add("offline");
    text.textContent = "Engine offline — start the backend";
  }
}

async function loadAnalyses() {
  const list = document.getElementById("analysisList");
  try {
    const res = await fetch(`${API_BASE}/api/analyses`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error("fetch failed");
    const analyses = await res.json();

    if (analyses.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="icon">📭</div>
          <div class="text">No analyses yet. Upload a file to get started.</div>
        </div>`;
      return;
    }

    list.innerHTML = analyses.slice(0, 5).map((a) => `
      <div class="analysis-item" data-id="${a.id}">
        <div class="name">${escapeHtml(a.filename)}</div>
        <div class="meta">
          <span class="time">${timeAgo(a.created_at)}</span>
          <span class="badge ${a.risk_level || a.status}">${a.status === "completed" ? a.risk_level : a.status}</span>
        </div>
      </div>
    `).join("");

    // Click to open in dashboard
    list.querySelectorAll(".analysis-item").forEach((item) => {
      item.addEventListener("click", () => {
        chrome.tabs.create({ url: `${DASHBOARD_URL}/analysis/${item.dataset.id}` });
      });
    });
  } catch {
    list.innerHTML = `
      <div class="empty-state">
        <div class="icon">⚠️</div>
        <div class="text">Cannot connect to ShadowBox backend.</div>
      </div>`;
  }
}

function handleFileUpload(e) {
  if (e.target.files.length > 0) {
    uploadFile(e.target.files[0]);
  }
}

async function uploadFile(file) {
  const ext = "." + file.name.split(".").pop().toLowerCase();
  const allowed = [".sh", ".py", ".jar", ".apk"];

  if (!allowed.includes(ext)) {
    alert(`Unsupported file type: ${ext}\nSupported: ${allowed.join(", ")}`);
    return;
  }

  const zone = document.getElementById("uploadZone");
  zone.innerHTML = `
    <div class="icon">⏳</div>
    <div class="title">Uploading ${escapeHtml(file.name)}...</div>
    <div class="subtitle">Sending to ShadowBox engine</div>`;

  try {
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload failed");
    }

    const result = await res.json();

    zone.innerHTML = `
      <div class="icon">✅</div>
      <div class="title">Analysis Started!</div>
      <div class="subtitle">Opening dashboard...</div>`;

    // Open dashboard
    chrome.tabs.create({ url: `${DASHBOARD_URL}/analysis/${result.analysis_id}` });

    // Reload analyses list
    setTimeout(loadAnalyses, 1000);
  } catch (err) {
    zone.innerHTML = `
      <div class="icon">❌</div>
      <div class="title">Upload Failed</div>
      <div class="subtitle">${escapeHtml(err.message)}</div>`;

    setTimeout(() => {
      zone.innerHTML = `
        <div class="icon">📁</div>
        <div class="title">Upload File for Analysis</div>
        <div class="subtitle">Supports .sh, .py, .jar, .apk</div>`;
    }, 3000);
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function timeAgo(dateStr) {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
