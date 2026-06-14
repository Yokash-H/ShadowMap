/**
 * ShadowBox Chrome Extension — Background Service Worker
 * Detects file downloads and offers analysis through ShadowBox.
 */

const SHADOWBOX_API = "http://127.0.0.1:8000/api";
const DASHBOARD_URL = "http://localhost:5173";
const ANALYZABLE_EXTENSIONS = [".sh", ".py", ".jar", ".apk"];

// Listen for file downloads
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const filename = downloadItem.filename || downloadItem.url || "";
  const ext = getExtension(filename);

  if (ANALYZABLE_EXTENSIONS.includes(ext)) {
    const pendingAnalysis = {
      downloadId: downloadItem.id,
      filename: filename,
      url: downloadItem.url,
      fileSize: downloadItem.fileSize,
      extension: ext,
      timestamp: Date.now(),
    };

    // Store the download info for the popup
    await chrome.storage.local.set({ pendingAnalysis });

    // Show notification
    chrome.notifications.create(`shadowbox-${downloadItem.id}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "⚠️ ShadowBox Alert",
      message: `Suspicious file detected: ${getBasename(filename)}\nAutomatically analyzing with ShadowBox...`,
      priority: 2,
      requireInteraction: false,
    });

    // Automatically open the extension popup as a window
    try {
      chrome.windows.create({
        url: chrome.runtime.getURL("popup.html"),
        type: "popup",
        width: 380,
        height: 480,
        focused: true
      });
    } catch (err) {
      console.error("Failed to open popup window:", err);
    }

    // Automatically trigger the analysis
    analyzeFile(pendingAnalysis);
  }
});

// Handle notification click
chrome.notifications.onClicked.addListener(async (notificationId) => {
  if (notificationId.startsWith("shadowbox-")) {
    const data = await chrome.storage.local.get("pendingAnalysis");
    if (data.pendingAnalysis) {
      // Just focus or open the dashboard again if clicked
      chrome.tabs.create({
        url: `${DASHBOARD_URL}`,
      });
    }
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_FILE") {
    analyzeFile(message.data).then(sendResponse);
    return true; // async response
  }

  if (message.type === "GET_ANALYSES") {
    fetchAnalyses().then(sendResponse);
    return true;
  }

  if (message.type === "GET_ANALYSIS") {
    fetchAnalysis(message.analysisId).then(sendResponse);
    return true;
  }
});

async function analyzeFile(downloadInfo) {
  try {
    // For downloaded files, we need to read and upload them
    // Since service workers can't directly access file paths,
    // we'll fetch the URL and upload it
    const response = await fetch(downloadInfo.url);
    const blob = await response.blob();

    const formData = new FormData();
    formData.append(
      "file",
      blob,
      getBasename(downloadInfo.filename)
    );

    const uploadResponse = await fetch(`${SHADOWBOX_API}/analyze`, {
      method: "POST",
      body: formData,
    });

    if (!uploadResponse.ok) {
      throw new Error(`Upload failed: ${uploadResponse.statusText}`);
    }

    const result = await uploadResponse.json();

    // Store analysis ID
    const analyses = (await chrome.storage.local.get("analyses"))
      .analyses || [];
    analyses.unshift({
      id: result.analysis_id,
      filename: getBasename(downloadInfo.filename),
      timestamp: Date.now(),
      status: "running",
    });
    await chrome.storage.local.set({ analyses: analyses.slice(0, 20) });

    // Open dashboard to analysis page
    chrome.tabs.create({
      url: `${DASHBOARD_URL}/analysis/${result.analysis_id}`,
    });

    return { success: true, analysisId: result.analysis_id };
  } catch (error) {
    console.error("[ShadowBox] Analysis failed:", error);
    return { success: false, error: error.message };
  }
}

async function fetchAnalyses() {
  try {
    const response = await fetch(`${SHADOWBOX_API}/analyses`);
    if (!response.ok) throw new Error("Failed to fetch analyses");
    return await response.json();
  } catch (error) {
    return [];
  }
}

async function fetchAnalysis(analysisId) {
  try {
    const response = await fetch(
      `${SHADOWBOX_API}/analysis/${analysisId}`
    );
    if (!response.ok) throw new Error("Analysis not found");
    return await response.json();
  } catch (error) {
    return null;
  }
}

function getExtension(filename) {
  const parts = filename.split(".");
  return parts.length > 1 ? "." + parts.pop().toLowerCase() : "";
}

function getBasename(filepath) {
  return filepath.split(/[/\\]/).pop() || filepath;
}
