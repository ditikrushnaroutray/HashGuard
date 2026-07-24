/**
 * HashGuard Sentinel - Background Service Worker
 * Registers context menu for inspecting selected passwords and stores selection for popup auto-fill.
 */

// Register context menu on installation
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "checkHashGuard",
    title: "Check this password with HashGuard",
    contexts: ["selection"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "checkHashGuard" && info.selectionText) {
    // Store selected password under key 'autoFillPassword' for popup auto-fill
    chrome.storage.local.set({ autoFillPassword: info.selectionText.trim() });
  }
});
