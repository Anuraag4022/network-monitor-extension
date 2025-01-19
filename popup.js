chrome.storage.local.get(["logs"], (data) => {
    const logs = data.logs || [];
    const logContainer = document.getElementById("logs");
    logContainer.innerHTML = logs.map((log) => `<div>${log}</div>`).join("");
  });
  