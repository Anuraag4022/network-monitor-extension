let requestCounts = {};
const trustedDomains = ["google.com", "facebook.com", "cdn.net"]; // Example trusted domains
let lastNotificationTime = 0;
const notificationCooldown = 30000; // 30 seconds cooldown

// Notify user of suspicious activity
const notifyUser = (title, message) => {
  const currentTime = Date.now();
  if (currentTime - lastNotificationTime > notificationCooldown) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icon.png",
      title: title,
      message: message,
    });
    lastNotificationTime = currentTime;
  }
};

// Function to analyze traffic for potential DDoS attacks
const analyzeTraffic = (details) => {
  const currentTime = Date.now();
  const ip = details.initiator || "unknown";
  const url = details.url;

  // Skip trusted domains
  if (trustedDomains.some((domain) => url.includes(domain))) {
    return;
  }

  if (!requestCounts[ip]) {
    requestCounts[ip] = [];
  }

  // Add timestamp of the request
  requestCounts[ip].push(currentTime);

  // Filter requests older than 60 seconds
  requestCounts[ip] = requestCounts[ip].filter(
    (timestamp) => currentTime - timestamp < 60000
  );

  // Trigger alert only if the number of requests exceeds 200 in 60 seconds
  if (requestCounts[ip].length > 100) {
    notifyUser("Potential DDoS detected!", `Source: ${ip}`);
  }
};

// Function to detect potential XSS attacks
const detectXSS = (details) => {
  const url = details.url;

  try {
    // Parse query parameters
    const urlParams = new URL(url).searchParams;

    for (const [key, value] of urlParams) {
      // Check specific keys for XSS patterns
      if (/((%3C|<).*?(script|img).*?(%3E|>))/i.test(value)) {
        notifyUser("Potential XSS Detected", `URL: ${url}`);
        return;
      }
    }
  } catch (error) {
    console.error("Error analyzing URL for XSS:", error);
  }
};

// Event listener to monitor network requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    analyzeTraffic(details);
    detectXSS(details);
  },
  { urls: ["<all_urls>"] }
);
