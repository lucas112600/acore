import {
  base64ToArrayBuffer,
  arrayBufferToBase64,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveECDHSharedSecret,
  encryptAESGCM,
  decryptAESGCM
} from '../crypto-helper.js';

let ecdhSharedKey = null;
let currentAccounts = [];
let localTimerInterval = null;
const isExtensionContext = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage;

const CHAPTERS_ORDER = ['intro', 'install', 'crypto', 'backup-schema', 'audit-spec'];
const CHAPTERS_METADATA = {
  'intro': { title: '系統簡介' },
  'install': { title: '安裝指南' },
  'crypto': { title: '密碼學架構' },
  'backup-schema': { title: '備份檔案格式' },
  'audit-spec': { title: '審計日誌規範' }
};

// --- Docusaurus View Navigation & Routing ---
function switchView(viewName, targetChapter = null) {
  const viewHome = document.getElementById("view-home");
  const viewDocs = document.getElementById("view-docs");
  const viewDashboard = document.getElementById("view-dashboard");

  // Reset navbar active tabs
  document.querySelectorAll(".navbar__link").forEach(l => l.classList.remove("navbar__link--active"));

  // Hide all main containers
  viewHome.classList.add("hidden");
  viewDocs.classList.add("hidden");
  viewDashboard.classList.add("hidden");

  if (viewName === "home") {
    viewHome.classList.remove("hidden");
    document.getElementById("nav-home").classList.add("navbar__link--active");
    window.scrollTo({ top: 0, behavior: "auto" });
  } else if (viewName === "docs") {
    viewDocs.classList.remove("hidden");
    document.getElementById("nav-docs").classList.add("navbar__link--active");
    
    // Default to 'intro' if no chapter provided
    const chapter = targetChapter || 'intro';
    showDocChapter(chapter);
  } else if (viewName === "dashboard") {
    viewDashboard.classList.remove("hidden");
    document.getElementById("nav-dashboard").classList.add("navbar__link--active");
    window.scrollTo({ top: 0, behavior: "auto" });
    if (isExtensionContext) {
      checkStatus();
    }
  }
}

function showDocChapter(chapterId) {
  // Hide all articles
  document.querySelectorAll(".doc-chapter").forEach(ch => ch.classList.add("hidden"));

  // Show target article
  const activeChapter = document.getElementById(`chapter-${chapterId}`);
  if (activeChapter) {
    activeChapter.classList.remove("hidden");
  }

  // Sync left sidebar button highlights
  document.querySelectorAll(".sidebar-link").forEach(link => {
    if (link.dataset.chapter === chapterId) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });

  // Re-build Table of Contents on the right
  generateTOC(chapterId);

  // Update previous/next pagination footer links
  updatePagination(chapterId);

  // Scroll reader window to top
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// --- Dynamic Table of Contents (TOC) Builder ---
function generateTOC(chapterId) {
  const activeChapter = document.getElementById(`chapter-${chapterId}`);
  const tocList = document.getElementById("toc-list");
  if (!tocList) return;
  tocList.innerHTML = "";

  if (!activeChapter) return;

  const headings = activeChapter.querySelectorAll("h3");
  const tocSidebar = document.querySelector(".toc-sidebar");

  if (headings.length === 0) {
    if (tocSidebar) tocSidebar.classList.add("hidden");
    return;
  }
  if (tocSidebar) tocSidebar.classList.remove("hidden");

  headings.forEach((heading, idx) => {
    // Generate anchor ID if not present
    if (!heading.id) {
      heading.id = `${chapterId}-heading-${idx}`;
    }

    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = `#${heading.id}`;
    a.className = "toc-link";
    a.textContent = heading.textContent.trim();

    a.addEventListener("click", (e) => {
      e.preventDefault();
      const targetElement = document.getElementById(heading.id);
      if (targetElement) {
        const offsetPosition = targetElement.offsetTop - 80; // Offset for top sticky navbar
        window.scrollTo({
          top: offsetPosition,
          behavior: "smooth"
        });
      }
      
      document.querySelectorAll(".toc-link").forEach(l => l.classList.remove("active"));
      a.classList.add("active");
    });

    li.appendChild(a);
    tocList.appendChild(li);
  });
}

// --- Scroll Spy Header Tracer ---
function initScrollSpy() {
  window.addEventListener("scroll", () => {
    const docsView = document.getElementById("view-docs");
    if (docsView.classList.contains("hidden")) return;

    const activeChapter = document.querySelector(".doc-chapter:not(.hidden)");
    if (!activeChapter) return;

    const headings = Array.from(activeChapter.querySelectorAll("h3"));
    if (headings.length === 0) return;

    let currentActive = headings[0];
    const scrollPosition = window.scrollY + 100; // Account for navbar height

    for (let i = 0; i < headings.length; i++) {
      if (headings[i].offsetTop <= scrollPosition) {
        currentActive = headings[i];
      } else {
        break;
      }
    }

    if (currentActive) {
      document.querySelectorAll(".toc-link").forEach(link => {
        if (link.getAttribute("href") === `#${currentActive.id}`) {
          link.classList.add("active");
        } else {
          link.classList.remove("active");
        }
      });
    }
  });
}

// --- Previous / Next Doc Pagination Page ---
function updatePagination(chapterId) {
  const currentIndex = CHAPTERS_ORDER.indexOf(chapterId);
  const btnPrev = document.getElementById("btn-prev-page");
  const btnNext = document.getElementById("btn-next-page");
  const labelPrev = document.getElementById("label-prev-page");
  const labelNext = document.getElementById("label-next-page");

  if (currentIndex > 0) {
    btnPrev.classList.remove("hidden");
    const prevChapter = CHAPTERS_ORDER[currentIndex - 1];
    labelPrev.textContent = CHAPTERS_METADATA[prevChapter].title;
    btnPrev.onclick = () => showDocChapter(prevChapter);
  } else {
    btnPrev.classList.add("hidden");
  }

  if (currentIndex < CHAPTERS_ORDER.length - 1) {
    btnNext.classList.remove("hidden");
    const nextChapter = CHAPTERS_ORDER[currentIndex + 1];
    labelNext.textContent = CHAPTERS_METADATA[nextChapter].title;
    btnNext.onclick = () => showDocChapter(nextChapter);
  } else {
    btnNext.classList.add("hidden");
  }
}

// --- Dark / Light Mode Switcher ---
function initThemeToggle() {
  const themeToggle = document.getElementById("theme-toggle");
  if (!themeToggle) return;

  const savedTheme = localStorage.getItem("theme-choice") || "light";
  document.documentElement.setAttribute("data-theme", savedTheme);

  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    localStorage.setItem("theme-choice", nextTheme);
  });
}

// --- Copy Code Blocks ---
function initCopySnippets() {
  const copyButtons = document.querySelectorAll(".btn-copy");
  copyButtons.forEach(btn => {
    btn.addEventListener("click", async () => {
      const targetId = btn.dataset.target;
      const codeEl = document.getElementById(targetId);
      if (!codeEl) return;

      try {
        await navigator.clipboard.writeText(codeEl.textContent);
        const originalText = btn.textContent;
        btn.textContent = "已複製！";
        setTimeout(() => {
          btn.textContent = originalText;
        }, 1500);
      } catch (err) {
        console.error("Failed to copy code snippet", err);
      }
    });
  });
}

// --- Toast Notifications ---
function showToast(text) {
  const toast = document.getElementById("toast");
  toast.textContent = text;
  toast.classList.remove("hidden");
  const newToast = toast.cloneNode(true);
  toast.parentNode.replaceChild(newToast, toast);
  setTimeout(() => {
    newToast.classList.add("hidden");
  }, 1500);
}

// --- Web UI View Toggle (inside Dashboard) ---
function showWebView(viewId) {
  document.querySelectorAll('.web-view').forEach(view => view.classList.add('hidden'));
  document.getElementById(viewId).classList.remove('hidden');
}

// --- Secure Messaging Bridge ---
async function establishSecureChannel() {
  const keyPair = await generateECDHKeyPair();
  const exportedPubKey = await exportPublicKey(keyPair.publicKey);

  const attemptConnect = (retriesLeft) => {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage({
          type: "CONNECT_IPC",
          publicKey: exportedPubKey
        }, async (response) => {
          if (chrome.runtime.lastError) {
            const errMsg = chrome.runtime.lastError.message;
            if (retriesLeft > 0 && (errMsg.includes("Could not establish connection") || errMsg.includes("Receiving end does not exist"))) {
              setTimeout(() => {
                attemptConnect(retriesLeft - 1).then(resolve).catch(reject);
              }, 150);
              return;
            }
            reject(new Error(errMsg));
            return;
          }
          if (!response || !response.success) {
            reject(new Error(response ? response.error : "ECDH secure handshake failed"));
            return;
          }
        try {
          const bgPubKey = await importPublicKey(response.publicKey);
          ecdhSharedKey = await deriveECDHSharedSecret(keyPair.privateKey, bgPubKey);
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    });
  };

  return attemptConnect(4); // Try up to 5 times (1 initial + 4 retries)
}

async function sendEncryptedRequest(action, params = {}, isRetry = false) {
  if (!ecdhSharedKey) {
    if (isRetry) throw new Error("Secure communication channel not established");
    await establishSecureChannel();
    return sendEncryptedRequest(action, params, true);
  }
  const encryptedReq = await encryptAESGCM(ecdhSharedKey, JSON.stringify({ action, params }));
  
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage({
        type: "ENCRYPTED_MSG",
        iv: encryptedReq.iv,
        ciphertext: encryptedReq.ciphertext
      }, async (response) => {
        if (chrome.runtime.lastError) {
          if (!isRetry) {
            try {
              await establishSecureChannel();
              resolve(await sendEncryptedRequest(action, params, true));
            } catch (e) { reject(e); }
            return;
          }
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response) {
          reject(new Error("Empty response from database sandbox"));
          return;
        }

        if (response.type === "ENCRYPTED_MSG") {
          try {
            const decryptedStr = await decryptAESGCM(ecdhSharedKey, response.iv, response.ciphertext);
            const res = JSON.parse(decryptedStr);
            if (res.success) {
              resolve(res.data);
            } else {
              reject(new Error(res.error || res.data?.error || "Vault rejected request"));
            }
          } catch (err) {
            if (!isRetry) {
              try {
                await establishSecureChannel();
                resolve(await sendEncryptedRequest(action, params, true));
              } catch (e) { reject(e); }
              return;
            }
            reject(new Error("IPC Decryption error: " + err.message));
          }
        } else {
          if (!isRetry && response.error && response.error.includes("IPC channel")) {
            try {
              await establishSecureChannel();
              resolve(await sendEncryptedRequest(action, params, true));
            } catch (e) { reject(e); }
            return;
          }
          reject(new Error(response.error || "Unexpected raw response"));
        }
      });
    } catch (e) {
      if (e.message && e.message.includes("Extension context invalidated")) {
        window.location.reload();
      } else {
        reject(e);
      }
    }
  });
}

// --- Render Live Web Accounts Grid ---
function renderWebAccounts(accounts) {
  currentAccounts = accounts;
  const gridEl = document.getElementById("web-accounts-grid");
  const emptyEl = document.getElementById("web-empty-state");
  gridEl.innerHTML = "";

  if (accounts.length === 0) {
    emptyEl.classList.remove("hidden");
    return;
  }
  emptyEl.classList.add("hidden");

  accounts.forEach(acc => {
    const card = document.createElement("div");
    card.className = "web-account-card";

    // Stacked layout (Issuer top, code middle, email bottom)
    card.innerHTML = `
      <div class="web-acc-top-meta">
        <div class="web-acc-issuer-label">${acc.issuer}</div>
        <button class="web-btn-delete" data-id="${acc.id}" title="雙擊以刪除">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6" />
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          </svg>
        </button>
      </div>
      
      <div class="web-acc-middle-row" data-id="${acc.id}" data-label="${acc.issuer}:${acc.name}" title="點擊直接複製">
        <div class="web-totp-val">${acc.totp}</div>
        <div class="web-acc-controls">
          <svg class="card-progress-ring" width="16" height="16" viewBox="0 0 16 16">
            <circle class="card-progress-ring__circle" stroke="#5f6368" stroke-width="8" fill="transparent" cx="8" cy="8" r="4" stroke-dasharray="25.13" stroke-dashoffset="0" />
          </svg>
        </div>
      </div>

      <div class="web-acc-bottom-meta">
        <div class="web-acc-name-label">${acc.name}</div>
      </div>
    `;

    // Click to copy code
    const middleEl = card.querySelector(".web-acc-middle-row");
    middleEl.addEventListener("click", async () => {
      const code = middleEl.querySelector(".web-totp-val").textContent.replace(/\s/g, "");
      if (code === "ERR_KEY") return;
      try {
        await navigator.clipboard.writeText(code);
        showToast("已複製驗證碼");
        await sendEncryptedRequest("LOG_EVENT", { event: `Copied TOTP via Web Dashboard for: ${middleEl.dataset.label}` });
      } catch (err) {
        console.error("Copy failed:", err);
      }
    });

    // Double click to delete
    const delBtn = card.querySelector(".web-btn-delete");
    let confirmDel = false;
    delBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirmDel) {
        confirmDel = true;
        delBtn.style.color = "var(--accent-red)";
        delBtn.setAttribute("title", "再次點擊確認刪除！");
        showToast("再次點擊刪除按鈕以確認刪除此金鑰");
        setTimeout(() => {
          confirmDel = false;
          delBtn.style.color = "";
          delBtn.setAttribute("title", "雙擊以刪除");
        }, 3000);
      } else {
        try {
          await sendEncryptedRequest("DELETE_ACCOUNT", { id: delBtn.dataset.id });
          showToast("金鑰帳戶已刪除");
          loadDashboardData();
        } catch (err) {
          showToast("刪除失敗：" + err.message);
        }
      }
    });

    gridEl.appendChild(card);
  });
}

// --- Live Dashboard Updates ---
async function loadDashboardData() {
  try {
    const accounts = await sendEncryptedRequest("GET_ACCOUNTS_TOTP");
    renderWebAccounts(accounts);
  } catch (err) {
    if (err.message === "VAULT_LOCKED") {
      clearInterval(localTimerInterval);
      showWebView("web-locked-view");
    } else {
      showToast("載入失敗：" + err.message);
    }
  }
}

function startTimerLoop() {
  if (localTimerInterval) clearInterval(localTimerInterval);
  currentAccounts = []; // Clear cache to trigger initial render on unlock

  const circle = document.getElementById("web-timer-circle");
  const timerText = document.getElementById("web-timer-text");
  const circumference = 2 * Math.PI * 13; // 81.68

  const update = async () => {
    const time = Math.floor(Date.now() / 1000);
    const remaining = 30 - (time % 30);
    
    // Update dashboard header timer circle
    if (circle) {
      const offset = circumference - (remaining / 30) * circumference;
      circle.style.strokeDashoffset = offset;
    }
    if (timerText) {
      timerText.textContent = `${remaining}s`;
    }

    // Sync individual card timer rings
    const cardCircles = document.querySelectorAll(".card-progress-ring__circle");
    const cardCircumference = 25.13;
    const cardOffset = (1 - (remaining / 30)) * cardCircumference;
    cardCircles.forEach(cc => {
      cc.style.strokeDashoffset = cardOffset;
      if (remaining <= 5) {
        cc.setAttribute("stroke", "var(--accent-red)");
      } else {
        cc.setAttribute("stroke", "#5f6368");
      }
    });

    if (remaining === 30 || currentAccounts.length === 0) {
      await loadDashboardData();
    }
  };

  update();
  localTimerInterval = setInterval(update, 1000);
}

// --- Check Session Status ---
async function checkStatus() {
  try {
    const status = await sendEncryptedRequest("GET_STATUS");
    if (!status.initialized) {
      showWebView("web-setup-view");
    } else if (!status.unlocked) {
      showWebView("web-locked-view");
    } else {
      showWebView("web-unlocked-view");
      startTimerLoop();
    }
  } catch (err) {
    console.error("Status check error:", err);
    showToast("通道載入錯誤，請重新開啟此頁面");
  }
}

// --- Initialize App & Event Binds ---
document.addEventListener("DOMContentLoaded", async () => {
  initThemeToggle();
  initCopySnippets();
  initScrollSpy();

  // Navigation Links Binding
  document.getElementById("nav-brand").addEventListener("click", (e) => {
    e.preventDefault();
    switchView("home");
  });
  document.getElementById("nav-home").addEventListener("click", (e) => {
    e.preventDefault();
    switchView("home");
  });
  document.getElementById("nav-docs").addEventListener("click", (e) => {
    e.preventDefault();
    switchView("docs");
  });
  document.getElementById("nav-api").addEventListener("click", (e) => {
    e.preventDefault();
    switchView("docs", "crypto");
    document.getElementById("nav-api").classList.add("navbar__link--active");
  });
  document.getElementById("nav-dashboard").addEventListener("click", (e) => {
    e.preventDefault();
    switchView("dashboard");
  });

  // Home CTA Buttons Binding
  document.getElementById("hero-get-started").addEventListener("click", () => {
    switchView("docs");
  });
  document.getElementById("hero-go-dashboard").addEventListener("click", () => {
    switchView("dashboard");
  });


  // Left sidebar menu item clicks
  document.querySelectorAll(".sidebar-link").forEach(link => {
    link.addEventListener("click", () => {
      showDocChapter(link.dataset.chapter);
    });
  });

  // Footer link menu clicks
  document.querySelectorAll(".footer-link-item").forEach(link => {
    const chapter = link.getAttribute("data-chapter");
    if (chapter) {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        switchView("docs", chapter);
      });
    }
  });



  // Default to showing Home view first
  switchView("home");

  // Check if loaded standalone without background extension sandbox
  if (!isExtensionContext) {
    const dashboardSection = document.getElementById("chapter-dashboard");
    dashboardSection.innerHTML = `
      <header class="doc-header">
        <div class="doc-badge">金鑰驗證中心</div>
        <h2>連接未建立</h2>
        <p class="lead">此說明網頁目前以本機檔案載入，無法直接連接擴充功能的安全金鑰庫。</p>
      </header>
      <div class="security-warning" style="margin-top:20px;">
        <svg viewBox="0 0 24 24" class="warning-icon"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        <div style="display:flex; flex-direction:column; gap:4px;">
          <h4 style="color:var(--text-main); font-size:14px; font-weight:700;">使用擴充功能分頁開啟</h4>
          <span style="font-size:12.5px; color:var(--text-muted); line-height:1.5;">
            請先將外掛載入 Chrome，接著打開外掛 Popup 視窗，並點擊頂部工具列最左側的<strong>「開啟網頁版儀表板 (彎頭指引箭頭)」</strong>按鈕，即可建立安全的加密通訊管道！
          </span>
        </div>
      </div>
    `;
    return;
  }

  // Active Extension context: run Handshake & unlock listener loops
  try {
    await establishSecureChannel();
    await checkStatus();
  } catch (err) {
    console.error("IPC Handshake failed", err);
    showToast("安全加密通道連線失敗");
  }

  // --- Initial Setup Form Submit ---
  const formSetup = document.getElementById("web-form-setup");
  formSetup.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("web-setup-password").value;
    const confirm = document.getElementById("web-setup-confirm").value;

    if (pw.length < 8) {
      showToast("主密碼長度必須至少 8 個字元");
      return;
    }
    if (pw !== confirm) {
      showToast("兩次輸入的密碼不一致");
      return;
    }

    try {
      await sendEncryptedRequest("INITIALIZE_VAULT", { password: pw });
      showToast("防禦矩陣資料庫初始化完成！");
      showWebView("web-unlocked-view");
      startTimerLoop();
    } catch (err) {
      showToast("部署失敗：" + err.message);
    }
  });

  // Setup password strength indicator
  const passwordInput = document.getElementById("web-setup-password");
  const strengthFill = document.getElementById("web-strength-fill");
  const strengthLabel = document.getElementById("web-strength-label");
  passwordInput.addEventListener("input", () => {
    const val = passwordInput.value;
    let score = 0;
    if (val.length >= 8) score += 1;
    if (/[a-z]/.test(val) && /[A-Z]/.test(val)) score += 1;
    if (/\d/.test(val)) score += 1;
    if (/[^A-Za-z0-9]/.test(val)) score += 1;

    let color = "var(--accent-red)";
    let text = "密碼強度：弱 (建議大小寫混和及符號)";
    let width = "25%";

    if (val.length === 0) {
      width = "0%";
      text = "密碼強度：未輸入";
    } else if (score === 2) {
      color = "#f59e0b";
      text = "密碼強度：中等";
      width = "50%";
    } else if (score === 3) {
      color = "var(--primary)";
      text = "密碼強度：良好";
      width = "75%";
    } else if (score === 4) {
      color = "var(--accent-green)";
      text = "密碼強度：強健";
      width = "100%";
    }

    strengthFill.style.width = width;
    strengthFill.style.backgroundColor = color;
    strengthLabel.textContent = text;
  });

  // --- Unlock Vault Form Submit ---
  const formUnlock = document.getElementById("web-form-unlock");
  formUnlock.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("web-unlock-password").value;
    const errorEl = document.getElementById("web-unlock-error");

    try {
      errorEl.classList.add("hidden");
      await sendEncryptedRequest("UNLOCK_VAULT", { password: pw });
      document.getElementById("web-unlock-password").value = "";
      showWebView("web-unlocked-view");
      startTimerLoop();
    } catch (err) {
      errorEl.classList.remove("hidden");
      errorEl.textContent = err.message === "INCORRECT_PASSWORD" ? "密碼錯誤，解密失敗！" : "錯誤：" + err.message;
    }
  });

  // --- Manual Lock ---
  document.getElementById("web-btn-lock").addEventListener("click", async () => {
    try {
      await sendEncryptedRequest("LOCK_VAULT");
      clearInterval(localTimerInterval);
      showWebView("web-locked-view");
      showToast("安全庫已手動鎖定");
    } catch (err) {
      showToast("鎖定失敗：" + err.message);
    }
  });

  // --- Modal Add 2FA triggers ---
  const modalAdd = document.getElementById("web-modal-add");
  document.getElementById("web-btn-open-add").addEventListener("click", () => {
    modalAdd.classList.remove("hidden");
    document.getElementById("web-add-issuer").focus();
  });
  document.getElementById("web-btn-close-add").addEventListener("click", () => modalAdd.classList.add("hidden"));
  document.getElementById("web-btn-cancel-add").addEventListener("click", () => modalAdd.classList.add("hidden"));

  // Add Account Submit
  const formAdd = document.getElementById("web-form-add");
  formAdd.addEventListener("submit", async (e) => {
    e.preventDefault();
    const issuer = document.getElementById("web-add-issuer").value;
    const name = document.getElementById("web-add-name").value;
    let secret = document.getElementById("web-add-secret").value;
    const errorEl = document.getElementById("web-add-error");

    secret = secret.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z2-7]+=*$/.test(secret)) {
      errorEl.classList.remove("hidden");
      return;
    }
    errorEl.classList.add("hidden");

    try {
      await sendEncryptedRequest("ADD_ACCOUNT", { issuer, name, secret });
      showToast("2FA 金鑰寫入成功！");
      modalAdd.classList.add("hidden");
      formAdd.reset();
      loadDashboardData();
    } catch (err) {
      showToast("寫入失敗：" + err.message);
    }
  });

  // --- Modal Logs triggers ---
  const modalLogs = document.getElementById("web-modal-logs");
  const tbodyLogs = document.getElementById("web-logs-tbody");
  document.getElementById("web-btn-open-logs").addEventListener("click", async () => {
    try {
      const logs = await sendEncryptedRequest("GET_AUDIT_LOGS");
      tbodyLogs.innerHTML = "";
      if (logs.length === 0) {
        tbodyLogs.innerHTML = `<tr><td colspan="2" style="text-align:center; color:var(--text-dark);">無日誌資料</td></tr>`;
      } else {
        logs.slice().reverse().forEach(log => {
          const tr = document.createElement("tr");
          const dateStr = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + new Date(log.timestamp).toLocaleDateString();
          tr.innerHTML = `
            <td>${dateStr}</td>
            <td>${log.event}</td>
          `;
          tbodyLogs.appendChild(tr);
        });
      }
      modalLogs.classList.remove("hidden");
    } catch (err) {
      showToast("載入日誌失敗：" + err.message);
    }
  });
  document.getElementById("web-btn-close-logs").addEventListener("click", () => modalLogs.classList.add("hidden"));
  document.getElementById("web-btn-close-logs-footer").addEventListener("click", () => modalLogs.classList.add("hidden"));

  // --- Modal Backup triggers ---
  const modalBackup = document.getElementById("web-modal-backup-panel");
  document.getElementById("web-btn-open-backup").addEventListener("click", () => {
    modalBackup.classList.remove("hidden");
    resetBackupModalStates();
  });
  document.getElementById("web-btn-close-backup").addEventListener("click", () => modalBackup.classList.add("hidden"));

  function resetBackupModalStates() {
    document.getElementById("web-import-file").value = "";
    document.getElementById("web-selected-filename").textContent = "未選擇任何檔案";
    document.getElementById("web-backup-password-group").classList.add("hidden");
    document.getElementById("web-btn-submit-import").classList.add("hidden");
    document.getElementById("web-import-error").classList.add("hidden");
  }

  // Backup Export
  document.getElementById("web-btn-export-file").addEventListener("click", async () => {
    try {
      const backupObj = await sendEncryptedRequest("EXPORT_BACKUP");
      const blob = new Blob([JSON.stringify(backupObj, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `defimatrix_backup_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      showToast("已成功導出備份檔案");
      await sendEncryptedRequest("LOG_EVENT", { event: "Exported security backup file via Web Dashboard" });
    } catch (err) {
      showToast("導出失敗：" + err.message);
    }
  });

  // Backup Import selectors
  const fileInput = document.getElementById("web-import-file");
  const triggerBtn = document.getElementById("web-btn-trigger-file");
  const filenameSpan = document.getElementById("web-selected-filename");
  const passwordGroup = document.getElementById("web-backup-password-group");
  const importSubmitBtn = document.getElementById("web-btn-submit-import");
  
  triggerBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      filenameSpan.textContent = fileInput.files[0].name;
      passwordGroup.classList.remove("hidden");
      importSubmitBtn.classList.remove("hidden");
    } else {
      resetBackupModalStates();
    }
  });

  // Import Submit
  importSubmitBtn.addEventListener("click", () => {
    const file = fileInput.files[0];
    const password = document.getElementById("web-backup-password").value;
    const errorEl = document.getElementById("web-import-error");

    if (!password) {
      showToast("請輸入該備份檔密碼");
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        errorEl.classList.add("hidden");
        const backupData = JSON.parse(e.target.result);
        await sendEncryptedRequest("IMPORT_BACKUP", { backupData, password });
        showToast("備份還原載入成功！");
        modalBackup.classList.add("hidden");
        resetBackupModalStates();
        loadDashboardData();
      } catch (err) {
        errorEl.classList.remove("hidden");
        errorEl.textContent = err.message === "INCORRECT_PASSWORD" ? "密碼錯誤，無法解密此備份！" : "還原失敗：" + err.message;
      }
    };
    reader.readAsText(file);
  });
});
