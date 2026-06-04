import {
  base64ToArrayBuffer,
  arrayBufferToBase64,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveECDHSharedSecret,
  encryptAESGCM,
  decryptAESGCM
} from './crypto-helper.js';

let ecdhSharedKey = null;
let currentAccounts = [];
let localTimerInterval = null;
let isEditMode = false;

// --- Screen Router ---
function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(scr => scr.classList.add('hidden'));
  document.getElementById(screenId).classList.remove('hidden');

  // Toggle header actions visibility - only display on the main dashboard screen
  const showHeaderActions = (screenId === "screen-dashboard");
  const btnSettings = document.getElementById("btn-open-settings");
  const btnScan = document.getElementById("btn-open-scan");
  const btnEdit = document.getElementById("btn-toggle-edit");

  if (btnSettings) {
    if (showHeaderActions) btnSettings.classList.remove("hidden");
    else btnSettings.classList.add("hidden");
  }
  if (btnScan) {
    if (showHeaderActions) btnScan.classList.remove("hidden");
    else btnScan.classList.add("hidden");
  }
  if (btnEdit) {
    if (showHeaderActions) btnEdit.classList.remove("hidden");
    else btnEdit.classList.add("hidden");
  }

  // Auto-close settings modal when leaving dashboard
  if (!showHeaderActions) {
    const modalSettings = document.getElementById("modal-settings");
    if (modalSettings) modalSettings.classList.add("hidden");
  }
}

// --- Toast Notifications ---
function showToast(text) {
  const toast = document.getElementById("toast");
  toast.textContent = text;
  toast.classList.remove("hidden");
  // Clone element to reset animation
  const newToast = toast.cloneNode(true);
  toast.parentNode.replaceChild(newToast, toast);
  setTimeout(() => {
    newToast.classList.add("hidden");
  }, 1500);
}

// --- ECDH Handshake & Encrypted Messaging Channel ---

async function establishSecureChannel() {
  const keyPair = await generateECDHKeyPair();
  const exportedPubKey = await exportPublicKey(keyPair.publicKey);

  const attemptConnect = (retriesLeft) => {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: "CONNECT_IPC",
        publicKey: exportedPubKey
      }, async (response) => {
        if (chrome.runtime.lastError) {
          const errMsg = chrome.runtime.lastError.message;
          // Retry if background service worker is starting up and not yet ready
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
          reject(new Error(response ? response.error : "Secure handshake failed"));
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

async function sendEncryptedRequest(action, params = {}) {
  if (!ecdhSharedKey) {
    throw new Error("Secure communication channel not established");
  }
  const encryptedReq = await encryptAESGCM(ecdhSharedKey, JSON.stringify({ action, params }));
  
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({
      type: "ENCRYPTED_MSG",
      iv: encryptedReq.iv,
      ciphertext: encryptedReq.ciphertext
    }, async (response) => {
      if (chrome.runtime.lastError) {
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
            reject(new Error(res.data.error || "Vault process rejected request"));
          }
        } catch (err) {
          reject(new Error("IPC Decryption error: " + err.message));
        }
      } else {
        reject(new Error(response.error || "Unexpected raw response from background"));
      }
    });
  });
}

// --- Active Tab Autofill Script Injection ---

async function triggerAutofill(code, accountLabel) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    showToast("找不到當前分頁，請在網頁中開啟");
    return;
  }

  // Check if it is a system page (chrome://)
  if (tab.url && (tab.url.startsWith("chrome://") || tab.url.startsWith("edge://") || tab.url.startsWith("about:"))) {
    showToast("無法在瀏覽器設定頁面自動填入");
    return;
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillOTPField,
      args: [code]
    });
    showToast("已自動填入驗證碼");
    await sendEncryptedRequest("LOG_EVENT", { event: `Autofilled TOTP for: ${accountLabel}` });
  } catch (err) {
    console.error("Autofill injection failed:", err);
    showToast("填入失敗！請確認網頁已載入，或手動點擊輸入框");
  }
}

// This function executes inside the web page context
function fillOTPField(otpCode) {
  const inputs = Array.from(document.querySelectorAll('input'));
  const targets = [];

  for (const input of inputs) {
    if (input.type === 'hidden' || input.disabled || input.readOnly) continue;
    
    let score = 0;
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    
    if (autocomplete === 'one-time-code' || autocomplete === 'two-factor') {
      score += 100;
    }
    
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const className = (input.className || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const type = (input.type || '').toLowerCase();
    
    const patterns = ['otp', '2fa', 'mfa', 'code', 'token', 'auth', 'sec', 'factor', '驗證碼', '雙重'];
    for (const p of patterns) {
      if (name.includes(p)) score += 30;
      if (id.includes(p)) score += 30;
      if (placeholder.includes(p)) score += 20;
      if (className.includes(p)) score += 10;
    }
    
    if (type === 'tel' || type === 'number') {
      score += 15;
    }
    
    const maxlength = input.getAttribute('maxlength');
    if (maxlength === '6') {
      score += 25;
    }
    
    if (score > 0) {
      targets.push({ input, score });
    }
  }

  // Sort candidates by score
  targets.sort((a, b) => b.score - a.score);

  if (targets.length > 0) {
    const targetInput = targets[0].input;
    targetInput.focus();
    targetInput.value = otpCode;
    // Dispatch React/Vue framework listeners
    targetInput.dispatchEvent(new Event('input', { bubbles: true }));
    targetInput.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }

  // Fallback: active focused element if it's an input
  const active = document.activeElement;
  if (active && active.tagName === 'INPUT') {
    active.value = otpCode;
    active.dispatchEvent(new Event('input', { bubbles: true }));
    active.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }
  return false;
}

// --- Accounts UI Rendering ---

function renderAccounts(accounts) {
  currentAccounts = accounts;
  const listEl = document.getElementById("accounts-list");
  const emptyEl = document.getElementById("empty-state");
  listEl.innerHTML = "";

  if (accounts.length === 0) {
    emptyEl.classList.remove("hidden");
    return;
  }
  emptyEl.classList.add("hidden");

  accounts.forEach(acc => {
    const card = document.createElement("div");
    card.className = "account-card";
    if (isEditMode) {
      card.classList.add("edit-mode-active");
    }

    // Build stacked structure matching screenshot (Issuer at top, Code in middle, Name at bottom)
    card.innerHTML = `
      <div class="acc-card-left">
        <div class="acc-issuer-label">${acc.issuer}</div>
        <div class="totp-code" data-id="${acc.id}">${acc.totp}</div>
        <div class="acc-name-label">${acc.name}</div>
      </div>
      <div class="acc-card-right">
        <div class="acc-edit-actions ${isEditMode ? '' : 'hidden'}">
          <button class="action-btn-sm fill-btn" data-id="${acc.id}" data-code="${acc.totp}" data-label="${acc.issuer} (${acc.name})" title="自動填入此頁面">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="9 10 4 15 9 20" />
              <path d="M20 4v7a4 4 0 0 1-4 4H4" />
            </svg>
          </button>
          <button class="action-btn-sm delete-btn" data-id="${acc.id}" title="雙擊以刪除">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
            </svg>
          </button>
        </div>
        <svg class="card-progress-ring ${isEditMode ? 'hidden' : ''}" width="16" height="16" viewBox="0 0 16 16">
          <circle class="card-progress-ring__circle" stroke="#5f6368" stroke-width="8" fill="transparent" cx="8" cy="8" r="4" stroke-dasharray="25.13" stroke-dashoffset="0" />
        </svg>
      </div>
    `;

    // Click anywhere on the card to copy code (unless in edit mode)
    card.addEventListener("click", async (e) => {
      if (isEditMode || e.target.closest(".acc-edit-actions")) {
        return;
      }
      const code = acc.totp.replace(/\s/g, "");
      if (code === "ERR_KEY") return;
      try {
        await navigator.clipboard.writeText(code);
        showToast("已複製驗證碼");
        await sendEncryptedRequest("LOG_EVENT", { event: `Copied TOTP for: ${acc.issuer}:${acc.name}` });
      } catch (err) {
        console.error("Copy failed:", err);
      }
    });

    // Click autofill button
    const fillBtn = card.querySelector(".fill-btn");
    fillBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const code = fillBtn.dataset.code;
      if (code === "ERR_KEY") return;
      triggerAutofill(code, fillBtn.dataset.label);
    });

    // Double click delete button
    const delBtn = card.querySelector(".delete-btn");
    let deleteConfirmState = false;
    delBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!deleteConfirmState) {
        deleteConfirmState = true;
        delBtn.style.color = "var(--accent-red)";
        delBtn.setAttribute("title", "再次點擊確認刪除！");
        showToast("再次點擊以確認刪除");
        setTimeout(() => {
          deleteConfirmState = false;
          delBtn.style.color = "";
          delBtn.setAttribute("title", "雙擊以刪除");
        }, 3000);
      } else {
        try {
          await sendEncryptedRequest("DELETE_ACCOUNT", { id: delBtn.dataset.id });
          showToast("帳戶已刪除");
          loadDashboardData();
        } catch (err) {
          showToast("刪除失敗：" + err.message);
        }
      }
    });

    listEl.appendChild(card);
  });
}

// --- Dashboard Logic & Loop ---

async function loadDashboardData() {
  try {
    const accounts = await sendEncryptedRequest("GET_ACCOUNTS_TOTP");
    renderAccounts(accounts);
  } catch (err) {
    if (err.message === "VAULT_LOCKED") {
      clearInterval(localTimerInterval);
      showScreen("screen-unlock");
    } else {
      showToast("載入失敗：" + err.message);
    }
  }
}

function startTimerLoop() {
  if (localTimerInterval) clearInterval(localTimerInterval);
  currentAccounts = []; // Clear to force initial render on unlock

  const circle = document.getElementById("timer-circle");
  const timerText = document.getElementById("timer-text");
  const circumference = 2 * Math.PI * 11; // 69.115

  const update = async () => {
    const time = Math.floor(Date.now() / 1000);
    const remaining = 30 - (time % 30);
    
    // Update global progress circle
    if (circle) {
      const offset = circumference - (remaining / 30) * circumference;
      circle.style.strokeDashoffset = offset;
    }
    if (timerText) {
      timerText.textContent = `${remaining}s`;
    }

    // Update each individual card progress circle in sync
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

    // Refresh codes on rollover or if lists are empty
    if (remaining === 30 || currentAccounts.length === 0) {
      await loadDashboardData();
    }
  };

  update();
  localTimerInterval = setInterval(update, 1000);
}

// --- Initialize App State ---

async function checkStatus() {
  try {
    const status = await sendEncryptedRequest("GET_STATUS");
    if (!status.initialized) {
      showScreen("screen-setup");
    } else if (!status.unlocked) {
      showScreen("screen-unlock");
    } else {
      showScreen("screen-dashboard");
      startTimerLoop();
    }
  } catch (err) {
    console.error("Status check failed:", err);
    showToast("通道連接錯誤，請重新開啟外掛");
  }
}

// --- Event Listeners and Submits ---

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // 1. Establish Secure IPC Channel
    await establishSecureChannel();
    // 2. Load Screen Status
    await checkStatus();
  } catch (err) {
    console.error("Initialization error:", err);
    showToast("安全連線失敗，請重試");
  }

  // --- Initial Setup Form Submit ---
  const formSetup = document.getElementById("form-setup");
  formSetup.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("setup-password").value;
    const confirm = document.getElementById("setup-confirm").value;

    if (pw.length < 8) {
      showToast("主密碼長度必須至少 8 個字元");
      return;
    }
    if (pw !== confirm) {
      showToast("兩次輸入的密碼不一致");
      return;
    }

    try {
      document.getElementById("btn-do-setup").disabled = true;
      document.getElementById("btn-do-setup").textContent = "正在部署防禦矩陣...";
      
      await sendEncryptedRequest("INITIALIZE_VAULT", { password: pw });
      showToast("防禦矩陣部署完成！");
      showScreen("screen-dashboard");
      startTimerLoop();
    } catch (err) {
      showToast("部署失敗：" + err.message);
      document.getElementById("btn-do-setup").disabled = false;
      document.getElementById("btn-do-setup").textContent = "部署安全矩陣";
    }
  });

  // Setup Password Strength Event
  const passwordInput = document.getElementById("setup-password");
  const strengthFill = document.getElementById("strength-fill");
  const strengthLabel = document.getElementById("strength-label");
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
      color = "#f59e0b"; // Warning Orange
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
  const formUnlock = document.getElementById("form-unlock");
  formUnlock.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("unlock-password").value;
    const errorEl = document.getElementById("unlock-error");

    try {
      errorEl.classList.add("hidden");
      document.getElementById("btn-do-unlock").disabled = true;
      
      await sendEncryptedRequest("UNLOCK_VAULT", { password: pw });
      document.getElementById("unlock-password").value = "";
      showScreen("screen-dashboard");
      startTimerLoop();
    } catch (err) {
      errorEl.classList.remove("hidden");
      errorEl.textContent = err.message === "INCORRECT_PASSWORD" ? "密碼錯誤，解密失敗！" : "錯誤：" + err.message;
    } finally {
      document.getElementById("btn-do-unlock").disabled = false;
    }
  });

  // --- Toggling Edit Mode ---
  const btnToggleEdit = document.getElementById("btn-toggle-edit");
  const editIconPencil = document.getElementById("edit-icon-pencil");
  const editIconCheck = document.getElementById("edit-icon-check");

  btnToggleEdit.addEventListener("click", () => {
    isEditMode = !isEditMode;
    if (isEditMode) {
      editIconPencil.classList.add("hidden");
      editIconCheck.classList.remove("hidden");
      btnToggleEdit.setAttribute("title", "完成編輯");
    } else {
      editIconPencil.classList.remove("hidden");
      editIconCheck.classList.add("hidden");
      btnToggleEdit.setAttribute("title", "編輯帳戶");
    }
    renderAccounts(currentAccounts);
  });

  // --- Settings Modal triggers ---
  const modalSettings = document.getElementById("modal-settings");
  document.getElementById("btn-open-settings").addEventListener("click", () => {
    modalSettings.classList.remove("hidden");
  });
  document.getElementById("btn-close-settings").addEventListener("click", () => {
    modalSettings.classList.add("hidden");
  });

  // Settings items click
  document.getElementById("btn-menu-open-web").addEventListener("click", () => {
    modalSettings.classList.add("hidden");
    chrome.tabs.create({ url: chrome.runtime.getURL("website/index.html") });
  });

  document.getElementById("btn-menu-show-logs").addEventListener("click", () => {
    modalSettings.classList.add("hidden");
    document.getElementById("btn-show-logs-trigger").click();
  });

  document.getElementById("btn-menu-show-backup").addEventListener("click", () => {
    modalSettings.classList.add("hidden");
    document.getElementById("btn-show-backup-trigger").click();
  });

  document.getElementById("btn-menu-lock").addEventListener("click", async () => {
    modalSettings.classList.add("hidden");
    try {
      await sendEncryptedRequest("LOCK_VAULT");
      clearInterval(localTimerInterval);
      showScreen("screen-unlock");
      showToast("安全庫已手動鎖定");
    } catch (err) {
      showToast("鎖定失敗：" + err.message);
    }
  });

  // Dummy hidden buttons for compatibility
  const btnShowLogsTrigger = document.createElement("button");
  btnShowLogsTrigger.id = "btn-show-logs-trigger";
  btnShowLogsTrigger.style.display = "none";
  document.body.appendChild(btnShowLogsTrigger);

  const btnShowBackupTrigger = document.createElement("button");
  btnShowBackupTrigger.id = "btn-show-backup-trigger";
  btnShowBackupTrigger.style.display = "none";
  document.body.appendChild(btnShowBackupTrigger);

  // --- Modal: Add Account UI triggers ---
  const modalAdd = document.getElementById("modal-add");
  const openAddModal = () => {
    modalAdd.classList.remove("hidden");
    document.getElementById("add-issuer").focus();
  };

  document.getElementById("btn-open-scan").addEventListener("click", openAddModal);

  document.getElementById("btn-close-add").addEventListener("click", () => modalAdd.classList.add("hidden"));
  document.getElementById("btn-cancel-add").addEventListener("click", () => modalAdd.classList.add("hidden"));

  // Add Account submit
  const formAdd = document.getElementById("form-add");
  formAdd.addEventListener("submit", async (e) => {
    e.preventDefault();
    const issuer = document.getElementById("add-issuer").value;
    const name = document.getElementById("add-name").value;
    let secret = document.getElementById("add-secret").value;
    const errorEl = document.getElementById("add-error");

    secret = secret.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z2-7]+=*$/.test(secret)) {
      errorEl.classList.remove("hidden");
      return;
    }
    errorEl.classList.add("hidden");

    try {
      await sendEncryptedRequest("ADD_ACCOUNT", { issuer, name, secret });
      showToast("2FA 安全金鑰寫入成功");
      modalAdd.classList.add("hidden");
      formAdd.reset();
      loadDashboardData();
    } catch (err) {
      showToast("寫入失敗：" + err.message);
    }
  });

  // --- Modal: Audit Logs triggers ---
  const modalLogs = document.getElementById("modal-logs");
  const tbodyLogs = document.getElementById("logs-tbody");
  btnShowLogsTrigger.addEventListener("click", async () => {
    try {
      const logs = await sendEncryptedRequest("GET_AUDIT_LOGS");
      tbodyLogs.innerHTML = "";
      if (logs.length === 0) {
        tbodyLogs.innerHTML = `<tr><td colspan="2" style="text-align:center; color:var(--text-muted);">無日誌資料</td></tr>`;
      } else {
        // Render in reverse chronological order
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
      showToast("取得日誌失敗：" + err.message);
    }
  });
  document.getElementById("btn-close-logs").addEventListener("click", () => modalLogs.classList.add("hidden"));
  document.getElementById("btn-close-logs-footer").addEventListener("click", () => modalLogs.classList.add("hidden"));

  // --- Modal: Backup/Restore triggers ---
  const modalBackup = document.getElementById("modal-backup-panel");
  btnShowBackupTrigger.addEventListener("click", () => {
    modalBackup.classList.remove("hidden");
    resetBackupModalStates();
  });
  document.getElementById("btn-close-backup").addEventListener("click", () => modalBackup.classList.add("hidden"));

  // Reset file states helper
  function resetBackupModalStates() {
    document.getElementById("import-file").value = "";
    document.getElementById("selected-filename").textContent = "未選擇任何檔案";
    document.getElementById("backup-password-group").classList.add("hidden");
    document.getElementById("btn-submit-import").classList.add("hidden");
    document.getElementById("import-error").classList.add("hidden");
  }

  // Backup Export trigger
  document.getElementById("btn-export-file").addEventListener("click", async () => {
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
      await sendEncryptedRequest("LOG_EVENT", { event: "Exported security backup file" });
    } catch (err) {
      showToast("導出失敗：" + err.message);
    }
  });

  // Backup Import trigger
  const fileInput = document.getElementById("import-file");
  const triggerBtn = document.getElementById("btn-trigger-file");
  const filenameSpan = document.getElementById("selected-filename");
  const passwordGroup = document.getElementById("backup-password-group");
  const importSubmitBtn = document.getElementById("btn-submit-import");
  
  triggerBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      const file = fileInput.files[0];
      filenameSpan.textContent = file.name;
      passwordGroup.classList.remove("hidden");
      importSubmitBtn.classList.remove("hidden");
    } else {
      resetBackupModalStates();
    }
  });

  // Submit Import
  importSubmitBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];
    const password = document.getElementById("backup-password").value;
    const errorEl = document.getElementById("import-error");
    
    if (!password) {
      showToast("請輸入該備份的主密碼");
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        errorEl.classList.add("hidden");
        const backupData = JSON.parse(e.target.result);
        
        await sendEncryptedRequest("IMPORT_BACKUP", { backupData, password });
        showToast("資料還原載入成功！");
        modalBackup.classList.add("hidden");
        resetBackupModalStates();
        loadDashboardData();
      } catch (err) {
        errorEl.classList.remove("hidden");
        errorEl.textContent = err.message === "INCORRECT_PASSWORD" ? "密碼錯誤，無法解密備份檔！" : "還原失敗：" + err.message;
      }
    };
    reader.readAsText(file);
  });
});
