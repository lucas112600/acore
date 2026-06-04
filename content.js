/* acore Webpage 2FA Autofill Content Script */

let activeBadgeContainer = null;
let badgeTimerInterval = null;

// --- Helper: Detect if input is a 2FA/OTP field ---
function isOTPField(input) {
  if (input.type === 'hidden' || input.disabled || input.readOnly) return false;
  
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
  
  return score >= 25;
}

// --- Position the floating badge ---
function positionBadge(input, container) {
  const rect = input.getBoundingClientRect();
  container.style.top = `${window.scrollY + rect.bottom + 6}px`;
  container.style.left = `${window.scrollX + rect.left}px`;
}

// --- Remove active badges ---
function removeBadge() {
  if (activeBadgeContainer) {
    activeBadgeContainer.remove();
    activeBadgeContainer = null;
  }
  if (badgeTimerInterval) {
    clearInterval(badgeTimerInterval);
    badgeTimerInterval = null;
  }
}

// --- Handle Focus Events on OTP inputs ---
function handleOTPFieldFocused(input) {
  removeBadge(); // Remove any stale badges first

  // Query background for 2FA matches for this domain
  chrome.runtime.sendMessage({
    type: "GET_MATCHED_TOTP",
    domain: window.location.hostname
  }, (response) => {
    if (chrome.runtime.lastError || !response || !response.success || !response.matches || response.matches.length === 0) {
      return; // No active vault/unlocked state or no matching keys
    }

    // Build floating badges container
    const container = document.createElement("div");
    container.className = "acore-floating-badge-container";
    document.body.appendChild(container);
    activeBadgeContainer = container;

    // Position container next to the focused input
    positionBadge(input, container);

    // Re-position on resize or scroll
    const scrollHandler = () => positionBadge(input, container);
    window.addEventListener("scroll", scrollHandler, { passive: true });
    window.addEventListener("resize", scrollHandler, { passive: true });

    // Render badge for each matching account
    response.matches.forEach(acc => {
      const badge = document.createElement("div");
      badge.className = "acore-floating-badge";
      badge.setAttribute("title", `帳號: ${acc.name} (點擊填入並複製)`);
      badge.innerHTML = `
        <div class="acore-badge-status">已複製並填入</div>
        <span class="acore-badge-code">${acc.totp}</span>
        <svg class="acore-badge-timer" width="12" height="12" viewBox="0 0 12 12">
          <circle stroke="rgba(0,0,0,0.06)" stroke-width="1.8" fill="transparent" r="4.5" cx="6" cy="6" />
          <circle class="acore-badge-timer-fill" stroke="#25c2a0" stroke-width="9" fill="transparent" r="4.5" cx="6" cy="6" stroke-dasharray="28.27" stroke-dashoffset="0" />
        </svg>
      `;

      // Handle Click-to-Autofill and Copy
      badge.addEventListener("mousedown", async (e) => {
        e.preventDefault(); // Prevent input blurring
        e.stopPropagation();

        const code = acc.totp.replace(/\s/g, "");
        if (code === "ERR_KEY") return;

        try {
          // 1. Copy code to clipboard
          await navigator.clipboard.writeText(code);

          // 2. Autofill the input field
          input.focus();
          input.value = code;
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));

          // 3. Show success tooltip
          const status = badge.querySelector(".acore-badge-status");
          status.classList.add("active");

          // Log event to service worker audit
          chrome.runtime.sendMessage({
            type: "ENCRYPTED_MSG",
            // We tunnel a LOG_EVENT directly or send log message, let's keep it simple
            // We can send a message to trigger an audit log
          });

          // 4. Fade out badge
          setTimeout(() => {
            removeBadge();
            window.removeEventListener("scroll", scrollHandler);
            window.removeEventListener("resize", scrollHandler);
          }, 1000);

        } catch (err) {
          console.error("Autofill click failed:", err);
        }
      });

      container.appendChild(badge);
    });

    // Start local timer loop to sync countdown pie sector
    const startWedgeTimer = () => {
      const fillElements = container.querySelectorAll(".acore-badge-timer-fill");
      const circumference = 28.27; // 2 * Math.PI * 4.5

      const update = () => {
        const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
        const offset = (1 - (remaining / 30)) * circumference;
        
        fillElements.forEach(fill => {
          fill.style.strokeDashoffset = offset;
          if (remaining <= 5) {
            fill.setAttribute("stroke", "#fa383e");
          } else {
            fill.setAttribute("stroke", "#25c2a0");
          }
        });

        // If time rolls over, refresh the codes by triggering a re-focus logic
        if (remaining === 30) {
          handleOTPFieldFocused(input);
        }
      };

      update();
      badgeTimerInterval = setInterval(update, 1000);
    };

    startWedgeTimer();
  });
}

// --- Global Event Delegation: Monitor Focused Elements ---
document.addEventListener("focus", (e) => {
  if (e.target && e.target.tagName === "INPUT") {
    const input = e.target;
    if (isOTPField(input)) {
      handleOTPFieldFocused(input);
    }
  }
}, true);

// Close badge when user clicks anywhere else
document.addEventListener("mousedown", (e) => {
  if (activeBadgeContainer && !activeBadgeContainer.contains(e.target) && e.target !== document.activeElement) {
    removeBadge();
  }
});
