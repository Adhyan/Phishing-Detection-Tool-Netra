/* =============================================
   NETRA — JavaScript Interactions & Animations
   Scan output: Safe / Suspicious / Phishing
   Feature keys match dataset.csv columns exactly:
     url_length, num_dots, has_at, has_hyphen,
     num_subdomains, uses_https, has_ip, entropy,
     has_login_keyword, has_suspicious_tld,
     contains_brand, digit_count, long_url, has_mx,
     num_ips, num_forms, has_password_field,
     num_iframes, has_login_text, external_link_ratio,
     has_js_redirect, brand_distance
============================================= */

document.addEventListener('DOMContentLoaded', () => {

  // ============================
  // PARTICLE SYSTEM
  // ============================
  const particleContainer = document.getElementById('particles');
  if (particleContainer) {
    for (let i = 0; i < 30; i++) {
      const p = document.createElement('div');
      p.classList.add('particle');
      p.style.left = Math.random() * 100 + 'vw';
      p.style.setProperty('--dur', (Math.random() * 10 + 8) + 's');
      p.style.setProperty('--dx', (Math.random() * 100 - 50) + 'px');
      p.style.animationDelay = (Math.random() * 15) + 's';
      particleContainer.appendChild(p);
    }
  }

  // ============================
  // AUTH MODAL
  // ============================
  const modal     = document.getElementById('authModal');
  const openBtn   = document.getElementById('openAuthModal');
  const closeBtn  = document.getElementById('closeAuthModal');
  const tabBtns   = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-content');

  if (openBtn)  openBtn.addEventListener('click',  () => modal.classList.add('open'));
  if (closeBtn) closeBtn.addEventListener('click', () => modal.classList.remove('open'));
  if (modal)    modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('open'); });

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });

  // ============================
  // NAVBAR SCROLL
  // ============================
  const navbar = document.getElementById('navbar');
  window.addEventListener('scroll', () => {
    if (!navbar) return;
    navbar.style.background = window.scrollY > 60 ? 'rgba(2,10,15,0.98)' : 'rgba(2,10,15,0.92)';
    navbar.style.boxShadow  = window.scrollY > 60 ? '0 4px 30px rgba(0,229,255,0.05)' : 'none';
  });

  // ============================
  // URL SCANNER
  // ============================
  const urlInput   = document.getElementById('urlInput');
  const scanBtn    = document.getElementById('scanBtn');
  const scanResult = document.getElementById('scanResult');
  let scanning = false;

  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      const url = urlInput.value.trim();
      if (!url) {
        urlInput.style.borderColor = 'var(--red)';
        setTimeout(() => (urlInput.style.borderColor = ''), 1500);
        return;
      }
      if (scanning) return;
      scanning = true;

      scanBtn.classList.add('scanning');
      scanBtn.querySelector('.scan-btn-text').textContent = 'SCANNING';
      scanResult.innerHTML = '';
      scanResult.classList.remove('visible');

      let data;
      try {
        const res = await fetch('/scan', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ url })
        });
        data = await res.json();
      } catch {
        scanResult.innerHTML = '';
        scanResult.appendChild(statusBanner('error',
          '🔌 CONNECTION ERROR',
          'Could not reach the NETRA server. Make sure <code>app.py</code> is running on port 5000.'
        ));
        scanResult.classList.add('visible');
        resetBtn(); return;
      }

      scanResult.innerHTML = '';
      scanResult.appendChild(buildResult(url, data));
      scanResult.classList.add('visible');
      addToRecent(url, data.result);
      resetBtn();
    });
  }

  if (urlInput) urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });

  function resetBtn() {
    scanBtn.classList.remove('scanning');
    scanBtn.querySelector('.scan-btn-text').textContent = 'SCAN NOW';
    scanning = false;
  }

  // ============================================================
  // BUILD RESULT — all feature keys match dataset.csv exactly
  // ============================================================
  function buildResult(url, data) {
    const result = data.result; // Safe | Suspicious | Phishing | Invalid | Unreachable
    const wrap = document.createElement('div');
    wrap.style.cssText = 'display:flex;flex-direction:column;gap:12px;font-family:var(--font-mono);font-size:13px;';

    // ── Domain does not exist ──
    if (result === 'Invalid') {
      wrap.appendChild(statusBanner('error',
        '❌  DOMAIN DOES NOT EXIST',
        `The domain <strong style="color:var(--cyan)">${data.domain}</strong> could not be resolved. ` +
        `It may be misspelled, never existed, or has been taken offline. ` +
        `Double-check the URL and try again.`
      ));
      return wrap;
    }

    // ── Site unreachable ──
    if (result === 'Unreachable') {
      wrap.appendChild(statusBanner('warn',
        '⚠️  SITE UNREACHABLE',
        `Domain <strong style="color:var(--cyan)">${data.domain}</strong> resolved to ` +
        `<code style="color:var(--cyan)">${data.ip_address}</code> but did not respond to HTTP requests. ` +
        `The server may be down, blocking bots, or behind a firewall.`
      ));
      wrap.appendChild(infoRow('🌐 IP Address', data.ip_address || '—'));
      return wrap;
    }

    // ── Type config ──
    const cfg = {
      Safe:       { btype: 'safe',   icon: '✅', heading: 'SAFE',             msg: 'No significant phishing indicators detected. Site appears legitimate — but always stay alert before entering credentials.' },
      Suspicious: { btype: 'warn',   icon: '⚠️', heading: 'SUSPICIOUS',        msg: 'This URL shows suspicious patterns. Proceed with extreme caution and do not enter passwords or personal information.' },
      Phishing:   { btype: 'danger', icon: '🚨', heading: 'PHISHING DETECTED', msg: 'Multiple phishing signals detected. This site is likely malicious. Do NOT visit or enter any information whatsoever.' },
    }[result] || { btype:'warn', icon:'⚠️', heading:'UNKNOWN', msg:'Could not determine status.' };

    const score      = Math.round(data.threat_score  ?? 0);
    const confidence = Math.round(data.confidence    ?? 0);
    const riskLevel  = score > 70 ? 'HIGH RISK' : score > 40 ? 'MEDIUM RISK' : 'LOW RISK';
    const riskColor  = score > 70 ? 'var(--red)' : score > 40 ? '#ff8800' : 'var(--green)';

    // 1 — Banner
    wrap.appendChild(statusBanner(cfg.btype, `${cfg.icon}  ${cfg.heading}`, cfg.msg));

    // 2 — Threat score bar
    wrap.appendChild(scoreBar(score, riskLevel, riskColor, confidence));

    // 3 — Info grid: IP / domain / HTTP / SSL age
    wrap.appendChild(infoGrid(data));

    // 4 — Lookalike warning (uses brand_distance column)
    if (data.brand_distance != null && data.brand_distance < 3 &&
        data.closest_domain && data.closest_domain !== data.domain) {
      wrap.appendChild(lookalikeBanner(data.closest_domain, data.brand_distance));
    }

    // 5 — Why it is dangerous (Phishing / Suspicious only)
    if (result !== 'Safe') {
      const reasons = buildReasons(data);
      if (reasons.length) wrap.appendChild(dangerReasons(reasons, result));
    }

    // 6 — Recommended actions (Phishing only)
    if (result === 'Phishing') wrap.appendChild(recommendedActions());

    // 7 — Trust breakdown (all results)
    wrap.appendChild(trustBreakdown(data));

    return wrap;
  }

  // ──────────────────────────────────────────
  // COMPONENT BUILDERS
  // ──────────────────────────────────────────

  function statusBanner(type, title, body) {
    const s = {
      safe:   { bg:'rgba(0,255,136,0.08)',  border:'var(--green)',    text:'var(--green)'    },
      danger: { bg:'rgba(255,42,42,0.10)',  border:'var(--red)',      text:'var(--red)'      },
      warn:   { bg:'rgba(255,136,0,0.08)', border:'#ff8800',          text:'#ff8800'         },
      error:  { bg:'rgba(90,122,138,0.10)',border:'var(--text-dim)',  text:'var(--text-dim)' },
    }[type] || {};
    const el = document.createElement('div');
    el.style.cssText = `background:${s.bg};border:1px solid ${s.border};border-radius:8px;padding:16px 20px;animation:slideIn 0.35s ease;`;
    el.innerHTML = `
      <div style="color:${s.text};font-weight:bold;font-size:15px;letter-spacing:1.5px;margin-bottom:8px;">${title}</div>
      <div style="color:var(--text);opacity:0.9;line-height:1.6;font-size:12px;">${body}</div>`;
    return el;
  }

  function scoreBar(score, riskLevel, riskColor, confidence) {
    const barEnd = score > 70 ? '#ff0000' : score > 40 ? '#ffaa00' : '#00ffaa';
    const el = document.createElement('div');
    el.style.cssText = 'background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:16px 20px;';
    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;margin-bottom:10px;align-items:center;">
        <span style="color:var(--text-dim);font-size:10px;letter-spacing:3px;">THREAT SCORE</span>
        <span style="color:${riskColor};font-weight:bold;font-size:11px;letter-spacing:2px;
               background:rgba(255,255,255,0.04);padding:3px 10px;border-radius:3px;
               border:1px solid ${riskColor};">${riskLevel}</span>
      </div>
      <div style="background:rgba(255,255,255,0.05);border-radius:6px;height:12px;overflow:hidden;margin-bottom:12px;">
        <div style="width:${score}%;height:100%;border-radius:6px;
             background:linear-gradient(90deg,${riskColor},${barEnd});
             box-shadow:0 0 10px ${riskColor};transition:width 1s ease;"></div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:flex-end;">
        <div>
          <span style="color:${riskColor};font-size:28px;font-family:var(--font-display);font-weight:900;">${score}</span>
          <span style="color:var(--text-dim);font-size:12px;"> / 100</span>
        </div>
        <div style="text-align:right;font-size:11px;color:var(--text-dim);">
          Model Confidence<br>
          <strong style="color:var(--cyan);font-size:16px;">${confidence}%</strong>
        </div>
      </div>`;
    return el;
  }

  function infoGrid(data) {
    const certAge = (data.domain_age != null && data.domain_age !== -1) ? `${data.domain_age} days` : 'N/A';
    const items = [
      ['🌐 IP Address',   data.ip_address || '—'],
      ['🔗 Domain',       data.domain      || '—'],
      ['📡 HTTP Status',  data.http_status != null ? String(data.http_status) : '—'],
      ['🔒 SSL Cert Age', certAge],
    ];
    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:8px;';
    items.forEach(([label, val]) => {
      const cell = document.createElement('div');
      cell.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 14px;';
      cell.innerHTML = `
        <div style="color:var(--text-dim);font-size:10px;letter-spacing:1px;margin-bottom:5px;">${label}</div>
        <div style="color:var(--cyan);font-size:12px;word-break:break-all;">${val}</div>`;
      grid.appendChild(cell);
    });
    return grid;
  }

  function infoRow(label, val) {
    const el = document.createElement('div');
    el.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:12px;';
    el.innerHTML = `<span style="color:var(--text-dim);">${label}: </span><span style="color:var(--cyan);">${val}</span>`;
    return el;
  }

  function lookalikeBanner(closest, distance) {
    const el = document.createElement('div');
    el.style.cssText = 'background:rgba(255,107,0,0.08);border:1px solid #ff6b00;border-radius:8px;padding:12px 16px;';
    el.innerHTML = `
      <strong style="color:#ff6b00;">🎭 LOOKALIKE DOMAIN DETECTED</strong>
      <div style="color:var(--text);margin-top:6px;font-size:12px;line-height:1.6;">
        This domain is suspiciously similar to <strong style="color:var(--yellow);">${closest}</strong>
        (brand_distance: ${distance}). It may be impersonating a trusted brand to steal your credentials.
      </div>`;
    return el;
  }

  // Reason builder — keys match dataset.csv columns EXACTLY
  function buildReasons(data) {
    const f = data.features || {};
    const reasons = [];

    if (Number(f.uses_https) === 0)
      reasons.push('Not using HTTPS — connection is unencrypted and can be intercepted by attackers');

    if (Number(f.has_ip) === 1)
      reasons.push('Raw IP address used as domain — attackers hide behind IPs to avoid brand recognition');

    if (Number(f.has_at) === 1)
      reasons.push('@ symbol in URL — browser ignores everything before @ and silently redirects you elsewhere');

    if (Number(f.has_login_keyword) === 1)
      reasons.push('Phishing keywords in URL (e.g. "login", "verify", "secure", "update", "confirm")');

    if (Number(f.has_login_text) === 1)
      reasons.push('Page content contains credential-harvesting login text patterns');

    if (Number(f.has_suspicious_tld) === 1)
      reasons.push('Suspicious top-level domain detected (e.g. .xyz, .ru, .tk, .pw, .ml) — high abuse rate');

    if (Number(f.num_subdomains) >= 3)
      reasons.push(`Excessive subdomains (${f.num_subdomains}) — used to bury the real domain and trick users`);

    if (Number(f.long_url) === 1)
      reasons.push(`Abnormally long URL (${f.url_length} chars) — designed to hide the true destination`);

    if (Number(f.digit_count) > 4)
      reasons.push(`High digit count in URL (${f.digit_count}) — may be obfuscating a legitimate brand name`);

    if (Number(f.has_password_field) === 1)
      reasons.push('Page contains a password input field — possible credential harvesting form');

    if (Number(f.num_iframes) > 0)
      reasons.push(`${f.num_iframes} hidden iframe(s) found — commonly used to silently load malicious content`);

    if (Number(f.has_js_redirect) === 1)
      reasons.push('JavaScript redirect detected — you may be invisibly bounced to a different malicious page');

    if (Number(f.external_link_ratio) > 0.7)
      reasons.push(`High external link ratio (${Math.round(f.external_link_ratio * 100)}%) — most links on this page lead away from it`);

    if (Number(f.has_hyphen) === 1 && data.brand_distance != null && data.brand_distance < 4)
      reasons.push('Hyphens in domain — classic technique in fake brand clones (e.g. pay-pal-login.com)');

    if (data.brand_distance != null && data.brand_distance < 2 && data.closest_domain)
      reasons.push(`Near-exact imitation of <strong style="color:var(--yellow);">${data.closest_domain}</strong> (brand_distance: ${data.brand_distance})`);

    return reasons;
  }

  function dangerReasons(reasons, result) {
    const isPhish = result === 'Phishing';
    const color = isPhish ? 'var(--red)' : '#ff8800';
    const el = document.createElement('div');
    el.style.cssText = `background:${isPhish ? 'rgba(255,42,42,0.06)' : 'rgba(255,136,0,0.06)'};
      border:1px solid ${color};border-radius:8px;padding:16px 20px;`;
    el.innerHTML = `<div style="color:${color};font-weight:bold;margin-bottom:12px;font-size:13px;letter-spacing:1px;">
      ${isPhish ? '⚠ WHY THIS IS DANGEROUS' : '⚠ SUSPICIOUS INDICATORS'}</div>`;
    reasons.forEach(r => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:10px;margin-bottom:9px;color:var(--text);font-size:12px;line-height:1.55;align-items:flex-start;';
      row.innerHTML = `<span style="color:${color};flex-shrink:0;margin-top:1px;">▸</span><span>${r}</span>`;
      el.appendChild(row);
    });
    return el;
  }

  function recommendedActions() {
    const el = document.createElement('div');
    el.style.cssText = 'background:rgba(255,42,42,0.06);border:1px solid var(--red);border-radius:8px;padding:16px 20px;';
    el.innerHTML = `
      <div style="color:var(--red);font-weight:bold;margin-bottom:12px;letter-spacing:1px;">🛡 RECOMMENDED ACTIONS</div>
      <div style="color:var(--text);font-size:12px;line-height:2.1;">
        ▸ <strong>Do NOT</strong> enter passwords, emails, card details or OTPs on this site<br>
        ▸ Close this tab / browser window immediately<br>
        ▸ If you already entered credentials — <strong>change them now</strong><br>
        ▸ Enable <strong>two-factor authentication (2FA)</strong> on all affected accounts<br>
        ▸ Use the 🚨 <strong>Report</strong> button below to flag this URL<br>
        ▸ Warn anyone else who may have received a link to this URL
      </div>`;
    return el;
  }

  // Trust breakdown — uses exact dataset.csv column names
  function trustBreakdown(data) {
    const f = data.features || {};
    const checks = [
      [ Number(f.uses_https) === 1,                                            '🔒 HTTPS encrypted connection'            ],
      [ Number(f.has_ip) === 0,                                                '🌐 No raw IP address in URL'              ],
      [ Number(f.has_at) === 0,                                                '🔗 No @ symbol in URL'                    ],
      [ Number(f.has_login_keyword) === 0,                                     '🔑 No phishing keywords in URL'           ],
      [ Number(f.has_suspicious_tld) === 0,                                    '🌍 Trusted top-level domain'              ],
      [ Number(f.num_subdomains) < 3,                                          '📡 Normal subdomain count'                ],
      [ Number(f.has_password_field) === 0,                                    '🔐 No hidden password field'              ],
      [ Number(f.has_js_redirect) === 0,                                       '↪ No JavaScript redirect'                 ],
      [ Number(f.num_iframes) === 0,                                           '🖼 No iframes on page'                    ],
      [ Number(f.long_url) === 0,                                              '📏 Normal URL length'                     ],
      [ data.domain_age == null || data.domain_age === -1 || data.domain_age >= 30, '📅 SSL certificate mature (30+ days)' ],
      [ !(data.brand_distance != null && data.brand_distance < 3),             '🎭 No brand lookalike risk'               ],
    ];

    const el = document.createElement('div');
    el.style.cssText = 'background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:16px 20px;';
    el.innerHTML = `<div style="color:var(--text-dim);font-size:10px;letter-spacing:3px;margin-bottom:12px;">📊 TRUST BREAKDOWN</div>`;
    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:6px;';
    checks.forEach(([pass, label]) => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px;align-items:flex-start;font-size:11px;padding:5px 0;';
      row.innerHTML = `
        <span style="color:${pass ? 'var(--green)' : 'var(--red)'};font-size:13px;flex-shrink:0;">${pass ? '✔' : '✘'}</span>
        <span style="color:${pass ? 'var(--text)' : 'var(--text-dim)'};line-height:1.4;">${label}</span>`;
      grid.appendChild(row);
    });
    el.appendChild(grid);
    return el;
  }

  // ============================
  // RECENT SCANS
  // ============================
  function addToRecent(url, result) {
    const list = document.getElementById('recentList');
    if (!list) return;
    const m = {
      Safe:        { cls:'safe',   dot:'green',  badge:'badge-safe',   text:'SAFE'        },
      Suspicious:  { cls:'warn',   dot:'yellow', badge:'badge-warn',   text:'SUSPICIOUS'  },
      Phishing:    { cls:'danger', dot:'red',    badge:'badge-danger', text:'PHISHING'    },
      Invalid:     { cls:'warn',   dot:'yellow', badge:'badge-warn',   text:'NOT FOUND'   },
      Unreachable: { cls:'warn',   dot:'yellow', badge:'badge-warn',   text:'UNREACHABLE' },
    }[result] || { cls:'warn', dot:'yellow', badge:'badge-warn', text:'UNKNOWN' };
    const item = document.createElement('div');
    item.className = `recent-item ${m.cls}`;
    item.innerHTML = `
      <span class="status-dot ${m.dot}"></span>
      <span class="url-truncate">${url}</span>
      <span class="${m.badge}">${m.text}</span>`;
    list.insertBefore(item, list.firstChild);
    if (list.children.length > 6) list.removeChild(list.lastChild);
  }

  // ============================
  // REPORT BUTTON
  // ============================
  const reportBtn = document.getElementById('reportBtn');
  if (reportBtn) {
    reportBtn.addEventListener('click', async () => {
      const url = urlInput.value.trim();
      if (!url) { alert('No URL to report'); return; }
      try {
        await fetch('/report', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        alert('✅ URL reported successfully. Thank you for helping keep NETRA safe!');
      } catch { alert('❌ Report failed. Check your connection.'); }
    });
  }

  // ============================
  // QR SCANNER
  // ============================
  const qrBtn    = document.getElementById('qrBtn');
  const qrFile   = document.getElementById('qrFile');
  const qrVideo  = document.getElementById('qrVideo');
  const qrCanvas = document.getElementById('qrCanvas');
  const qrCtx    = qrCanvas ? qrCanvas.getContext('2d') : null;

  if (qrBtn && qrFile) {
    qrBtn.addEventListener('click', () => {
      if (confirm('Press OK for Camera\nPress Cancel to Upload a QR Image')) startCameraScan();
      else qrFile.click();
    });
    qrFile.addEventListener('change', e => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = ev => {
        const img = new Image();
        img.onload = () => {
          qrCanvas.width = img.width; qrCanvas.height = img.height;
          qrCtx.drawImage(img, 0, 0);
          const d = qrCtx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
          const code = jsQR(d.data, d.width, d.height);
          if (code) { urlInput.value = code.data; scanBtn.click(); }
          else alert('No QR code detected. Try a clearer image.');
        };
        img.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    });
  }

  async function startCameraScan() {
    try {
      qrVideo.style.display = 'block';
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      qrVideo.srcObject = stream;
      qrVideo.setAttribute('playsinline', true);
      qrVideo.play();
      requestAnimationFrame(function tick() {
        if (qrVideo.readyState === qrVideo.HAVE_ENOUGH_DATA) {
          qrCanvas.width = qrVideo.videoWidth; qrCanvas.height = qrVideo.videoHeight;
          qrCtx.drawImage(qrVideo, 0, 0);
          const d = qrCtx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
          const code = jsQR(d.data, d.width, d.height);
          if (code) {
            stream.getTracks().forEach(t => t.stop());
            qrVideo.style.display = 'none';
            urlInput.value = code.data; scanBtn.click(); return;
          }
        }
        requestAnimationFrame(tick);
      });
    } catch { alert('Camera access denied or unavailable.'); }
  }

  // ============================
  // SUGGEST (live hint)
  // ============================
  if (urlInput) {
    urlInput.addEventListener('input', () => {
      fetch('/suggest', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:urlInput.value}) })
        .then(r => r.json())
        .then(d => { urlInput.style.borderColor = d.suggestion ? 'orange' : ''; })
        .catch(() => {});
    });
  }

  // ============================
  // COUNTER ANIMATION
  // ============================
  const counterObserver = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { animateCounter(e.target); counterObserver.unobserve(e.target); } });
  }, { threshold: 0.5 });
  document.querySelectorAll('.stat-num').forEach(c => counterObserver.observe(c));

  function animateCounter(el) {
    const target = parseFloat(el.dataset.target);
    const dec = String(target).includes('.') ? 1 : 0;
    let start = 0;
    requestAnimationFrame(function step(ts) {
      if (!start) start = ts;
      const p = Math.min((ts - start) / 1800, 1);
      el.textContent = ((1 - Math.pow(1-p,3)) * target).toFixed(dec);
      if (p < 1) requestAnimationFrame(step); else el.textContent = target.toFixed(dec);
    });
  }

  // ============================
  // CHARTS
  // ============================
  function initCharts() {
    const acc = document.getElementById('accuracyChart');
    if (acc) new Chart(acc, {
      type: 'line',
      data: {
        labels: ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],
        datasets: [
          { label:'Phishing Detection %', data:[94.2,95.1,95.8,96.4,97.0,97.5,98.1,98.4,98.9,99.2,99.5,99.7],
            borderColor:'#ff2a2a', backgroundColor:'rgba(255,42,42,0.08)', fill:true, tension:0.4,
            pointBackgroundColor:'#ff2a2a', pointRadius:4, pointHoverRadius:6 },
          { label:'Piracy Detection %', data:[88.0,89.2,90.5,91.0,92.1,93.0,93.8,94.5,95.0,95.6,96.2,97.1],
            borderColor:'#00e5ff', backgroundColor:'rgba(0,229,255,0.06)', fill:true, tension:0.4,
            pointBackgroundColor:'#00e5ff', pointRadius:4, pointHoverRadius:6 }
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ labels:{ color:'#5a7a8a', font:{ family:'Share Tech Mono', size:11 } } } },
        scales: {
          x:{ ticks:{ color:'#5a7a8a', font:{ family:'Share Tech Mono', size:10 } }, grid:{ color:'rgba(0,229,255,0.06)' } },
          y:{ ticks:{ color:'#5a7a8a', font:{ family:'Share Tech Mono', size:10 }, callback:v=>v+'%' },
              grid:{ color:'rgba(0,229,255,0.06)' }, min:85, max:100 }
        }
      }
    });
    const donut = document.getElementById('donutChart');
    if (donut) new Chart(donut, {
      type: 'doughnut',
      data: {
        labels: ['Phishing','Pirated','Malware','Safe'],
        datasets:[{ data:[42,18,12,28],
          backgroundColor:['rgba(255,42,42,0.8)','rgba(255,140,0,0.8)','rgba(255,208,0,0.8)','rgba(0,255,136,0.8)'],
          borderColor:['#ff2a2a','#ff8c00','#ffd000','#00ff88'], borderWidth:2, hoverOffset:8 }]
      },
      options:{
        responsive:true, maintainAspectRatio:true, cutout:'72%',
        plugins:{ legend:{display:false}, tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${ctx.raw}%`}} },
        animation:{animateScale:true, duration:1200}
      }
    });
  }

  const dashEl = document.getElementById('dashboard');
  if (dashEl) {
    const obs = new IntersectionObserver(e => { if (e[0].isIntersecting) { initCharts(); obs.disconnect(); } }, {threshold:0.2});
    obs.observe(dashEl);
  }

  // ============================
  // PLAY SIMULATION → /game
  // ============================
  const playBtn = document.getElementById('playSimBtn');
  if (playBtn) {
    const fresh = playBtn.cloneNode(true);
    playBtn.parentNode.replaceChild(fresh, playBtn);
    fresh.addEventListener('click', () => { window.location.href = '/game'; });
  }

  // ============================
  // SCROLL REVEAL
  // ============================
  const revealObs = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) setTimeout(() => e.target.classList.add('visible'), parseInt(e.target.dataset.delay||0));
    });
  }, {threshold:0.1});
  document.querySelectorAll('.feat-card, .sim-info-card, .dash-card, .about-hl, .sim-protect-tips')
    .forEach(el => { el.classList.add('reveal'); revealObs.observe(el); });

  // ============================
  // SIGNUP FORM
  // ============================
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', e => {
      e.preventDefault();
      const btn = signupForm.querySelector('.signup-submit-btn');
      btn.innerHTML = '<span>✅ REGISTRATION SUCCESSFUL! NETRA IS ACTIVE.</span>';
      btn.style.background = 'linear-gradient(135deg,#00a060,#007040)';
      btn.disabled = true;
      setTimeout(() => { btn.innerHTML='<span>🛡 ACTIVATE NETRA PROTECTION</span>'; btn.style.background=''; btn.disabled=false; signupForm.reset(); }, 4000);
    });
  }

  // ============================
  // ACTIVE NAV ON SCROLL
  // ============================
  const navLinks = document.querySelectorAll('.nav-link');
  new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        navLinks.forEach(l => l.style.color='');
        const a = document.querySelector(`.nav-link[href="#${e.target.id}"]`);
        if (a) a.style.color = 'var(--cyan)';
      }
    });
  }, {threshold:0.4}).observe.apply(null, [...document.querySelectorAll('section[id]')]);

  // ============================
  // TYPING PLACEHOLDER
  // ============================
  const placeholders = [
    'https://suspicious-login-bank.xyz',
    'http://paypa1-secure-verify.ru',
    'https://free-movies-hd-stream.co',
    'https://amaz0n-account-alert.net',
    'https://enter-suspicious-url.com',
  ];
  let pIdx=0, charIdx=0, typing=true;
  (function type() {
    const cur = placeholders[pIdx];
    if (typing) {
      if (urlInput) urlInput.placeholder = cur.substring(0, ++charIdx);
      if (charIdx >= cur.length) { typing=false; setTimeout(type,2500); return; }
    } else {
      if (urlInput) urlInput.placeholder = cur.substring(0, --charIdx);
      if (charIdx<=0) { typing=true; pIdx=(pIdx+1)%placeholders.length; }
    }
    setTimeout(type, typing?55:25);
  })();

  // ============================
  // THREAT FEED ROTATION
  // ============================
  const threats = [
    'bank-secure-alert.xyz | paypa1-login.net | amaz0n-verify.co',
    'netflix-account-suspended.ru | whatsapp-update.phish.io | support-apple.fake.com',
    'irs-tax-refund-claim.xyz | fedex-package-hold.net | covid-relief-fund.scam.co',
    'instagram-verify.phish.ru | steam-trade-offer.malware.net | crypto-reward-claim.xyz',
  ];
  let threatIdx=0;
  const alertText = document.querySelector('.alert-text');
  if (alertText) {
    setInterval(() => {
      const parts = threats[++threatIdx % threats.length].split(' | ');
      alertText.innerHTML = `LIVE THREAT FEED: 3 new phishing domains detected in the last 10 minutes — <strong>${parts[0]}</strong> | <strong>${parts[1]}</strong> | <strong>${parts[2]}</strong>`;
    }, 6000);
  }

}); // end DOMContentLoaded
