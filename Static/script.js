/* =============================================
   NETRA — JavaScript Interactions & Animations
============================================= */

document.addEventListener('DOMContentLoaded', () => {

  // ============================
  // PARTICLE SYSTEM
  // ============================
  const particleContainer = document.getElementById('particles');
  const PARTICLE_COUNT = 30;
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const p = document.createElement('div');
    p.classList.add('particle');
    p.style.left = Math.random() * 100 + 'vw';
    p.style.setProperty('--dur', (Math.random() * 10 + 8) + 's');
    p.style.setProperty('--dx', (Math.random() * 100 - 50) + 'px');
    p.style.animationDelay = (Math.random() * 15) + 's';
    particleContainer.appendChild(p);
  }

  // ============================
  // AUTH MODAL
  // ============================
  const modal     = document.getElementById('authModal');
  const openBtn   = document.getElementById('openAuthModal');
  const closeBtn  = document.getElementById('closeAuthModal');
  const tabBtns   = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-content');

  openBtn.addEventListener('click', () => modal.classList.add('open'));
  closeBtn.addEventListener('click', () => modal.classList.remove('open'));
  modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('open'); });

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(target).classList.add('active');
    });
  });

  // ============================
  // NAVBAR SCROLL EFFECT
  // ============================
  const navbar = document.getElementById('navbar');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 60) {
      navbar.style.background = 'rgba(2,10,15,0.98)';
      navbar.style.boxShadow = '0 4px 30px rgba(0,229,255,0.05)';
    } else {
      navbar.style.background = 'rgba(2,10,15,0.92)';
      navbar.style.boxShadow = 'none';
    }
  });

  // ============================
  // URL SCANNER
  // ============================
  const urlInput   = document.getElementById('urlInput');
  const scanBtn    = document.getElementById('scanBtn');
  const scanResult = document.getElementById('scanResult');

  // Simulated threat DB
  

  const resultMessages = {
    safe:   '✅ SAFE — No threats detected. This URL appears legitimate.',
    danger: '🚨 PHISHING DETECTED — This URL matches known phishing patterns. DO NOT proceed!',
    warn:   '⚠ SUSPICIOUS — This URL shows piracy/suspicious indicators. Proceed with caution.'
  };

  let scanning = false;
  scanBtn.addEventListener('click', async () => {
    console.log("SCAN BUTTON CLICKED");
    const url = urlInput.value.trim();
    if (!url) {
      urlInput.style.borderColor = 'var(--red)';
      setTimeout(() => (urlInput.style.borderColor = ''), 1500);
      return;
    }
    if (scanning) return;
    scanning = true;

    // Scanning state
    scanBtn.classList.add('scanning');
    scanBtn.querySelector('.scan-btn-text').textContent = 'SCANNING';
    scanResult.innerHTML = '';
    scanResult.classList.remove('visible');

    // Add to recent list
    const response = await fetch("/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
          },
          body: JSON.stringify({ url: url })
});

const data = await response.json();

let type = data.result === "Phishing" ? "danger" : "safe";
const features = data.features;
const threatScore = Math.round(data.threat_score);

    const badge = type === 'safe' ? 'badge-safe' : type === 'danger' ? 'badge-danger' : 'badge-warn';
    const badgeText = type === 'safe' ? 'SAFE' : type === 'danger' ? 'PHISHING' : 'SUSPICIOUS';
    const dotColor  = type === 'safe' ? 'green' : type === 'danger' ? 'red' : 'yellow';

    const div = document.createElement('div');
    div.className = `result-${type}`;
    div.textContent = resultMessages[type];
    scanResult.innerHTML = '';
    scanResult.appendChild(div);
    const scorebox = document.createElement("div");
    let color ="green";
    if(threatScore > 70) color = "red";
    else if(threatScore > 40) color = "orange";
    scorebox.className = "threat-score";
    scorebox.innerHTML = `<strong>Threat Score: </strong><span style = "color :${color} "> ${threatScore}%` ;
    
    scanResult.appendChild(scorebox);

    const featureBox = document.createElement("div");
    featureBox.className = "feature-explanation";

    let reasons = [];

    if (features.length_url > 80)
      reasons.push("URL is unusually long");

    if (features.nb_dots > 3)
      reasons.push("Too many subdomains in the URL");

    if (features.phish_hints > 0)
      reasons.push("Suspicious phishing keywords detected");

    if (features.domain_age < 30)
      reasons.push("Domain is very new");

    if (features.iframe === 1)
      reasons.push("Website contains iframe elements");

    if (reasons.length > 0) {
      featureBox.innerHTML = "<h4>⚠ Detection Reasons</h4>";
      reasons.forEach(r => {
        featureBox.innerHTML += `<p>• ${r}</p>`;
  });
}

scanResult.appendChild(featureBox);
    scanResult.classList.add('visible');

    // Add to recent scans
    const recentList = document.getElementById('recentList');
    const item = document.createElement('div');
    item.className = `recent-item ${type}`;
    item.innerHTML = `
      <span class="status-dot ${dotColor}"></span>
      <span class="url-truncate">${url}</span>
      <span class="${badge}">${badgeText}</span>
    `;
    recentList.insertBefore(item, recentList.firstChild);
    if (recentList.children.length > 6) recentList.removeChild(recentList.lastChild);

    scanBtn.classList.remove('scanning');
    scanBtn.querySelector('.scan-btn-text').textContent = 'SCAN NOW';
    scanning = false;
  });

  urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });

  // ============================
  // COUNTER ANIMATION
  // ============================
  const counters = document.querySelectorAll('.stat-num');
  const counterObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateCounter(entry.target);
        counterObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });

  counters.forEach(c => counterObserver.observe(c));

  function animateCounter(el) {
    const target = parseFloat(el.dataset.target);
    const isDecimal = String(target).includes('.');
    const decimals = isDecimal ? 1 : 0;
    let start = 0;
    const duration = 1800;
    const step = timestamp => {
      if (!start) start = timestamp;
      const progress = Math.min((timestamp - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = (eased * target).toFixed(decimals);
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = target.toFixed(decimals);
    };
    requestAnimationFrame(step);
  }

  // ============================
  // CHARTS
  // ============================
  function initCharts() {
    // Line chart
    const accuracyCtx = document.getElementById('accuracyChart');
    if (accuracyCtx) {
      new Chart(accuracyCtx, {
        type: 'line',
        data: {
          labels: ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],
          datasets: [
            {
              label: 'Phishing Detection %',
              data: [94.2, 95.1, 95.8, 96.4, 97.0, 97.5, 98.1, 98.4, 98.9, 99.2, 99.5, 99.7],
              borderColor: '#ff2a2a',
              backgroundColor: 'rgba(255,42,42,0.08)',
              fill: true, tension: 0.4,
              pointBackgroundColor: '#ff2a2a',
              pointRadius: 4, pointHoverRadius: 6,
            },
            {
              label: 'Piracy Detection %',
              data: [88.0, 89.2, 90.5, 91.0, 92.1, 93.0, 93.8, 94.5, 95.0, 95.6, 96.2, 97.1],
              borderColor: '#00e5ff',
              backgroundColor: 'rgba(0,229,255,0.06)',
              fill: true, tension: 0.4,
              pointBackgroundColor: '#00e5ff',
              pointRadius: 4, pointHoverRadius: 6,
            }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: '#5a7a8a', font: { family: 'Share Tech Mono', size: 11 } } } },
          scales: {
            x: { ticks: { color: '#5a7a8a', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: 'rgba(0,229,255,0.06)' } },
            y: {
              ticks: { color: '#5a7a8a', font: { family: 'Share Tech Mono', size: 10 }, callback: v => v + '%' },
              grid: { color: 'rgba(0,229,255,0.06)' },
              min: 85, max: 100
            }
          }
        }
      });
    }

    // Donut chart
    const donutCtx = document.getElementById('donutChart');
    if (donutCtx) {
      new Chart(donutCtx, {
        type: 'doughnut',
        data: {
          labels: ['Phishing', 'Pirated', 'Malware', 'Safe'],
          datasets: [{
            data: [42, 18, 12, 28],
            backgroundColor: ['rgba(255,42,42,0.8)', 'rgba(255,140,0,0.8)', 'rgba(255,208,0,0.8)', 'rgba(0,255,136,0.8)'],
            borderColor: ['#ff2a2a', '#ff8c00', '#ffd000', '#00ff88'],
            borderWidth: 2,
            hoverOffset: 8,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: true,
          cutout: '72%',
          plugins: {
            legend: { display: false },
            tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}%` } }
          },
          animation: { animateScale: true, duration: 1200 }
        }
      });
    }
  }

  // Init charts when dashboard is visible
  const dashObserver = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) { initCharts(); dashObserver.disconnect(); }
  }, { threshold: 0.2 });
  const dashSection = document.getElementById('dashboard');
  if (dashSection) dashObserver.observe(dashSection);

  // ============================
  // PHISHING SIMULATION
  // ============================
  const playBtn  = document.getElementById('playSimBtn');
  const vsteps   = document.querySelectorAll('.vstep');
  let simRunning = false;
  let simTimeout = null;

  playBtn.addEventListener('click', () => {
    if (simRunning) return;
    simRunning = true;
    playBtn.classList.add('running');
    playBtn.textContent = '⚡ SIMULATING...';

    vsteps.forEach(s => s.classList.remove('active'));

    let stepIdx = 0;
    const runStep = () => {
      if (stepIdx >= vsteps.length) {
        setTimeout(() => {
          playBtn.classList.remove('running');
          playBtn.textContent = '▶ PLAY SIMULATION';
          simRunning = false;
          // highlight all briefly then reset
          vsteps.forEach(s => s.classList.add('active'));
          setTimeout(() => vsteps.forEach(s => s.classList.remove('active')), 2000);
        }, 800);
        return;
      }
      vsteps.forEach(s => s.classList.remove('active'));
      vsteps[stepIdx].classList.add('active');
      stepIdx++;
      simTimeout = setTimeout(runStep, 1200);
    };
    runStep();
  });

  // ============================
  // SCROLL REVEAL
  // ============================
  const revealEls = document.querySelectorAll('.feat-card, .sim-info-card, .dash-card, .about-hl, .sim-protect-tips');
  revealEls.forEach(el => el.classList.add('reveal'));

  const revealObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const delay = entry.target.dataset.delay || 0;
        setTimeout(() => entry.target.classList.add('visible'), parseInt(delay));
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

  // Feature cards specific observer
  const featCards = document.querySelectorAll('.feat-card');
  const featObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const delay = parseInt(entry.target.dataset.delay || 0);
        setTimeout(() => entry.target.classList.add('visible'), delay);
      }
    });
  }, { threshold: 0.1 });
  featCards.forEach(c => featObserver.observe(c));

  // ============================
  // SIGNUP FORM
  // ============================
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', e => {
      e.preventDefault();
      const btn = signupForm.querySelector('.signup-submit-btn');
      btn.innerHTML = '<span>✅ REGISTRATION SUCCESSFUL! NETRA IS ACTIVE.</span>';
      btn.style.background = 'linear-gradient(135deg, #00a060, #007040)';
      btn.disabled = true;
      setTimeout(() => {
        btn.innerHTML = '<span>🛡 ACTIVATE NETRA PROTECTION</span>';
        btn.style.background = '';
        btn.disabled = false;
        signupForm.reset();
      }, 4000);
    });
  }

  // ============================
  // ACTIVE NAV LINK ON SCROLL
  // ============================
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  const sectionObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navLinks.forEach(l => l.style.color = '');
        const active = document.querySelector(`.nav-link[href="#${entry.target.id}"]`);
        if (active) { active.style.color = 'var(--cyan)'; }
      }
    });
  }, { threshold: 0.4 });
  sections.forEach(s => sectionObserver.observe(s));

  // ============================
  // UTILITY
  // ============================
  function delay(ms) { return new Promise(res => setTimeout(res, ms)); }

  // ============================
  // TYPING EFFECT FOR URL INPUT
  // ============================
  const placeholders = [
    'https://suspicious-login-bank.xyz',
    'http://paypa1-secure-verify.ru',
    'https://free-movies-hd-stream.co',
    'https://amaz0n-account-alert.net',
    'https://enter-suspicious-url.com',
  ];
  let pIdx = 0;
  let charIdx = 0;
  let typing = true;

  function typePlaceholder() {
    const current = placeholders[pIdx];
    if (typing) {
      charIdx++;
      urlInput.placeholder = current.substring(0, charIdx);
      if (charIdx >= current.length) {
        typing = false;
        setTimeout(typePlaceholder, 2500);
        return;
      }
    } else {
      charIdx--;
      urlInput.placeholder = current.substring(0, charIdx);
      if (charIdx <= 0) {
        typing = true;
        pIdx = (pIdx + 1) % placeholders.length;
      }
    }
    setTimeout(typePlaceholder, typing ? 55 : 25);
  }
  typePlaceholder();

  // ============================
  // THREAT FEED ROTATION
  // ============================
  const threats = [
    'bank-secure-alert.xyz | paypa1-login.net | amaz0n-verify.co',
    'netflix-account-suspended.ru | whatsapp-update.phish.io | support-apple.fake.com',
    'irs-tax-refund-claim.xyz | fedex-package-hold.net | covid-relief-fund.scam.co',
    'instagram-verify.phish.ru | steam-trade-offer.malware.net | crypto-reward-claim.xyz',
  ];
  let threatIdx = 0;
  const alertText = document.querySelector('.alert-text');
  if (alertText) {
    setInterval(() => {
      threatIdx = (threatIdx + 1) % threats.length;
      alertText.innerHTML = `LIVE THREAT FEED: 3 new phishing domains detected in the last 10 minutes — <strong>${threats[threatIdx].split(' | ')[0]}</strong> | <strong>${threats[threatIdx].split(' | ')[1]}</strong> | <strong>${threats[threatIdx].split(' | ')[2]}</strong>`;
    }, 6000);
  }

});
