// SecureWatch Dashboard JS

// ─── Chart defaults ───────────────────────────────────────────
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#1e2d4a';
Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
Chart.defaults.font.size = 11;

const COLORS = {
  blue: '#2563eb', cyan: '#06b6d4', green: '#10b981',
  yellow: '#f59e0b', orange: '#f97316', red: '#ef4444', purple: '#8b5cf6',
};

function alpha(hex, a) {
  const r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${a})`;
}

// ─── Login Activity Chart ─────────────────────────────────────
function buildLoginChart(labels, failedData, successData) {
  const ctx = document.getElementById('loginChart');
  if (!ctx) return;
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Failed Logins',
          data: failedData,
          backgroundColor: alpha(COLORS.red, 0.7),
          borderColor: COLORS.red,
          borderWidth: 1,
          borderRadius: 4,
        },
        {
          label: 'Successful Logins',
          data: successData,
          backgroundColor: alpha(COLORS.green, 0.7),
          borderColor: COLORS.green,
          borderWidth: 1,
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', labels: { padding: 16, boxWidth: 10, usePointStyle: true } },
        tooltip: { backgroundColor: '#111827', borderColor: '#1e2d4a', borderWidth: 1, padding: 10 },
      },
      scales: {
        x: { stacked: false, grid: { color: alpha('#1e2d4a', 0.8) } },
        y: { beginAtZero: true, grid: { color: alpha('#1e2d4a', 0.8) } },
      },
    },
  });
}

// ─── Severity Doughnut ────────────────────────────────────────
function buildSeverityChart(counts) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  const { critical, high, medium, low } = counts;
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [critical, high, medium, low],
        backgroundColor: [alpha(COLORS.red, 0.85), alpha(COLORS.orange, 0.85), alpha(COLORS.yellow, 0.85), alpha(COLORS.green, 0.85)],
        borderColor: ['#0f1629'],
        borderWidth: 3,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: { position: 'right', labels: { padding: 14, boxWidth: 10, usePointStyle: true } },
        tooltip: { backgroundColor: '#111827', borderColor: '#1e2d4a', borderWidth: 1, padding: 10 },
      },
    },
  });
}

// ─── Trend Line Chart ─────────────────────────────────────────
function buildTrendChart(labels, failedData) {
  const ctx = document.getElementById('trendChart');
  if (!ctx) return;
  new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Failed Attempts',
        data: failedData,
        borderColor: COLORS.cyan,
        backgroundColor: alpha(COLORS.cyan, 0.06),
        borderWidth: 2,
        pointRadius: 4,
        pointBackgroundColor: COLORS.cyan,
        fill: true,
        tension: 0.4,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#111827', borderColor: '#1e2d4a', borderWidth: 1, padding: 10 },
      },
      scales: {
        x: { grid: { color: alpha('#1e2d4a', 0.8) } },
        y: { beginAtZero: true, grid: { color: alpha('#1e2d4a', 0.8) } },
      },
    },
  });
}

// ─── Sidebar toggle (mobile) ──────────────────────────────────
function initSidebar() {
  const hamburger = document.getElementById('hamburger');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('overlay');
  if (!hamburger || !sidebar) return;
  hamburger.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    overlay && overlay.classList.toggle('open');
  });
  overlay && overlay.addEventListener('click', () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
  });
}

// ─── Live stats refresh ───────────────────────────────────────
function startLiveRefresh() {
  setInterval(async () => {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const data = await res.json();
      const update = (id, val) => {
        const el = document.getElementById(id);
        if (el && el.textContent !== String(val)) {
          el.textContent = val;
          el.classList.add('updated');
          setTimeout(() => el.classList.remove('updated'), 600);
        }
      };
      update('live-total', data.total_attempts);
      update('live-failed', data.failed);
      update('live-success', data.success);
      update('live-alerts', data.active_alerts);
    } catch (_) {}
  }, 30000);
}

// ─── Auto-dismiss flash messages ─────────────────────────────
function initFlash() {
  document.querySelectorAll('.flash-msg').forEach(el => {
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.5s';
      setTimeout(() => el.remove(), 500);
    }, 4000);
  });
}

// ─── Threat score bar colors ──────────────────────────────────
function initThreatBars() {
  document.querySelectorAll('.threat-bar-fill').forEach(bar => {
    const score = parseInt(bar.getAttribute('data-score') || '0', 10);
    let color = COLORS.green;
    if (score >= 80) color = COLORS.red;
    else if (score >= 60) color = COLORS.orange;
    else if (score >= 40) color = COLORS.yellow;
    bar.style.background = color;
    bar.style.width = score + '%';
    const num = bar.closest('.threat-bar-wrap')?.querySelector('.threat-score-num');
    if (num) { num.style.color = color; }
  });
}

// ─── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initFlash();
  initThreatBars();
  startLiveRefresh();
});
