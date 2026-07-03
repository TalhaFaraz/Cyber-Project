// ─── CyberShield Frontend Utilities ─────────────────────────────────────────
// Shared across all pages

const API_BASE = '/api';

// ─── Auth Helpers ─────────────────────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('token'),
  getUser: () => JSON.parse(localStorage.getItem('user') || 'null'),
  isLoggedIn: () => !!localStorage.getItem('token'),
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login.html';
  },
  requireAuth: () => {
    if (!Auth.isLoggedIn()) window.location.href = '/login.html';
  },
  requireGuest: () => {
    if (Auth.isLoggedIn()) window.location.href = '/dashboard.html';
  },
};

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────
const Http = {
  headers: () => ({
    'Content-Type': 'application/json',
    ...(Auth.getToken() ? { Authorization: `Bearer ${Auth.getToken()}` } : {}),
  }),

  get: async (url) => {
    const res = await fetch(API_BASE + url, { headers: Http.headers() });
    return res.json();
  },

  post: async (url, body) => {
    const res = await fetch(API_BASE + url, {
      method: 'POST',
      headers: Http.headers(),
      body: JSON.stringify(body),
    });
    return res.json();
  },

  put: async (url, body) => {
    const res = await fetch(API_BASE + url, {
      method: 'PUT',
      headers: Http.headers(),
      body: JSON.stringify(body),
    });
    return res.json();
  },

  delete: async (url) => {
    const res = await fetch(API_BASE + url, {
      method: 'DELETE',
      headers: Http.headers(),
    });
    return res.json();
  },
};

// ─── Toast Notifications ──────────────────────────────────────────────────────
const Toast = {
  show: (msg, type = 'info') => {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: 'fa-check-circle', error: 'fa-circle-xmark', info: 'fa-circle-info', warning: 'fa-triangle-exclamation' };
    const toast = document.createElement('div');
    toast.className = `cyber-toast ${type}`;
    toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  },
  success: (msg) => Toast.show(msg, 'success'),
  error: (msg) => Toast.show(msg, 'error'),
  info: (msg) => Toast.show(msg, 'info'),
  warning: (msg) => Toast.show(msg, 'warning'),
};

// ─── Activity Logger ──────────────────────────────────────────────────────────
const Activity = {
  log: async (toolId, actionType, queryInput = '') => {
    if (!Auth.isLoggedIn()) return;
    // Store locally
    const localLog = JSON.parse(localStorage.getItem('activityLog') || '[]');
    localLog.push({ toolId, action: actionType, timestamp: new Date().toISOString() });
    localStorage.setItem('activityLog', JSON.stringify(localLog.slice(-100))); // keep last 100
    // Send to backend
    try {
      await Http.post('/activity/log', { tool_id: toolId, action_type: actionType, query_input: queryInput });
    } catch (e) {}
  },
};

// ─── Bookmark Manager ─────────────────────────────────────────────────────────
const Bookmarks = {
  get: () => JSON.parse(localStorage.getItem('bookmarks') || '[]'),
  has: (id) => Bookmarks.get().includes(id),
  toggle: (id) => {
    const bm = Bookmarks.get();
    const idx = bm.indexOf(id);
    if (idx === -1) { bm.push(id); } else { bm.splice(idx, 1); }
    localStorage.setItem('bookmarks', JSON.stringify(bm));
    return idx === -1; // true = added
  },
  count: () => Bookmarks.get().length,
};

// ─── Format Utilities ─────────────────────────────────────────────────────────
const Format = {
  json: (data) => JSON.stringify(data, null, 2),
  date: (d) => new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
  relativeTime: (d) => {
    const diff = Date.now() - new Date(d).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  },
};

// ─── Counter Animation ────────────────────────────────────────────────────────
const animateCount = (el, target, suffix = '', duration = 1500) => {
  let start = 0;
  const step = target / (duration / 16);
  const timer = setInterval(() => {
    start = Math.min(start + step, target);
    el.textContent = Math.floor(start) + suffix;
    if (start >= target) clearInterval(timer);
  }, 16);
};
