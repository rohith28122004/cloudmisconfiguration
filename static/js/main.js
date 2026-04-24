/**
 * CloudShield - Main JavaScript
 * Cloud Security Scanner Frontend Logic
 * Includes Light/Dark Theme Support
 */

// ===== Theme Management =====
const ThemeManager = {
    STORAGE_KEY: 'cloudshield-theme',

    init() {
        // Check for saved theme preference or default to light
        const savedTheme = localStorage.getItem(this.STORAGE_KEY) || 'light';
        this.setTheme(savedTheme);
        this.createToggleButton();
    },

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem(this.STORAGE_KEY, theme);
        this.updateToggleButton(theme);
    },

    getTheme() {
        return document.documentElement.getAttribute('data-theme') || 'light';
    },

    toggle() {
        const currentTheme = this.getTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    },

    createToggleButton() {
        // Check if toggle already exists
        if (document.querySelector('.theme-toggle')) return;

        const toggle = document.createElement('button');
        toggle.className = 'theme-toggle';
        toggle.setAttribute('aria-label', 'Toggle theme');
        toggle.innerHTML = `
            <span class="theme-toggle-icon">🌙</span>
            <span class="theme-toggle-text">Dark</span>
        `;
        toggle.addEventListener('click', () => this.toggle());
        document.body.appendChild(toggle);

        this.updateToggleButton(this.getTheme());
    },

    updateToggleButton(theme) {
        const toggle = document.querySelector('.theme-toggle');
        if (!toggle) return;

        const icon = toggle.querySelector('.theme-toggle-icon');
        const text = toggle.querySelector('.theme-toggle-text');

        if (theme === 'dark') {
            icon.textContent = '☀️';
            text.textContent = 'Light';
        } else {
            icon.textContent = '🌙';
            text.textContent = 'Dark';
        }
    }
};

// ===== Utility Functions =====
const Utils = {
    formatDate: (date) => {
        return new Intl.DateTimeFormat('en-IN', {
            dateStyle: 'medium',
            timeStyle: 'short'
        }).format(new Date(date));
    },

    formatNumber: (num) => {
        return new Intl.NumberFormat('en-IN').format(num);
    },

    getScoreClass: (score) => {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    },

    getStatusClass: (percentage) => {
        if (percentage >= 80) return 'good';
        if (percentage >= 60) return 'warning';
        return 'bad';
    },

    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// ===== API Wrapper =====
const API = {
    baseUrl: '',

    async get(endpoint) {
        try {
            const response = await fetch(this.baseUrl + endpoint);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    },

    async post(endpoint, data = {}) {
        try {
            const response = await fetch(this.baseUrl + endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    }
};

// ===== Chart Configuration =====
const ChartConfig = {
    getDefaultOptions() {
        const isDark = ThemeManager.getTheme() === 'dark';
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: isDark ? '#e2e8f0' : '#0f172a',
                        padding: 15,
                        font: { family: 'Inter' }
                    }
                }
            },
            scales: {
                y: {
                    ticks: { color: isDark ? '#94a3b8' : '#475569' },
                    grid: { color: isDark ? 'rgba(148, 163, 184, 0.1)' : 'rgba(0, 0, 0, 0.1)' }
                },
                x: {
                    ticks: { color: isDark ? '#94a3b8' : '#475569' },
                    grid: { display: false }
                }
            }
        };
    },

    colors: {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#22c55e',
        blue: '#3b82f6',
        purple: '#8b5cf6'
    }
};

// ===== Toast Notifications =====
const Toast = {
    show(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => toast.classList.add('show'), 10);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
};

// Add toast styles
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    .toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        box-shadow: var(--shadow-lg);
        transform: translateY(100px);
        opacity: 0;
        transition: all 0.3s ease;
        z-index: 1000;
    }
    .toast.show {
        transform: translateY(0);
        opacity: 1;
    }
    .toast-success { border-left: 4px solid #22c55e; }
    .toast-error { border-left: 4px solid #ef4444; }
    .toast-warning { border-left: 4px solid #eab308; }
    .toast-info { border-left: 4px solid #3b82f6; }
`;
document.head.appendChild(toastStyles);

// ===== Initialize on DOM Load =====
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();
    console.log('CloudShield initialized with theme:', ThemeManager.getTheme());
});
