// HTLand Frontend Application - Main JavaScript File

// ==================== //
// GLOBAL STATE & CONFIG //
// ==================== //
const HTLand = {
    // User state
    user: null,
    walletBalance: 0,
    cartCount: 0,
    wishlistCount: 0,
    
    // App state
    currentTheme: localStorage.getItem('htland-theme') || 'light',
    isLoggedIn: false,
    
    // Live stats
    liveStats: {
        users: 243,
        sales: 15,
        orders: 42
    },
    
    // Configuration
    config: {
        minChargeAmount: 10000,
        maxChargeAmount: 5000000,
        otpTimeout: 120 // seconds
    },
    
    // Data storage
    data: {
        categories: [],
        products: [],
        transactions: []
    }
};

// ==================== //
// DOM ELEMENTS //
// ==================== //
const elements = {
    // Loading
    loading: document.getElementById('loading'),
    
    // Header & Navigation
    header: document.querySelector('.header'),
    mobileToggle: document.querySelector('.mobile-toggle'),
    navMenu: document.querySelector('.nav-menu'),
    floatingMenu: document.querySelectorAll('.floating-item'),
    themeToggle: document.querySelector('.theme-toggle'),
    
    // User Actions
    userBtn: document.querySelector('.user-btn'),
    cartBtn: document.querySelector('.cart-btn'),
    walletBtn: document.querySelector('.wallet-menu-btn'),
    
    // Modals
    authModal: document.getElementById('authModal'),
    walletModal: document.getElementById('walletModal'),
    chargeModal: document.getElementById('chargeModal'),
    twoFAModal: document.getElementById('twoFAModal'),
    modalCloses: document.querySelectorAll('.modal-close'),
    
    // Forms
    loginForm: document.getElementById('loginForm'),
    registerForm: document.getElementById('registerForm'),
    authTabs: document.querySelectorAll('.auth-tab'),
    
    // Wallet
    walletBalance: document.querySelector('.balance'),
    walletBalanceLarge: document.querySelector('.balance-amount'),
    chargeAmount: document.querySelector('.charge-amount'),
    quickAmounts: document.querySelectorAll('.quick-amount'),
    chargeSubmit: document.querySelector('.charge-submit'),
    
    // Quick Actions
    quickActions: document.querySelector('.quick-actions-fixed'),
    scrollTopBtn: document.querySelector('.scroll-top'),
    chatBtn: document.querySelector('.chat-btn'),
    themeToggleBtn: document.querySelector('.theme-toggle-btn'),
    
    // Live Stats
    liveUsers: document.getElementById('live-users'),
    recentSales: document.getElementById('recent-sales'),
    activeOrders: document.getElementById('active-orders'),
    statNumbers: document.querySelectorAll('.stat-number'),
    
    // Content containers
    categoriesGrid: document.querySelector('.categories-grid'),
    productsGrid: document.querySelector('.products-grid'),
    transactionsList: document.querySelector('.transactions-list'),
    
    // Toast container
    toastContainer: document.querySelector('.toast-container'),
    
    // Charts
    onlineUsersChart: document.getElementById('onlineUsersChart'),
    recentSalesChart: document.getElementById('recentSalesChart'),
    activeOrdersChart: document.getElementById('activeOrdersChart'),
    
    // Particles
    particlesContainer: document.getElementById('particles-js')
};

// ==================== //
// UTILITY FUNCTIONS //
// ==================== //

// Format price with Persian numerals
function formatPrice(price) {
    return new Intl.NumberFormat('fa-IR').format(price);
}

// Format date
function formatDate(date) {
    return new Intl.DateTimeFormat('fa-IR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

// Generate random number between min and max
function randomBetween(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Debounce function
function debounce(func, wait) {
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

// Throttle function
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== //
// THEME MANAGEMENT //
// ==================== //
class ThemeManager {
    constructor() {
        this.themes = ['light', 'dark', 'sea', 'royal'];
        this.currentTheme = HTLand.currentTheme;
        this.init();
    }

    init() {
        this.applyTheme();
        this.bindEvents();
        this.updateThemeButton();
    }

    applyTheme() {
        document.body.setAttribute('data-theme', this.currentTheme);
        localStorage.setItem('htland-theme', this.currentTheme);
    }

    toggleTheme() {
        const currentIndex = this.themes.indexOf(this.currentTheme);
        const nextIndex = (currentIndex + 1) % this.themes.length;
        this.currentTheme = this.themes[nextIndex];
        this.applyTheme();
        this.updateThemeButton();
        
        this.showToast(`تم ${this.getThemeName(this.currentTheme)} فعال شد`, 'info');
    }

    getThemeName(theme) {
        const names = {
            'light': 'طبیعت شمال',
            'dark': 'تاریک',
            'sea': 'دریای آبی',
            'royal': 'سلطنتی'
        };
        return names[theme] || theme;
    }

    updateThemeButton() {
        const icons = {
            'light': 'fa-moon',
            'dark': 'fa-sun',
            'sea': 'fa-water',
            'royal': 'fa-crown'
        };
        
        if (elements.themeToggle) {
            const icon = elements.themeToggle.querySelector('i');
            if (icon) {
                icon.className = `fas ${icons[this.currentTheme] || 'fa-palette'}`;
            }
        }
    }

    bindEvents() {
        if (elements.themeToggle) {
            elements.themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        if (elements.themeToggleBtn) {
            elements.themeToggleBtn.addEventListener('click', () => this.toggleTheme());
        }
    }

    showToast(message, type = 'info') {
        Toast.show(message, type);
    }
}

// ==================== //
// TOAST SYSTEM //
// ==================== //
class Toast {
    static show(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icon = this.getIcon(type);
        
        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
            <button class="toast-close">&times;</button>
        `;
        
        elements.toastContainer.appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            toast.style.animation = 'toastSlideOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
        
        // Close button
        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.style.animation = 'toastSlideOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        });
    }

    static getIcon(type) {
        const icons = {
            'success': '✅',
            'error': '❌',
            'warning': '⚠️',
            'info': 'ℹ️'
        };
        return icons[type] || '💡';
    }
}

// ==================== //
// MODAL SYSTEM //
// ==================== //
class ModalSystem {
    constructor() {
        this.modals = {};
        this.init();
    }

    init() {
        // Register all modals
        this.registerModal('auth', elements.authModal);
        this.registerModal('wallet', elements.walletModal);
        this.registerModal('charge', elements.chargeModal);
        this.registerModal('twoFA', elements.twoFAModal);
        
        // Close buttons
        elements.modalCloses.forEach(btn => {
            btn.addEventListener('click', () => {
                this.closeAll();
            });
        });
        
        // Close on outside click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeAll();
                }
            });
        });
        
        // Escape key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeAll();
            }
        });
    }

    registerModal(name, element) {
        this.modals[name] = element;
    }

    openModal(name) {
        this.closeAll();
        const modal = this.modals[name];
        if (modal) {
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
    }

    closeModal(name) {
        const modal = this.modals[name];
        if (modal) {
            modal.classList.remove('active');
            document.body.style.overflow = 'auto';
        }
    }

    closeAll() {
        Object.values(this.modals).forEach(modal => {
            modal.classList.remove('active');
        });
        document.body.style.overflow = 'auto';
    }
}

// ==================== //
// WALLET SYSTEM //
// ==================== //
class WalletSystem {
    constructor() {
        this.balance = HTLand.walletBalance;
        this.transactions = [];
        this.init();
    }

    init() {
        this.loadTransactions();
        this.bindEvents();
        this.updateDisplay();
    }

    loadTransactions() {
        // Simulated transactions
        this.transactions = [
            {
                id: 1,
                type: 'charge',
                amount: 50000,
                description: 'شارژ کیف پول',
                date: new Date(Date.now() - 86400000), // 1 day ago
                status: 'completed'
            },
            {
                id: 2,
                type: 'purchase',
                amount: -25000,
                description: 'خرید برنج هاشمی',
                date: new Date(Date.now() - 172800000), // 2 days ago
                status: 'completed'
            },
            {
                id: 3,
                type: 'refund',
                amount: 15000,
                description: 'عودت وجه',
                date: new Date(Date.now() - 259200000), // 3 days ago
                status: 'completed'
            }
        ];
    }

    updateDisplay() {
        // Update balance display
        if (elements.walletBalance) {
            elements.walletBalance.textContent = `${formatPrice(this.balance)} تومان`;
        }
        
        if (elements.walletBalanceLarge) {
            elements.walletBalanceLarge.textContent = `${formatPrice(this.balance)} تومان`;
        }
        
        // Update transactions list
        this.renderTransactions();
    }

    renderTransactions() {
        if (!elements.transactionsList) return;
        
        if (this.transactions.length === 0) {
            elements.transactionsList.innerHTML = '<p class="empty-state">هیچ تراکنشی یافت نشد</p>';
            return;
        }
        
        const transactionsHtml = this.transactions.map(transaction => `
            <div class="transaction-item">
                <div class="transaction-info">
                    <div class="transaction-title">${escapeHtml(transaction.description)}</div>
                    <div class="transaction-date">${escapeHtml(formatDate(transaction.date))}</div>
                </div>
                <div class="transaction-amount ${transaction.amount > 0 ? 'positive' : 'negative'}">
                    ${transaction.amount > 0 ? '+' : ''}${formatPrice(transaction.amount)} تومان
                </div>
            </div>
        `).join('');
        
        elements.transactionsList.innerHTML = transactionsHtml;
    }

    charge(amount) {
        if (amount < HTLand.config.minChargeAmount) {
            Toast.show(`حداقل مبلغ شارژ ${formatPrice(HTLand.config.minChargeAmount)} تومان است`, 'error');
            return false;
        }
        
        if (amount > HTLand.config.maxChargeAmount) {
            Toast.show(`حداکثر مبلغ شارژ ${formatPrice(HTLand.config.maxChargeAmount)} تومان است`, 'error');
            return false;
        }
        
        // Simulate payment process
        Toast.show('در حال انتقال به درگاه پرداخت...', 'info');
        
        setTimeout(() => {
            this.balance += amount;
            this.transactions.unshift({
                id: Date.now(),
                type: 'charge',
                amount: amount,
                description: 'شارژ کیف پول',
                date: new Date(),
                status: 'completed'
            });
            
            this.updateDisplay();
            Toast.show(`کیف پول شما با موفقیت به مبلغ ${formatPrice(amount)} تومان شارژ شد`, 'success');
            
            // Close charge modal
            modals.closeModal('charge');
        }, 2000);
        
        return true;
    }

    withdraw(amount) {
        if (amount > this.balance) {
            Toast.show('موجودی کیف پول شما کافی نیست', 'error');
            return false;
        }
        
        // Simulate withdrawal process
        Toast.show('درخواست برداشت شما ثبت شد', 'info');
        
        setTimeout(() => {
            this.balance -= amount;
            this.transactions.unshift({
                id: Date.now(),
                type: 'withdraw',
                amount: -amount,
                description: 'برداشت از کیف پول',
                date: new Date(),
                status: 'pending'
            });
            
            this.updateDisplay();
            Toast.show('درخواست برداشت شما با موفقیت ثبت شد', 'success');
        }, 1000);
        
        return true;
    }

    bindEvents() {
        // Charge button
        if (elements.chargeSubmit) {
            elements.chargeSubmit.addEventListener('click', () => {
                const amount = parseInt(elements.chargeAmount?.value || 0);
                this.charge(amount);
            });
        }
        
        // Quick amounts
        if (elements.quickAmounts) {
            elements.quickAmounts.forEach(btn => {
                btn.addEventListener('click', () => {
                    const amount = parseInt(btn.dataset.amount);
                    if (elements.chargeAmount) {
                        elements.chargeAmount.value = amount;
                    }
                    
                    // Update active state
                    elements.quickAmounts.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                });
            });
        }
        
        // Wallet action buttons
        document.querySelector('.charge-action')?.addEventListener('click', () => {
            modals.openModal('charge');
        });
        
        document.querySelector('.withdraw-action')?.addEventListener('click', () => {
            Toast.show('سیستم برداشت به زودی راه‌اندازی می‌شود', 'info');
        });
        
        document.querySelector('.history-action')?.addEventListener('click', () => {
            Toast.show('تاریخچه تراکنش‌ها در حال نمایش است', 'info');
        });
    }
}

// ==================== //
// CHART MANAGER //
// ==================== //
class ChartManager {
    constructor() {
        this.charts = {};
        this.init();
    }

    init() {
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js library not loaded');
            return;
        }
        
        this.createCharts();
        this.startLiveUpdates();
    }

    createCharts() {
        // Online Users Chart (Line)
        if (elements.onlineUsersChart) {
            this.charts.onlineUsers = new Chart(elements.onlineUsersChart, {
                type: 'line',
                data: {
                    labels: this.generateTimeLabels(10),
                    datasets: [{
                        label: 'کاربران آنلاین',
                        data: this.generateRandomData(200, 300, 10),
                        borderColor: 'rgba(46, 125, 50, 1)',
                        backgroundColor: 'rgba(46, 125, 50, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: this.getChartOptions('تعداد')
            });
        }

        // Recent Sales Chart (Bar)
        if (elements.recentSalesChart) {
            this.charts.recentSales = new Chart(elements.recentSalesChart, {
                type: 'bar',
                data: {
                    labels: ['امروز', 'دیروز', '۲ روز قبل', '۳ روز قبل'],
                    datasets: [{
                        label: 'فروش‌ها',
                        data: this.generateRandomData(10, 25, 4),
                        backgroundColor: 'rgba(255, 179, 0, 0.8)',
                        borderColor: 'rgba(255, 143, 0, 1)',
                        borderWidth: 1
                    }]
                },
                options: this.getChartOptions('تعداد فروش')
            });
        }

        // Active Orders Chart (Doughnut)
        if (elements.activeOrdersChart) {
            this.charts.activeOrders = new Chart(elements.activeOrdersChart, {
                type: 'doughnut',
                data: {
                    labels: ['در حال پردازش', 'آماده ارسال', 'در حال ارسال', 'تحویل شده'],
                    datasets: [{
                        data: [15, 12, 8, 7],
                        backgroundColor: [
                            'rgba(255, 112, 67, 0.8)',
                            'rgba(66, 165, 245, 0.8)',
                            'rgba(76, 175, 80, 0.8)',
                            'rgba(255, 202, 40, 0.8)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            rtl: true,
                            labels: {
                                font: {
                                    family: 'Vazirmatn',
                                    size: 12
                                },
                                padding: 20
                            }
                        }
                    }
                }
            });
        }
    }

    startLiveUpdates() {
        setInterval(() => {
            this.updateOnlineUsers();
            this.updateRecentSales();
        }, 10000); // هر 10 ثانیه
    }

    updateOnlineUsers() {
        if (this.charts.onlineUsers) {
            const newData = this.generateRandomData(200, 300, 10);
            this.charts.onlineUsers.data.datasets[0].data = newData;
            this.charts.onlineUsers.update('none');
        }
    }

    updateRecentSales() {
        if (this.charts.recentSales) {
            const newData = [randomBetween(10, 20), randomBetween(10, 20), randomBetween(10, 20), randomBetween(10, 20)];
            this.charts.recentSales.data.datasets[0].data = newData;
            this.charts.recentSales.update('none');
        }
    }

    generateTimeLabels(count) {
        const now = new Date();
        return Array.from({ length: count }, (_, i) => {
            const time = new Date(now.getTime() - (count - i - 1) * 5 * 60000);
            return time.toLocaleTimeString('fa-IR', { 
                hour: '2-digit', 
                minute: '2-digit' 
            });
        });
    }

    generateRandomData(min, max, count) {
        return Array.from({ length: count }, () => randomBetween(min, max));
    }

    getChartOptions(yAxisLabel) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    rtl: true,
                    labels: {
                        font: {
                            family: 'Vazirmatn',
                            size: 13
                        },
                        padding: 20
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        font: {
                            family: 'Vazirmatn'
                        }
                    },
                    title: {
                        display: true,
                        text: yAxisLabel,
                        font: {
                            family: 'Vazirmatn',
                            size: 14
                        }
                    }
                },
                x: {
                    ticks: {
                        font: {
                            family: 'Vazirmatn'
                        }
                    }
                }
            }
        };
    }
}

// ==================== //
// PARTICLE MANAGER //
// ==================== //
class ParticleManager {
    constructor() {
        this.init();
    }

    init() {
        if (typeof particlesJS === 'undefined') {
            console.warn('Particles.js library not loaded');
            return;
        }
        
        if (elements.particlesContainer) {
            particlesJS('particles-js', {
                particles: {
                    number: {
                        value: 80,
                        density: {
                            enable: true,
                            value_area: 800
                        }
                    },
                    color: {
                        value: "#ffffff"
                    },
                    shape: {
                        type: "circle"
                    },
                    opacity: {
                        value: 0.5,
                        random: false
                    },
                    size: {
                        value: 3,
                        random: true
                    },
                    line_linked: {
                        enable: true,
                        distance: 150,
                        color: "#ffffff",
                        opacity: 0.2,
                        width: 1
                    },
                    move: {
                        enable: true,
                        speed: 2,
                        direction: "none",
                        random: false,
                        straight: false,
                        out_mode: "out",
                        bounce: false
                    }
                },
                interactivity: {
                    detect_on: "canvas",
                    events: {
                        onhover: {
                            enable: true,
                            mode: "repulse"
                        },
                        onclick: {
                            enable: true,
                            mode: "push"
                        }
                    }
                },
                retina_detect: true
            });
        }
    }
}

// ==================== //
// AOS HANDLER //
// ==================== //
class AOSHandler {
    constructor() {
        this.init();
    }

    init() {
        if (typeof AOS === 'undefined') {
            console.warn('AOS library not loaded');
            return;
        }
        
        AOS.init({
            duration: 800,
            offset: 100,
            once: true,
            easing: 'ease-in-out',
            disable: window.innerWidth < 768
        });
    }
}

// ==================== //
// WORKING HOURS //
// ==================== //
class WorkingHours {
    constructor() {
        this.workingHours = {
            saturday: { start: 8, end: 22 },
            sunday: { start: 8, end: 22 },
            monday: { start: 8, end: 22 },
            tuesday: { start: 8, end: 22 },
            wednesday: { start: 8, end: 22 },
            thursday: { start: 8, end: 22 },
            friday: { start: 8, end: 14 }
        };
        
        this.persianDays = {
            0: 'شنبه',
            1: 'یکشنبه',
            2: 'دوشنبه',
            3: 'سه‌شنبه',
            4: 'چهارشنبه',
            5: 'پنج‌شنبه',
            6: 'جمعه'
        };
        
        this.init();
    }

    init() {
        this.updateStatus();
        setInterval(() => this.updateStatus(), 60000); // هر دقیقه
    }

    updateStatus() {
        const now = new Date();
        const currentHour = now.getHours();
        const currentDay = now.getDay();
        
        let isOpen = false;
        
        // تبدیل به سیستم هفته ایرانی (شنبه=0)
        let iranianDay = currentDay === 0 ? 6 : currentDay - 1;
        const dayKey = Object.keys(this.workingHours)[iranianDay];
        
        if (dayKey) {
            const hours = this.workingHours[dayKey];
            isOpen = currentHour >= hours.start && currentHour < hours.end;
        }
        
        const statusElement = document.querySelector('.status-indicator');
        if (statusElement) {
            statusElement.textContent = isOpen ? 'هم‌اکنون باز است' : 'هم‌اکنون بسته است';
            statusElement.className = `status-indicator ${isOpen ? 'open' : 'closed'}`;
        }
    }
}

// ==================== //
// AUTHENTICATION SYSTEM //
// ==================== //
class AuthSystem {
    constructor() {
        this.currentUser = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkAuth();
        this.init2FA();
    }

    bindEvents() {
        // Auth tabs
        if (elements.authTabs) {
            elements.authTabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const tabName = tab.dataset.tab;
                    this.switchTab(tabName);
                });
            });
        }
        
        // Login form
        if (elements.loginForm) {
            elements.loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.login();
            });
        }
        
        // Register form
        if (elements.registerForm) {
            elements.registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.register();
            });
        }
        
        // User button
        if (elements.userBtn) {
            elements.userBtn.addEventListener('click', () => {
                if (this.currentUser) {
                    // Show user profile
                    Toast.show(`خوش آمدید ${this.currentUser.name}`, 'success');
                } else {
                    modals.openModal('auth');
                }
            });
        }
        
        // Two-Factor Authentication methods
        document.querySelectorAll('.method-card').forEach(card => {
            card.addEventListener('click', () => {
                const method = card.dataset.method;
                this.requestOTP(method);
            });
        });
        
        // OTP resend button
        document.querySelector('.resend-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.resendOTP();
        });
    }

    switchTab(tabName) {
        // Update active tab
        elements.authTabs.forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });
        
        // Show active form
        document.querySelectorAll('.auth-form').forEach(form => {
            form.classList.toggle('active', form.id === `${tabName}Form`);
        });
    }

    login() {
        const mobile = document.getElementById('loginMobile')?.value;
        const password = document.getElementById('loginPassword')?.value;
        
        if (!this.validateMobile(mobile)) {
            Toast.show('شماره موبایل معتبر وارد کنید', 'error');
            return;
        }
        
        if (!password || password.length < 6) {
            Toast.show('رمز عبور باید حداقل ۶ کاراکتر باشد', 'error');
            return;
        }
        
        // Simulate API call
        Toast.show('در حال ورود...', 'info');
        
        setTimeout(() => {
            // For demo, show 2FA modal
            modals.closeModal('auth');
            modals.openModal('twoFA');
        }, 1500);
    }

    register() {
        const mobile = document.getElementById('registerMobile')?.value;
        const name = document.getElementById('registerName')?.value;
        
        if (!this.validateMobile(mobile)) {
            Toast.show('شماره موبایل معتبر وارد کنید', 'error');
            return;
        }
        
        if (!name || name.length < 3) {
            Toast.show('نام باید حداقل ۳ کاراکتر باشد', 'error');
            return;
        }
        
        // Simulate API call
        Toast.show('در حال ثبت‌نام...', 'info');
        
        setTimeout(() => {
            this.currentUser = {
                id: Date.now(),
                name: name,
                mobile: mobile,
                email: null
            };
            
            HTLand.isLoggedIn = true;
            modals.closeModal('auth');
            Toast.show('ثبت‌نام با موفقیت انجام شد', 'success');
            
            // Update UI
            this.updateUserUI();
            this.saveUser();
        }, 1500);
    }

    validateMobile(mobile) {
        const regex = /^09[0-9]{9}$/;
        return regex.test(mobile);
    }

    init2FA() {
        // Initialize OTP timer
        this.otpTimer = 120;
        this.otpInterval = null;
    }

    requestOTP(method) {
        Toast.show(`کد تأیید به روش ${this.getMethodName(method)} ارسال شد`, 'info');
        
        // Start OTP timer
        this.startOTPTimer();
    }

    getMethodName(method) {
        const names = {
            'sms': 'پیامک',
            'email': 'ایمیل',
            'authenticator': 'Authenticator'
        };
        return names[method] || method;
    }

    startOTPTimer() {
        this.otpTimer = 120;
        const countdownElement = document.querySelector('.countdown');
        const resendBtn = document.querySelector('.resend-btn');
        
        if (countdownElement) {
            countdownElement.textContent = this.otpTimer;
        }
        
        if (resendBtn) {
            resendBtn.disabled = true;
            resendBtn.style.opacity = '0.5';
        }
        
        if (this.otpInterval) {
            clearInterval(this.otpInterval);
        }
        
        this.otpInterval = setInterval(() => {
            this.otpTimer--;
            
            if (countdownElement) {
                countdownElement.textContent = this.otpTimer;
            }
            
            if (this.otpTimer <= 0) {
                clearInterval(this.otpInterval);
                if (resendBtn) {
                    resendBtn.disabled = false;
                    resendBtn.style.opacity = '1';
                }
            }
        }, 1000);
    }

    resendOTP() {
        Toast.show('کد تأیید مجدداً ارسال شد', 'info');
        this.startOTPTimer();
    }

    logout() {
        this.currentUser = null;
        HTLand.isLoggedIn = false;
        localStorage.removeItem('htland-user');
        Toast.show('با موفقیت خارج شدید', 'info');
        this.updateUserUI();
    }

    checkAuth() {
        // Check if user is logged in (from localStorage)
        const savedUser = localStorage.getItem('htland-user');
        if (savedUser) {
            try {
                this.currentUser = JSON.parse(savedUser);
                HTLand.isLoggedIn = true;
                this.updateUserUI();
            } catch (e) {
                console.error('Error parsing saved user:', e);
            }
        }
    }

    updateUserUI() {
        if (elements.userBtn) {
            const icon = elements.userBtn.querySelector('i');
            if (this.currentUser) {
                icon.className = 'fas fa-user-check';
                elements.userBtn.title = this.currentUser.name;
            } else {
                icon.className = 'fas fa-user';
                elements.userBtn.title = 'ورود / ثبت‌نام';
            }
        }
    }

    saveUser() {
        if (this.currentUser) {
            localStorage.setItem('htland-user', JSON.stringify(this.currentUser));
        }
    }
}

// ==================== //
// PRODUCT SYSTEM //
// ==================== //
class ProductSystem {
    constructor() {
        this.products = [];
        this.categories = [];
        this.cart = [];
        this.wishlist = [];
        this.init();
    }

    init() {
        this.loadData();
        this.bindEvents();
        this.renderCategories();
        this.renderProducts();
    }

    loadData() {
        // Sample categories
        this.categories = [
            { id: 1, name: 'برنج شمال', icon: 'fas fa-seedling', description: 'هاشمی، طارم، صدری درجه یک' },
            { id: 2, name: 'خاویار ایرانی', icon: 'fas fa-fish', description: 'طلایی، سیاه، فیل‌ماهی' },
            { id: 3, name: 'ماهی تازه', icon: 'fas fa-fish', description: 'کیلکا، کپور، سفید شمال' },
            { id: 4, name: 'عسل طبیعی', icon: 'fas fa-honey-pot', description: 'گون، کنار، جنگلی' },
            { id: 5, name: 'مرغ محلی', icon: 'fas fa-drumstick-bite', description: 'طبیعی، ارگانیک شمال' },
            { id: 6, name: 'سوغات شمال', icon: 'fas fa-gift', description: 'ترشیجات، مربا، خشکبار' }
        ];

        // Sample products
        this.products = [
            {
                id: 1,
                name: 'برنج هاشمی ممتاز شمال',
                description: 'برنج هاشمی درجه یک شمال با عطر و طعم بی‌نظیر',
                price: 85000,
                originalPrice: 95000,
                discount: 20,
                badge: 'ارگانیک',
                image: 'https://images.unsplash.com/photo-1586201375761-83865001e31c?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80',
                rating: 4.8,
                reviews: 120,
                options: {
                    weight: [
                        { value: '1', label: '۱ کیلو', price: 85000 },
                        { value: '2', label: '۲ کیلو', price: 170000 },
                        { value: '5', label: '۵ کیلو', price: 400000 }
                    ]
                }
            },
            {
                id: 2,
                name: 'خاویار طلایی ایرانی',
                description: 'خاویار درجه یک فیل‌ماهی خزر',
                price: 290000,
                originalPrice: 320000,
                discount: 10,
                badge: 'پرمیوم',
                image: 'https://images.unsplash.com/photo-1584824486509-112e4181ff6b?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80',
                rating: 4.9,
                reviews: 85,
                options: {
                    weight: [
                        { value: '30', label: '۳۰ گرم', price: 290000 },
                        { value: '50', label: '۵۰ گرم', price: 480000 },
                        { value: '100', label: '۱۰۰ گرم', price: 950000 }
                    ]
                }
            },
            {
                id: 3,
                name: 'عسل طبیعی گون',
                description: 'عسل خالص کوهستان‌های شمال',
                price: 75000,
                originalPrice: 85000,
                discount: 15,
                badge: 'ارگانیک',
                image: 'https://images.unsplash.com/photo-1587049352851-8d4e89133924?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80',
                rating: 4.7,
                reviews: 200,
                options: {
                    weight: [
                        { value: '500', label: '۵۰۰ گرم', price: 75000 },
                        { value: '1000', label: '۱ کیلو', price: 140000 },
                        { value: '2000', label: '۲ کیلو', price: 270000 }
                    ]
                }
            }
        ];
    }

    renderCategories() {
        if (!elements.categoriesGrid) return;
        
        const categoriesHtml = this.categories.map((category, index) => `
            <a href="#${category.name.replace(/\s+/g, '-')}" class="category-card" data-aos="fade-up" data-aos-delay="${index * 100}">
                <i class="${category.icon}"></i>
                <h3>${category.name}</h3>
                <p>${category.description}</p>
            </a>
        `).join('');
        
        elements.categoriesGrid.innerHTML = categoriesHtml;
    }

    renderProducts() {
        if (!elements.productsGrid) return;
        
        const productsHtml = this.products.map((product, index) => `
            <div class="product-card" data-aos="fade-up" data-aos-delay="${index * 100}">
                <div class="product-badge">${product.badge}</div>
                ${product.discount ? `<div class="product-badge" style="background: var(--secondary-color); top: 60px;">${product.discount}% تخفیف</div>` : ''}
                
                <div class="product-image">
                    <img src="${product.image}" alt="${product.name}" loading="lazy">
                </div>
                
                <div class="product-content">
                    <h3 class="product-title">${product.name}</h3>
                    <p class="product-description">${product.description}</p>
                    
                    <div class="product-rating">
                        <div class="stars">
                            ${'★'.repeat(Math.floor(product.rating))}${product.rating % 1 >= 0.5 ? '☆' : ''}
                            <span>${product.rating} (${product.reviews} نظر)</span>
                        </div>
                    </div>
                    
                    <div class="product-price">
                        <span class="current-price">${formatPrice(product.price)} تومان</span>
                        ${product.originalPrice ? `<span class="original-price">${formatPrice(product.originalPrice)} تومان</span>` : ''}
                    </div>
                    
                    ${product.options.weight ? `
                    <div class="product-options">
                        <div class="option-group">
                            <label>وزن:</label>
                            <div class="option-buttons">
                                ${product.options.weight.map(option => `
                                    <button class="option-btn" data-product="${product.id}" data-option="weight" data-value="${option.value}" data-price="${option.price}">
                                        ${option.label}
                                    </button>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                    ` : ''}
                    
                    <div class="product-actions">
                        <button class="btn btn-primary btn-block add-to-cart" data-product="${product.id}">
                            <i class="fas fa-shopping-cart"></i>
                            افزودن به سبد
                        </button>
                        <button class="btn btn-outline add-to-wishlist" data-product="${product.id}">
                            <i class="fas fa-heart"></i>
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
        
        elements.productsGrid.innerHTML = productsHtml;
        
        // Add event listeners to newly created elements
        this.bindProductEvents();
    }

    bindProductEvents() {
        // Option buttons
        document.querySelectorAll('.option-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const buttons = e.target.closest('.option-buttons').querySelectorAll('.option-btn');
                buttons.forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                
                // Update price
                const price = parseInt(e.target.dataset.price);
                const priceElement = e.target.closest('.product-card').querySelector('.current-price');
                if (priceElement) {
                    priceElement.textContent = `${formatPrice(price)} تومان`;
                }
            });
        });
        
        // Add to cart buttons
        document.querySelectorAll('.add-to-cart').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const productId = parseInt(e.target.dataset.product);
                this.addToCart(productId);
            });
        });
        
        // Add to wishlist buttons
        document.querySelectorAll('.add-to-wishlist').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const productId = parseInt(e.target.dataset.product);
                this.addToWishlist(productId);
            });
        });
    }

    bindEvents() {
        // Cart button
        if (elements.cartBtn) {
            elements.cartBtn.addEventListener('click', () => {
                if (this.cart.length === 0) {
                    Toast.show('سبد خرید شما خالی است', 'info');
                } else {
                    Toast.show(`شما ${this.cart.length} محصول در سبد خرید دارید`, 'info');
                }
            });
        }
    }

    addToCart(productId) {
        const product = this.products.find(p => p.id === productId);
        if (!product) return;
        
        this.cart.push({
            ...product,
            quantity: 1,
            selectedOptions: {}
        });
        
        HTLand.cartCount = this.cart.length;
        this.updateCartUI();
        
        Toast.show(`"${product.name}" به سبد خرید اضافه شد`, 'success');
    }

    addToWishlist(productId) {
        const product = this.products.find(p => p.id === productId);
        if (!product) return;
        
        if (this.wishlist.some(p => p.id === productId)) {
            Toast.show('این محصول قبلاً به علاقه‌مندی‌ها اضافه شده است', 'info');
            return;
        }
        
        this.wishlist.push(product);
        HTLand.wishlistCount = this.wishlist.length;
        this.updateWishlistUI();
        
        Toast.show(`"${product.name}" به علاقه‌مندی‌ها اضافه شد`, 'success');
    }

    updateCartUI() {
        if (elements.cartBtn) {
            const badge = elements.cartBtn.querySelector('.badge');
            if (badge) {
                badge.textContent = HTLand.cartCount;
                badge.style.display = HTLand.cartCount > 0 ? 'flex' : 'none';
            }
        }
    }

    updateWishlistUI() {
        // Update wishlist badge if exists
        const wishlistBtn = document.querySelector('.wishlist-btn');
        if (wishlistBtn) {
            const badge = wishlistBtn.querySelector('.badge');
            if (badge) {
                badge.textContent = HTLand.wishlistCount;
                badge.style.display = HTLand.wishlistCount > 0 ? 'flex' : 'none';
            }
        }
    }
}

// ==================== //
// LIVE STATS ANIMATION //
// ==================== //
class LiveStats {
    constructor() {
        this.init();
    }

    init() {
        this.animateStats();
        this.updateLiveStats();
    }

    animateStats() {
        if (!elements.statNumbers) return;
        
        elements.statNumbers.forEach(stat => {
            const target = parseInt(stat.dataset.count);
            const duration = 2000;
            const step = target / (duration / 16); // 60fps
            
            let current = 0;
            const timer = setInterval(() => {
                current += step;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                stat.textContent = Math.floor(current) + '+';
            }, 16);
        });
    }

    updateLiveStats() {
        // Simulate live updates
        setInterval(() => {
            if (elements.liveUsers) {
                const change = randomBetween(-5, 5);
                let current = parseInt(elements.liveUsers.textContent);
                current = Math.max(200, current + change);
                elements.liveUsers.textContent = current;
            }
            
            if (elements.recentSales) {
                const change = randomBetween(-2, 3);
                let current = parseInt(elements.recentSales.textContent);
                current = Math.max(5, current + change);
                elements.recentSales.textContent = current;
            }
            
            if (elements.activeOrders) {
                const change = randomBetween(-3, 4);
                let current = parseInt(elements.activeOrders.textContent);
                current = Math.max(30, current + change);
                elements.activeOrders.textContent = current;
            }
        }, 10000); // Update every 10 seconds
    }
}

// ==================== //
// SCROLL ANIMATIONS //
// ==================== //
class ScrollAnimations {
    constructor() {
        this.init();
    }

    init() {
        this.handleScroll();
        this.bindEvents();
    }

    handleScroll() {
        // Header scroll effect
        window.addEventListener('scroll', throttle(() => {
            if (window.scrollY > 100) {
                elements.header.classList.add('scrolled');
            } else {
                elements.header.classList.remove('scrolled');
            }
            
            // Show/hide scroll to top button
            if (elements.scrollTopBtn) {
                if (window.scrollY > 500) {
                    elements.scrollTopBtn.style.opacity = '1';
                    elements.scrollTopBtn.style.visibility = 'visible';
                } else {
                    elements.scrollTopBtn.style.opacity = '0';
                    elements.scrollTopBtn.style.visibility = 'hidden';
                }
            }
        }, 100));
    }

    bindEvents() {
        // Scroll to top button
        if (elements.scrollTopBtn) {
            elements.scrollTopBtn.addEventListener('click', () => {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        }
        
        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    window.scrollTo({
                        top: targetElement.offsetTop - 100,
                        behavior: 'smooth'
                    });
                    
                    // Close mobile menu if open
                    if (window.innerWidth < 992) {
                        elements.navMenu?.classList.remove('active');
                    }
                }
            });
        });
    }
}

// ==================== //
// MOBILE MENU //
// ==================== //
class MobileMenu {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // Mobile menu toggle
        if (elements.mobileToggle) {
            elements.mobileToggle.addEventListener('click', () => {
                elements.navMenu?.classList.toggle('active');
            });
        }
        
        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.nav') && elements.navMenu?.classList.contains('active')) {
                elements.navMenu.classList.remove('active');
            }
        });
        
        // Close menu on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && elements.navMenu?.classList.contains('active')) {
                elements.navMenu.classList.remove('active');
            }
        });
    }
}

// ==================== //
// FLOATING MENU //
// ==================== //
class FloatingMenuHandler {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        if (!elements.floatingMenu) return;
        
        elements.floatingMenu.forEach(item => {
            item.addEventListener('mouseenter', () => {
                // Close other submenus
                elements.floatingMenu.forEach(other => {
                    if (other !== item) {
                        const submenu = other.querySelector('.floating-submenu');
                        if (submenu) {
                            submenu.style.opacity = '0';
                            submenu.style.visibility = 'hidden';
                            submenu.style.transform = 'translateY(-10px)';
                        }
                    }
                });
                
                // Show this submenu
                const submenu = item.querySelector('.floating-submenu');
                if (submenu) {
                    submenu.style.opacity = '1';
                    submenu.style.visibility = 'visible';
                    submenu.style.transform = 'translateY(0)';
                }
            });
            
            item.addEventListener('mouseleave', () => {
                const submenu = item.querySelector('.floating-submenu');
                if (submenu) {
                    setTimeout(() => {
                        submenu.style.opacity = '0';
                        submenu.style.visibility = 'hidden';
                        submenu.style.transform = 'translateY(-10px)';
                    }, 300);
                }
            });
        });
        
        // Close all submenus when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.floating-item')) {
                elements.floatingMenu.forEach(item => {
                    const submenu = item.querySelector('.floating-submenu');
                    if (submenu) {
                        submenu.style.opacity = '0';
                        submenu.style.visibility = 'hidden';
                        submenu.style.transform = 'translateY(-10px)';
                    }
                });
            }
        });
    }
}

// ==================== //
// QUICK ACTIONS //
// ==================== //
class QuickActions {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // Chat button
        if (elements.chatBtn) {
            elements.chatBtn.addEventListener('click', () => {
                Toast.show('سیستم چت به زودی راه‌اندازی می‌شود', 'info');
            });
        }
        
        // Theme toggle button
        if (elements.themeToggleBtn) {
            elements.themeToggleBtn.addEventListener('click', () => {
                themeManager.toggleTheme();
            });
        }
    }
}

// ==================== //
// INITIALIZATION //
// ==================== //
document.addEventListener('DOMContentLoaded', () => {
    // Initialize all systems
    window.themeManager = new ThemeManager();
    window.modals = new ModalSystem();
    window.walletSystem = new WalletSystem();
    window.authSystem = new AuthSystem();
    window.productSystem = new ProductSystem();
    window.liveStats = new LiveStats();
    window.scrollAnimations = new ScrollAnimations();
    window.mobileMenu = new MobileMenu();
    window.floatingMenuHandler = new FloatingMenuHandler();
    window.quickActions = new QuickActions();
    
    // Initialize new systems
    window.chartManager = new ChartManager();
    window.particleManager = new ParticleManager();
    window.aosHandler = new AOSHandler();
    window.workingHours = new WorkingHours();
    
    // Hide loading screen
    setTimeout(() => {
        if (elements.loading) {
            elements.loading.style.opacity = '0';
            setTimeout(() => {
                elements.loading.style.display = 'none';
            }, 300);
        }
    }, 1000);
    
    // Initialize wallet button
    if (elements.walletBtn) {
        elements.walletBtn.addEventListener('click', () => {
            modals.openModal('wallet');
        });
    }
    
    // Initialize charge button in wallet submenu
    const chargeBtn = document.querySelector('.charge-btn');
    if (chargeBtn) {
        chargeBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            modals.openModal('charge');
        });
    }
    
    // Initialize history button in wallet submenu
    const historyBtn = document.querySelector('.history-btn');
    if (historyBtn) {
        historyBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            Toast.show('تاریخچه تراکنش‌ها در حال نمایش است', 'info');
        });
    }
    
    // Map button
    const mapBtn = document.querySelector('.map-btn');
    if (mapBtn) {
        mapBtn.addEventListener('click', () => {
            Toast.show('نقشه در حال بارگذاری...', 'info');
            setTimeout(() => {
                window.open('https://maps.google.com/?q=مازندران، ساری، بلوار طالقانی', '_blank');
            }, 1000);
        });
    }
    
    // Register Service Worker (only once)
    registerServiceWorker();
    
    console.log('🎯 HTLand Frontend Application Initialized!');
});

// ==================== //
// SERVICE WORKER REGISTRATION //
// ==================== //
function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('service-worker.js')
            .then(registration => {
                console.log('ServiceWorker registered:', registration.scope);
                
                // Check for updates
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    console.log('ServiceWorker update found:', newWorker.state);
                    
                    newWorker.addEventListener('statechange', () => {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            Toast.show('نسخه جدیدی از برنامه موجود است. لطفاً صفحه را رفرش کنید.', 'info');
                        }
                    });
                });
            })
            .catch(error => {
                console.log('ServiceWorker registration failed:', error);
            });
    }
}

// ==================== //
// PERFORMANCE MONITORING //
// ==================== //
window.addEventListener('load', () => {
    // Log performance metrics
    if ('performance' in window) {
        const perfData = window.performance.getEntriesByType('navigation')[0];
        if (perfData) {
            console.log('Page loaded in:', perfData.loadEventEnd - perfData.loadEventStart, 'ms');
            console.log('DOM loaded in:', perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart, 'ms');
        }
    }
});

// ==================== //
// ERROR HANDLING //
// ==================== */
window.addEventListener('error', (e) => {
    console.error('Application error:', e.error);
    Toast.show('خطایی در سیستم رخ داده است', 'error');
});

// ==================== //
// EXPORT FOR DEBUGGING //
// ==================== //
if (typeof window !== 'undefined') {
    window.HTLand = HTLand;
}