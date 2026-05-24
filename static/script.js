// ========================================
// ЗАЩИТА ОТ XSS
// ========================================

/**
 * Экранирует HTML-специальные символы в строке.
 * Применять к любым данным от пользователя/сервера перед вставкой в innerHTML.
 */
function escapeHtml(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/**
 * Проверяет URL перед вставкой в src/href. Разрешает http(s), data:image/
 * и относительные пути /static/... (для локально захостенных картинок).
 * Блокирует javascript:, vbscript:, file: и прочие опасные схемы.
 */
function safeUrl(u) {
    const s = String(u ?? '').trim();
    if (/^(https?:\/\/|data:image\/)/i.test(s)) return s;
    if (/^\/static\//.test(s)) return s;
    return '';
}

const LOT_PLACEHOLDER_IMG = '/static/img/lots/placeholder.jpg';

// ========================================
// TOAST УВЕДОМЛЕНИЯ
// ========================================

function showToast(message, type = 'error') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'fixed top-24 right-4 z-[100] flex flex-col gap-3 pointer-events-none';
        document.body.appendChild(container);
    }
    
    const colors = {
        error: 'bg-red-500/10 border-red-500/30 text-red-400',
        success: 'bg-green-500/10 border-green-500/30 text-green-400',
        info: 'bg-[var(--gold)]/10 border-[var(--gold)]/30 text-[var(--gold)]'
    };
    const icons = {
        error: 'lucide:alert-circle',
        success: 'lucide:check-circle',
        info: 'lucide:info'
    };
    
    const toast = document.createElement('div');
    toast.className = `pointer-events-auto backdrop-blur-md ${colors[type] || colors.error} border rounded-2xl px-5 py-4 flex items-center gap-3 shadow-xl min-w-[280px] max-w-md transition-all duration-300 translate-x-full opacity-0`;
    toast.innerHTML = `
        <iconify-icon icon="${icons[type] || icons.error}" class="text-xl flex-shrink-0"></iconify-icon>
        <span class="text-sm font-bold flex-1">${escapeHtml(message)}</span>
        <button class="opacity-50 hover:opacity-100 transition-opacity">
            <iconify-icon icon="lucide:x" class="text-lg"></iconify-icon>
        </button>
    `;
    
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.remove('translate-x-full', 'opacity-0');
    });
    
    const remove = () => {
        toast.classList.add('translate-x-full', 'opacity-0');
        setTimeout(() => toast.remove(), 300);
    };
    
    toast.querySelector('button').addEventListener('click', remove);
    setTimeout(remove, 4000);
}

// Глобальный доступ
window.showToast = showToast;

// ========================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ========================================

let currentUser = null;
let lots = [];
let featuredLot = null;

// Пагинация лотов
const LOTS_PAGE_SIZE = 6;
let lotsShownCount = 0;
let currentFilteredLots = [];

// ========================================
// ИНИЦИАЛИЗАЦИЯ
// ========================================

document.addEventListener('DOMContentLoaded', async function() {
    await checkAuth();
    await loadLots();
    setupEventListeners();
});

// ========================================
// ПРОВЕРКА АВТОРИЗАЦИИ
// ========================================

async function checkAuth() {
    try {
        const response = await fetch('/api/me');
        if (response.ok) {
            currentUser = await response.json();
            updateAuthUI();
        }
    } catch (error) {
        console.log('Пользователь не авторизован');
    }
}

function updateAuthUI() {
    const loginBtn = document.getElementById('header-login-btn');
    const registerBtn = document.getElementById('header-register-btn');
    
    if (currentUser) {
        loginBtn.textContent = currentUser.username;
        loginBtn.onclick = () => window.location.href = '/profile';
        registerBtn.textContent = 'Выйти';
        registerBtn.onclick = () => logout();
        
        // Кнопка создания лота только для админов
        if (currentUser.is_admin) {
            const createBtn = document.getElementById('createLotHeaderBtn');
            if (createBtn) createBtn.classList.remove('hidden');
        }
    }
}

// ========================================
// ЗАГРУЗКА ЛОТОВ
// ========================================

async function loadLots() {
    try {
        const response = await fetch('/api/lots');
        lots = await response.json();
        
        // Находим избранный лот
        featuredLot = lots.find(lot => lot.is_featured) || lots[0];
        
        displayHeroLot();
        displayLots();
        startTimers();
    } catch (error) {
        console.error('Ошибка загрузки лотов:', error);
    }
}

// ========================================
// ОТОБРАЖЕНИЕ HERO ЛОТА
// ========================================

function displayHeroLot() {
    if (!featuredLot) return;
    
    document.getElementById('heroTitle').textContent = featuredLot.title;
    // venue и date — пользовательские данные, экранируем
    document.getElementById('heroDescription').innerHTML = `
        ${escapeHtml(featuredLot.venue)} • ${escapeHtml(featuredLot.date)}
    `;
    // current_price — число, .toLocaleString() возвращает безопасную строку
    document.getElementById('heroPrice').innerHTML = `
        ${featuredLot.current_price.toLocaleString()} 
        <span class="text-xl font-medium text-gray-400 tracking-normal uppercase">AMD</span>
    `;
    // .src через присваивание + safeUrl блокирует javascript:
    const heroImg = document.getElementById('heroImage');
    heroImg.onerror = function() { this.onerror = null; this.src = LOT_PLACEHOLDER_IMG; };
    heroImg.src = safeUrl(featuredLot.image_url) || LOT_PLACEHOLDER_IMG;
    
    // Обработчик кнопки ставки - переход на страницу лота
    const heroLink = document.getElementById('hero-bid-cta-link');
    heroLink.href = `/lot/${featuredLot.id}`;
    heroLink.onclick = null;
}

// ========================================
// ОТОБРАЖЕНИЕ ЛОТОВ
// ========================================

function displayLots() {
    const lotsGrid = document.getElementById('lotsGrid');
    lotsGrid.innerHTML = '';
    lotsShownCount = 0;

    // Фильтрация по дате (или все лоты)
    currentFilteredLots = selectedDate
        ? lots.filter(lot => {
            const lotDate = parseLotDate(lot.date);
            return lotDate && lotDate.toDateString() === selectedDate.toDateString();
        })
        : lots;

    const noMsg = document.getElementById('noLotsMessage');

    if (currentFilteredLots.length === 0 && selectedDate) {
        lotsGrid.classList.add('hidden');
        if (noMsg) noMsg.classList.remove('hidden');
        updateShowMoreBtn();
    } else {
        lotsGrid.classList.remove('hidden');
        if (noMsg) noMsg.classList.add('hidden');
        // Показываем первые LOTS_PAGE_SIZE лотов
        const firstBatch = currentFilteredLots.slice(0, LOTS_PAGE_SIZE);
        firstBatch.forEach(lot => lotsGrid.appendChild(createLotCard(lot)));
        lotsShownCount = firstBatch.length;
        updateShowMoreBtn();
    }

    generateCalendarRibbon();
}

/** Показывает следующую порцию лотов из currentFilteredLots */
function showMoreLots() {
    const lotsGrid = document.getElementById('lotsGrid');
    const nextBatch = currentFilteredLots.slice(lotsShownCount, lotsShownCount + LOTS_PAGE_SIZE);
    nextBatch.forEach(lot => lotsGrid.appendChild(createLotCard(lot)));
    lotsShownCount += nextBatch.length;
    updateShowMoreBtn();
}

/** Показывает/скрывает кнопку "Показать ещё" */
function updateShowMoreBtn() {
    const wrapper = document.getElementById('showMoreWrapper');
    if (!wrapper) return;
    if (lotsShownCount < currentFilteredLots.length) {
        wrapper.classList.remove('hidden');
    } else {
        wrapper.classList.add('hidden');
    }
}

function createLotCard(lot) {
    const timeLeft = getTimeLeft(lot.end_time);
    const isUrgent = isLotUrgent(lot.end_time);

    // Бейдж статуса лота: «Повторный аукцион» / «Последний шанс» / «Аукцион закрыт».
    // Показывается в верхнем правом углу карточки. Поля retry_count / status
    // приходят из Lot.to_dict() (коммит #3). Используем textContent через
    // отдельный span — экранирование не нужно, но всё равно держим текст
    // статичным, без user-input.
    let statusBadgeHtml = '';
    if (lot.status === 'finalized') {
        statusBadgeHtml = `
            <div class="absolute top-5 right-5 bg-gray-500/80 backdrop-blur-md px-4 py-1.5 rounded-full flex items-center gap-2 border border-white/10">
                <iconify-icon icon="lucide:lock" class="text-white text-sm"></iconify-icon>
                <span class="text-xs font-bold text-white uppercase tracking-wider">Аукцион закрыт</span>
            </div>`;
    } else if (Number(lot.retry_count) === 2) {
        statusBadgeHtml = `
            <div class="absolute top-5 right-5 bg-red-600/90 backdrop-blur-md px-4 py-1.5 rounded-full flex items-center gap-2 border border-red-400/30 animate-pulse">
                <iconify-icon icon="lucide:flame" class="text-white text-sm"></iconify-icon>
                <span class="text-xs font-bold text-white uppercase tracking-wider">Последний шанс</span>
            </div>`;
    } else if (Number(lot.retry_count) === 1) {
        statusBadgeHtml = `
            <div class="absolute top-5 right-5 bg-orange-500/90 backdrop-blur-md px-4 py-1.5 rounded-full flex items-center gap-2 border border-orange-300/30">
                <iconify-icon icon="lucide:rotate-ccw" class="text-white text-sm"></iconify-icon>
                <span class="text-xs font-bold text-white uppercase tracking-wider">Повторный аукцион</span>
            </div>`;
    }

    const card = document.createElement('div');
    card.className = 'group bg-[var(--surface)] rounded-[32px] overflow-hidden border border-white/5 card-hover transition-all duration-300 flex flex-col cursor-pointer';
    card.onclick = () => window.location.href = `/lot/${lot.id}`;

    card.innerHTML = `
        <div class="relative h-72 overflow-hidden">
            <img src="${escapeHtml(safeUrl(lot.image_url) || LOT_PLACEHOLDER_IMG)}" onerror="this.onerror=null;this.src='${LOT_PLACEHOLDER_IMG}'" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-700">
            <div class="absolute top-5 left-5 bg-black/70 backdrop-blur-md px-4 py-1.5 rounded-full flex items-center gap-2 border border-white/10">
                <iconify-icon icon="lucide:users" class="text-[var(--gold)] text-sm"></iconify-icon>
                <span class="text-xs font-bold text-white uppercase tracking-wider">${Number(lot.participants) || 0} Участников</span>
            </div>
            ${statusBadgeHtml}
            <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black via-black/40 to-transparent p-5">
                <div class="flex items-center gap-2 text-white font-bold timer-font ${isUrgent ? 'bg-red-600/30 border-red-500/30' : 'bg-white/10 border-white/10'} backdrop-blur-md w-fit px-3 py-1.5 rounded-xl border text-sm" data-lot-id="${Number(lot.id)}">
                    ${isUrgent ? '<iconify-icon icon="lucide:timer" class="animate-pulse"></iconify-icon>' : ''} ${escapeHtml(timeLeft)}
                </div>
            </div>
        </div>
        <div class="p-8 flex-1 flex flex-col gap-6">
            <div class="space-y-1">
                <h3 class="text-2xl font-extrabold text-white tracking-tight uppercase">${escapeHtml(lot.title)}</h3>
                <p class="text-sm text-gray-500 font-medium">${escapeHtml(lot.venue)}</p>
            </div>
            <div class="flex flex-wrap gap-2">
                ${(lot.tags || []).map(tag => `<span class="text-[10px] uppercase font-black tracking-widest px-3 py-1 rounded-lg bg-white/5 text-gray-400 border border-white/10">${escapeHtml(tag)}</span>`).join('')}
            </div>
            <div class="grid grid-cols-2 gap-4 pt-6 border-t border-white/10">
                <div class="space-y-1">
                    <p class="text-[10px] text-gray-500 uppercase font-black tracking-widest">Текущая ставка</p>
                    <p class="text-xl font-bold text-white">${Number(lot.current_price).toLocaleString()} AMD</p>
                </div>
                <div class="space-y-1">
                    <p class="text-[10px] text-gray-500 uppercase font-black tracking-widest">Мин. шаг</p>
                    <p class="text-xl font-bold text-[var(--gold)]">+${Number(lot.bid_step).toLocaleString()} AMD</p>
                </div>
            </div>
            <a href="/lot/${Number(lot.id)}" onclick="event.stopPropagation()" class="block w-full text-center bg-white/5 border border-white/10 text-white py-4 rounded-2xl font-extrabold hover:bg-[var(--gold)] hover:text-black hover:border-[var(--gold)] transition-all uppercase tracking-widest text-sm">
                Сделать ставку
            </a>
        </div>
    `;
    
    return card;
}

// ========================================
// ТАЙМЕРЫ
// ========================================

function getTimeLeft(endTime) {
    const now = new Date().getTime();
    // Добавляем Z если нет, чтобы парсилось как UTC
    let endStr = endTime;
    if (typeof endStr === 'string' && !endStr.endsWith('Z') && !endStr.includes('+')) {
        endStr += 'Z';
    }
    const end = new Date(endStr).getTime();
    const diff = end - now;
    
    if (diff <= 0) {
        return "Завершен";
    }
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

function isLotUrgent(endTime) {
    const now = new Date().getTime();
    let endStr = endTime;
    if (typeof endStr === 'string' && !endStr.endsWith('Z') && !endStr.includes('+')) {
        endStr += 'Z';
    }
    const end = new Date(endStr).getTime();
    return (end - now) > 0 && (end - now) < 3 * 60 * 60 * 1000;
}

function startTimers() {
    // Обновляем hero таймер
    setInterval(() => {
        if (featuredLot) {
            document.getElementById('heroTimer').textContent = getTimeLeft(featuredLot.end_time);
        }
    }, 1000);
    
    // Обновляем таймеры на карточках
    setInterval(() => {
        document.querySelectorAll('[data-lot-id]').forEach(timer => {
            const lotId = parseInt(timer.dataset.lotId);
            const lot = lots.find(l => l.id === lotId);
            if (lot) {
                const text = getTimeLeft(lot.end_time);
                timer.textContent = text;
                if (text === 'Завершен') {
                    timer.classList.add('bg-gray-700/50');
                    timer.classList.remove('bg-red-600/30', 'bg-white/10');
                }
            }
        });
    }, 1000);
}

// ========================================
// МОДАЛЬНОЕ ОКНО СТАВКИ
// ========================================

function openBidModal(lotOrId) {
    const lot = typeof lotOrId === 'object' ? lotOrId : lots.find(l => l.id === lotOrId);
    
    if (!currentUser) {
        showLoginModal();
        return;
    }
    
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm';
    modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
    };
    
    modal.innerHTML = `
        <div class="bg-[var(--surface)] rounded-[32px] p-8 max-w-2xl w-full mx-4 border border-white/10">
            <div class="flex justify-between items-start mb-6">
                <h2 class="text-3xl font-black text-white uppercase tracking-tight">${escapeHtml(lot.title)}</h2>
                <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-white">
                    <iconify-icon icon="lucide:x" class="text-2xl"></iconify-icon>
                </button>
            </div>
            
            <div class="space-y-6">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="text-xs text-gray-500 uppercase font-black tracking-widest mb-2">Текущая ставка</p>
                        <p class="text-3xl font-bold text-white">${Number(lot.current_price).toLocaleString()} AMD</p>
                    </div>
                    <div>
                        <p class="text-xs text-gray-500 uppercase font-black tracking-widest mb-2">Минимальный шаг</p>
                        <p class="text-3xl font-bold text-[var(--gold)]">+${Number(lot.bid_step).toLocaleString()} AMD</p>
                    </div>
                </div>
                
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Ваша ставка</label>
                    <input type="number" id="bidAmount" min="${Number(lot.current_price) + Number(lot.bid_step)}" value="${Number(lot.current_price) + Number(lot.bid_step)}" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-xl font-bold focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <button onclick="submitBid(${Number(lot.id)})" class="w-full bg-[var(--gold)] text-black py-4 rounded-2xl font-black text-lg uppercase tracking-widest hover:bg-[var(--gold)]/90 transition-all">
                    Сделать ставку
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function submitBid(lotId) {
    const amount = parseInt(document.getElementById('bidAmount').value);
    
    try {
        const response = await fetch(`/api/lots/${lotId}/bid`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ amount })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Ставка принята! Вы лидируете.', 'success');
            document.querySelector('.fixed').remove();
            await loadLots(); // Перезагружаем лоты
        } else {
            showToast(data.error);
        }
    } catch (error) {
        showToast('Ошибка при отправке ставки');
        console.error(error);
    }
}

// ========================================
// АВТОРИЗАЦИЯ
// ========================================

function showLoginModal() {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm';
    modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
    };
    
    modal.innerHTML = `
        <div class="bg-[var(--surface)] rounded-[32px] p-8 max-w-md w-full mx-4 border border-white/10">
            <h2 class="text-3xl font-black text-white uppercase tracking-tight mb-6">Вход</h2>
            
            <div class="space-y-4">
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Имя пользователя</label>
                    <input type="text" id="loginUsername" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Пароль</label>
                    <input type="password" id="loginPassword" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <button onclick="login()" class="w-full bg-[var(--gold)] text-black py-4 rounded-2xl font-black text-lg uppercase tracking-widest hover:bg-[var(--gold)]/90 transition-all">
                    Войти
                </button>
                
                <p class="text-center text-gray-400 text-sm">
                    Нет аккаунта? <a href="#" onclick="event.preventDefault(); showRegisterModal()" class="text-[var(--gold)] hover:underline">Зарегистрироваться</a>
                </p>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

function showRegisterModal() {
    document.querySelector('.fixed')?.remove();
    
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm';
    modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
    };
    
    modal.innerHTML = `
        <div class="bg-[var(--surface)] rounded-[32px] p-8 max-w-md w-full mx-4 border border-white/10">
            <h2 class="text-3xl font-black text-white uppercase tracking-tight mb-6">Регистрация</h2>
            
            <div class="space-y-4">
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Имя пользователя</label>
                    <input type="text" id="regUsername" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Email</label>
                    <input type="email" id="regEmail" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <div>
                    <label class="text-sm text-gray-400 uppercase font-bold tracking-widest mb-2 block">Пароль</label>
                    <input type="password" id="regPassword" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-[var(--gold)]">
                </div>
                
                <button onclick="register()" class="w-full bg-[var(--gold)] text-black py-4 rounded-2xl font-black text-lg uppercase tracking-widest hover:bg-[var(--gold)]/90 transition-all">
                    Зарегистрироваться
                </button>
                
                <p class="text-center text-gray-400 text-sm">
                    Уже есть аккаунт? <a href="#" onclick="event.preventDefault(); showLoginModal()" class="text-[var(--gold)] hover:underline">Войти</a>
                </p>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}

async function login() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            updateAuthUI();
            document.querySelector('.fixed').remove();
            showToast('Вход выполнен успешно!', 'success');
        } else {
            showToast(data.error);
        }
    } catch (error) {
        showToast('Ошибка при входе');
        console.error(error);
    }
}

async function register() {
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            updateAuthUI();
            document.querySelector('.fixed').remove();
            showToast('Регистрация успешна!', 'success');
        } else {
            showToast(data.error);
        }
    } catch (error) {
        showToast('Ошибка при регистрации');
        console.error(error);
    }
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        currentUser = null;
        location.reload();
    } catch (error) {
        console.error('Ошибка при выходе:', error);
    }
}

// ========================================
// ИЗБРАННОЕ
// ========================================

async function toggleFavorite(lotId) {
    if (!currentUser) {
        showLoginModal();
        return;
    }
    
    try {
        const response = await fetch(`/api/lots/${lotId}/favorite`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'info');
        }
    } catch (error) {
        console.error('Ошибка при добавлении в избранное:', error);
    }
}

// ========================================
// ОБРАБОТЧИКИ СОБЫТИЙ
// ========================================

function setupEventListeners() {
    document.getElementById('header-login-btn').addEventListener('click', () => {
        if (currentUser) {
            showUserMenu();
        } else {
            window.location.href = '/login';
        }
    });
    document.getElementById('header-register-btn').addEventListener('click', () => {
        if (currentUser) {
            logout();
        } else {
            window.location.href = '/register';
        }
    });
    
    // Бургер-меню
    const burgerBtn = document.getElementById('burgerBtn');
    const mobileMenu = document.getElementById('mobileMenu');
    const closeBtn = document.getElementById('closeMobileMenu');

    if (burgerBtn && mobileMenu && closeBtn) {
        burgerBtn.addEventListener('click', () => mobileMenu.classList.remove('hidden'));
        closeBtn.addEventListener('click', () => mobileMenu.classList.add('hidden'));
    }

    // Кнопка "Показать ещё"
    const showMoreBtn = document.getElementById('showMoreBtn');
    if (showMoreBtn) {
        showMoreBtn.addEventListener('click', showMoreLots);
    }
}

function showUserMenu() {
    window.location.href = '/profile';
}

// ========================================
// ЛЕНТА-КАЛЕНДАРЬ (стиль Афиша)
// ========================================

let selectedDate = null;
let calScrollPos = 0;
const DAY_WIDTH = 52; // ширина одной ячейки в px
const SCROLL_STEP = 7; // дней за один клик стрелки

function generateCalendarRibbon() {
    const ribbon = document.getElementById('calendarRibbon');
    const monthLabel = document.getElementById('calendarMonthName');
    if (!ribbon) return;
    
    const today = new Date();
    const dayNamesShort = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб'];
    const monthNamesFull = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];
    const monthNamesVertical = ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн', 'Июл', 'Авг', 'Сен', 'Окт', 'Ноя', 'Дек'];
    
    // Собираем даты с аукционами
    const lotDates = new Set();
    lots.forEach(lot => {
        const parsed = parseLotDate(lot.date);
        if (parsed) lotDates.add(parsed.toDateString());
    });
    
    // Генерируем 90 дней
    let html = '';
    let prevMonth = -1;
    
    for (let i = 0; i < 90; i++) {
        const date = new Date(today);
        date.setDate(today.getDate() + i);
        
        // Вертикальный разделитель месяца (как на Афише)
        if (date.getMonth() !== prevMonth && i > 0) {
            html += `
                <div class="flex-shrink-0 flex items-center justify-center w-[1px] mx-2 relative">
                    <div class="absolute h-full w-[1px] bg-white/10"></div>
                    <span class="relative bg-[var(--dark-bg)] px-1 text-[9px] font-bold text-gray-500 uppercase tracking-widest" style="writing-mode:vertical-rl;transform:rotate(180deg)">${monthNamesVertical[date.getMonth()]}</span>
                </div>
            `;
        }
        prevMonth = date.getMonth();
        
        const isSelected = selectedDate && date.toDateString() === selectedDate.toDateString();
        const isToday = date.toDateString() === today.toDateString();
        const hasLots = lotDates.has(date.toDateString());
        const dayName = dayNamesShort[date.getDay()];
        const dayNum = String(date.getDate()).padStart(2, '0');
        const isWeekend = date.getDay() === 0 || date.getDay() === 6;
        
        let containerClass = `flex-shrink-0 w-[${DAY_WIDTH}px] py-3 rounded-2xl flex flex-col items-center gap-0.5 cursor-pointer transition-all duration-200 select-none `;
        let dayNameClass = 'text-[10px] font-bold uppercase leading-tight ';
        let dayNumClass = 'text-xl font-black leading-tight ';
        
        if (isSelected) {
            containerClass += 'bg-[var(--gold)] shadow-lg shadow-[var(--gold)]/20 scale-105';
            dayNameClass += 'text-black/70';
            dayNumClass += 'text-black';
        } else if (isToday) {
            containerClass += 'bg-white/10 border border-white/20';
            dayNameClass += 'text-[var(--gold)]';
            dayNumClass += 'text-white';
        } else {
            containerClass += 'hover:bg-white/5';
            dayNameClass += isWeekend ? 'text-red-400/80' : 'text-gray-500';
            dayNumClass += hasLots ? 'text-white' : 'text-gray-600';
        }
        
        html += `
            <button onclick="filterByDate(event, '${date.toISOString()}')" class="${containerClass}" style="min-width:${DAY_WIDTH}px">
                <span class="${dayNameClass}">${dayName}</span>
                <span class="${dayNumClass}">${dayNum}</span>
                ${hasLots && !isSelected ? '<span class="w-1.5 h-1.5 rounded-full bg-[var(--gold)] mt-0.5"></span>' : ''}
            </button>
        `;
    }
    
    ribbon.innerHTML = html;
    ribbon.style.transform = `translateX(-${calScrollPos}px)`;
    
    // Обновляем название месяца сверху
    if (monthLabel) {
        // Определяем какой месяц видим по текущей позиции скролла
        const visibleIndex = Math.floor(calScrollPos / DAY_WIDTH);
        const visibleDate = new Date(today);
        visibleDate.setDate(today.getDate() + visibleIndex);
        monthLabel.textContent = `${monthNamesFull[visibleDate.getMonth()]} ${visibleDate.getFullYear()}`;
    }
}

function parseLotDate(dateStr) {
    const months = {
        'января': 0, 'февраля': 1, 'марта': 2, 'апреля': 3,
        'мая': 4, 'июня': 5, 'июля': 6, 'августа': 7,
        'сентября': 8, 'октября': 9, 'ноября': 10, 'декабря': 11
    };
    const parts = dateStr.toLowerCase().trim().split(/\s+/);
    if (parts.length >= 3) {
        const day = parseInt(parts[0]);
        const month = months[parts[1]];
        const year = parseInt(parts[2]);
        if (!isNaN(day) && month !== undefined && !isNaN(year)) {
            return new Date(year, month, day);
        }
    }
    return null;
}

function filterByDate(event, isoString) {
    event.preventDefault();
    event.stopPropagation();
    
    const date = new Date(isoString);
    
    if (selectedDate && date.toDateString() === selectedDate.toDateString()) {
        selectedDate = null;
        document.getElementById('calendarSubtitle').textContent = 'Все предстоящие концерты';
    } else {
        selectedDate = date;
        const dayNames = ['воскресенье', 'понедельник', 'вторник', 'среда', 'четверг', 'пятница', 'суббота'];
        document.getElementById('calendarSubtitle').textContent = 
            `${date.getDate()} ${date.toLocaleDateString('ru-RU', {month: 'long'})} — ${dayNames[date.getDay()]}`;
    }
    
    displayLots();
}

function scrollCalendar(direction) {
    const ribbon = document.getElementById('calendarRibbon');
    if (!ribbon) return;
    
    const step = SCROLL_STEP * DAY_WIDTH;
    const maxScroll = (90 * DAY_WIDTH) - (ribbon.parentElement.offsetWidth || 800);
    
    if (direction === 'next') {
        calScrollPos = Math.min(calScrollPos + step, maxScroll);
    } else {
        calScrollPos = Math.max(calScrollPos - step, 0);
    }
    
    // Плавная анимация через CSS transition (уже задан в HTML)
    ribbon.style.transform = `translateX(-${calScrollPos}px)`;
    
    // Обновляем название месяца
    const monthLabel = document.getElementById('calendarMonthName');
    if (monthLabel) {
        const today = new Date();
        const monthNamesFull = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];
        const visibleIndex = Math.floor(calScrollPos / DAY_WIDTH);
        const visibleDate = new Date(today);
        visibleDate.setDate(today.getDate() + visibleIndex);
        monthLabel.textContent = `${monthNamesFull[visibleDate.getMonth()]} ${visibleDate.getFullYear()}`;
    }
}

// Стрелки навигации
document.addEventListener('DOMContentLoaded', () => {
    const prevBtn = document.getElementById('calPrev');
    const nextBtn = document.getElementById('calNext');

    if (prevBtn) prevBtn.addEventListener('click', () => scrollCalendar('prev'));
    if (nextBtn) nextBtn.addEventListener('click', () => scrollCalendar('next'));
});

// ========================================
// SCROLL-REVEAL (IntersectionObserver)
// ========================================

function initScrollReveal() {
    const elements = document.querySelectorAll('.reveal');
    if (!elements.length) return;

    // ── Настройки тайминга (крути эти два числа) ──
    // Насколько глубоко блок должен зайти в экран перед стартом анимации.
    // Больше = появляется позже = лучше видно само появление. Попробуй 150–300.
    const TRIGGER_OFFSET = 220;  // px от нижнего края экрана
    // Дополнительная пауза перед стартом анимации (буквально «подождать»).
    const REVEAL_DELAY = 120;    // мс

    // Fallback: нет поддержки IntersectionObserver — показать всё сразу
    if (!('IntersectionObserver' in window)) {
        elements.forEach(el => el.classList.add('active'));
        return;
    }

    const reveal = (el) => {
        setTimeout(() => el.classList.add('active'), REVEAL_DELAY);
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                reveal(entry.target);
                observer.unobserve(entry.target); // один раз, без скрытия при обратном скролле
            }
        });
    }, {
        threshold: 0,
        // Сдвигаем нижнюю границу срабатывания вверх: блок должен зайти глубже,
        // а не проявляться у самого края экрана
        rootMargin: `0px 0px -${TRIGGER_OFFSET}px 0px`
    });

    elements.forEach(el => {
        const rect = el.getBoundingClientRect();
        // Страховка: активируем сразу ТОЛЬКО если блок реально на первом экране
        // (зашёл выше зоны срабатывания). Остальные — ждут скролла с анимацией.
        if (rect.top < window.innerHeight - TRIGGER_OFFSET && rect.bottom > 0) {
            reveal(el);
        } else {
            observer.observe(el);
        }
    });
}

document.addEventListener('DOMContentLoaded', initScrollReveal);
