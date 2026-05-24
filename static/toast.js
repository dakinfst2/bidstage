// Универсальная toast-функция для всех страниц
window.showToast = function(message, type = 'error') {
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
    // message — пользовательская строка (часто текст ошибки от сервера),
    // экранируем чтобы не словить XSS из ответа API
    const safeMessage = (typeof window.escapeHtml === 'function')
        ? window.escapeHtml(message)
        : String(message ?? '').replace(/[&<>"']/g, ch =>
            ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[ch]));
    toast.innerHTML = `
        <iconify-icon icon="${icons[type] || icons.error}" class="text-xl flex-shrink-0"></iconify-icon>
        <span class="text-sm font-bold flex-1">${safeMessage}</span>
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
};
