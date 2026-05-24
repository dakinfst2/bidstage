// Автоматически вставляет баланс в шапку рядом с кнопкой пользователя
(async function() {
    // На странице профиля баланс не показываем (он там в карточке)
    if (window.location.pathname === '/profile') return;
    
    try {
        const r = await fetch('/api/wallet/balance');
        const data = await r.json();
        
        if (!data.authenticated) return;
        
        const balance = (data.balance || 0).toLocaleString();
        
        // Найти место в шапке для вставки
        const header = document.querySelector('header');
        if (!header) return;
        
        // Контейнер с правой стороны шапки — обычно последний div
        const rightSide = header.querySelector('.flex.items-center.gap-4.lg\\:gap-8') 
            || header.querySelector('.flex.items-center.gap-6')
            || header.querySelector('.flex.items-center.gap-4');
        
        if (!rightSide) return;
        
        // Если уже есть — обновляем
        let balanceEl = document.getElementById('headerBalance');
        if (balanceEl) {
            balanceEl.querySelector('.balance-amount').textContent = balance;
            return;
        }
        
        // Создаём элемент баланса
        balanceEl = document.createElement('a');
        balanceEl.id = 'headerBalance';
        balanceEl.href = '/wallet/topup';
        balanceEl.className = 'hidden md:flex items-center gap-2 px-4 py-2 rounded-full bg-[var(--gold)]/10 border border-[var(--gold)]/30 hover:bg-[var(--gold)]/20 transition-all group';
        balanceEl.title = 'Пополнить баланс';
        balanceEl.innerHTML = `
            <iconify-icon icon="lucide:wallet" class="text-[var(--gold)] text-lg"></iconify-icon>
            <span class="text-sm font-bold font-mono text-white"><span class="balance-amount">${balance}</span> <span class="text-[10px] text-gray-400">AMD</span></span>
            <iconify-icon icon="lucide:plus" class="text-[var(--gold)] opacity-0 group-hover:opacity-100 transition-opacity"></iconify-icon>
        `;
        
        // Вставить в начало правой части шапки
        rightSide.insertBefore(balanceEl, rightSide.firstChild);
    } catch (e) {
        console.error('Не удалось загрузить баланс:', e);
    }
})();
