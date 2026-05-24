// ========================================
// ОБЩИЕ ФУНКЦИИ ЗАЩИТЫ ОТ XSS
// ========================================
// Подключается во всех шаблонах ПЕРЕД любыми скриптами,
// использующими innerHTML с пользовательскими данными.

/**
 * Экранирует HTML-специальные символы. Применять к любым данным
 * (от пользователя, сервера, БД) перед вставкой в innerHTML или
 * в шаблонные литералы, которые потом идут в innerHTML.
 *
 * Пример:
 *   element.innerHTML = `<h3>${escapeHtml(lot.title)}</h3>`;
 */
window.escapeHtml = function(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
};

/**
 * Проверяет URL перед вставкой в src/href.
 * Разрешает только http(s) и data:image/.
 * Блокирует javascript:, vbscript:, file: и прочие опасные схемы,
 * через которые срабатывает XSS.
 *
 * Пример:
 *   element.src = safeUrl(lot.image_url);
 *   // или для шаблонной строки:
 *   innerHTML = `<img src="${escapeHtml(safeUrl(lot.image_url))}">`;
 */
window.safeUrl = function(u) {
    const s = String(u ?? '').trim();
    if (/^(https?:\/\/|data:image\/)/i.test(s)) return s;
    if (/^\/static\//.test(s)) return s;   // локальные картинки /static/img/lots/...
    return '';
};

// Путь к заглушке для битых/отсутствующих картинок лотов
window.LOT_PLACEHOLDER_IMG = '/static/img/lots/placeholder.jpg';

/**
 * Защита от open redirect для параметра ?next= и подобных.
 * Разрешает только относительные внутренние пути:
 *   /path, /winner/12, /profile?x=1
 * Блокирует http://evil, //evil, /\evil, javascript:, переводы строк и т.д.
 * Возвращает безопасную строку или '' если значение не подходит.
 */
window.safeNextUrl = function(v) {
    const s = String(v ?? '').trim();
    if (!s || s.length > 512) return '';
    if (/[\r\n]/.test(s)) return '';
    if (!s.startsWith('/')) return '';
    if (s.startsWith('//') || s.startsWith('/\\')) return '';
    const rest = s.slice(1);
    const slash = rest.indexOf('/');
    const head = slash === -1 ? rest : rest.slice(0, slash);
    if (head.includes(':')) return '';
    return s;
};
