from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse
import os
import re
import secrets as secrets_module
import logging


# ========================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ========================================

def utcnow():
    """Возвращает timezone-aware UTC datetime.
    Заменяет datetime.utcnow() (deprecated в Python 3.12).
    """
    return datetime.now(timezone.utc)


# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('bidstage.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('bidstage')

app = Flask(__name__)

# SECRET_KEY: в проде ОБЯЗАТЕЛЬНО задать через переменную окружения.
# Без этого сессии будут разными у каждого gunicorn-воркера, и пользователей
# будет случайно разлогинивать.
_secret_key = os.environ.get('SECRET_KEY')
_is_production = bool(os.environ.get('DATABASE_URL'))  # на Railway всегда задан
if not _secret_key:
    if _is_production:
        raise RuntimeError(
            'SECRET_KEY обязателен в production. Задайте его в переменных окружения. '
            'Сгенерировать: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    # В dev — фиксированное значение, чтобы сессии не слетали при перезапуске
    _secret_key = 'dev-only-not-secure-do-not-use-in-production'
    logger.warning('SECRET_KEY не задан — использую dev-ключ. Не используйте в проде!')
app.config['SECRET_KEY'] = _secret_key

# Поддержка PostgreSQL (Railway даёт postgres://, SQLAlchemy требует postgresql://)
_db_url = os.environ.get('DATABASE_URL', 'sqlite:///bidstage.db')
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = _is_production  # HTTPS на проде
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# Railway/прокси: правильный URL за reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


# ========================================
# Cache-Control: запрещаем кэширование персональных данных
# ========================================

@app.after_request
def add_cache_headers(response):
    """Запрещает кэширование API и страниц с персональными данными"""
    path = request.path
    if path.startswith('/api/') or path in ('/profile', '/my-tickets') or path.startswith('/winner/') or path.startswith('/ticket/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

db = SQLAlchemy(app)


# ========================================
# SECURITY: Rate Limiting
# ========================================

rate_limit_store = {}  # {key: [timestamps]}
rate_limit_blocks = {}  # {key: block_until_ts}

def rate_limit(max_requests=10, window_seconds=60, block_seconds=None):
    """Простой rate limiter без внешних зависимостей.

    Если block_seconds задан — при превышении лимита ключ блокируется на
    block_seconds (жёсткий cooldown), и в ответе ставится Retry-After.
    Без block_seconds работает как sliding window: запросы пропускаются
    по мере того, как старые выпадают из окна window_seconds.
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            endpoint = request.endpoint
            now = datetime.utcnow().timestamp()

            key = f"{ip}:{endpoint}"

            block_until = rate_limit_blocks.get(key, 0)
            if block_until > now:
                retry_after = int(block_until - now) + 1
                resp = jsonify({'error': f'Слишком много запросов. Попробуйте через {retry_after} сек.'})
                resp.status_code = 429
                resp.headers['Retry-After'] = str(retry_after)
                return resp

            if key not in rate_limit_store:
                rate_limit_store[key] = []
            rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window_seconds]

            if len(rate_limit_store[key]) >= max_requests:
                if block_seconds:
                    rate_limit_blocks[key] = now + block_seconds
                    retry_after = block_seconds
                else:
                    retry_after = max(1, int(window_seconds - (now - rate_limit_store[key][0])))
                resp = jsonify({'error': f'Слишком много запросов. Попробуйте через {retry_after} сек.'})
                resp.status_code = 429
                resp.headers['Retry-After'] = str(retry_after)
                return resp

            rate_limit_store[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ========================================
# SECURITY: CSRF Protection
# ========================================

ALLOWED_HOSTS = {
    'concertauction.online',
    'www.concertauction.online',
    '127.0.0.1',
    'localhost',
    '127.0.0.1:5000',
    'localhost:5000',
}


def _host_from_url(url):
    """Извлекает netloc (host:port) из URL. Возвращает '' если не парсится."""
    if not url:
        return ''
    try:
        parsed = urlparse(url)
        return (parsed.netloc or '').lower()
    except Exception:
        return ''


def _host_allowed(host):
    """Точная проверка хоста (не substring!) с поддержкой *.railway.app."""
    if not host:
        return False
    host = host.lower()
    if host in ALLOWED_HOSTS:
        return True
    # Поддомены Railway: разрешаем X.railway.app и X.up.railway.app точно
    if host.endswith('.railway.app') or host.endswith('.up.railway.app'):
        return True
    return False


def _safe_next_url(value):
    """Защита от open redirect.

    Разрешает только внутренние относительные пути:
    - начинаются с одного '/'
    - не '//host' (protocol-relative) и не '/\\host'
    - не содержат схемы вида 'javascript:', 'http:' и пр.
    - не содержат CR/LF (header-injection)

    Возвращает безопасную строку или '' если значение не подходит.
    """
    if not value or not isinstance(value, str):
        return ''
    v = value.strip()
    if len(v) == 0 or len(v) > 512:
        return ''
    if '\r' in v or '\n' in v:
        return ''
    if not v.startswith('/'):
        return ''
    if v.startswith('//') or v.startswith('/\\'):
        return ''
    # Защита от 'javascript:', 'data:' и пр. — двоеточие до первого '/' после ведущего '/'
    rest = v[1:]
    first_slash = rest.find('/')
    head = rest if first_slash == -1 else rest[:first_slash]
    if ':' in head:
        return ''
    return v


@app.before_request
def csrf_protect():
    """CSRF-проверка для всех state-changing запросов.

    Изменения от старой версии:
    - Срабатывает для ЛЮБОГО content-type, не только application/json
      (раньше form-encoded POST проходил мимо проверки).
    - Использует urlparse + точное сравнение netloc вместо substring 'in url'
      (раньше домен evilconcertauction.online проходил как валидный).
    - Если оба заголовка Origin и Referer отсутствуют — отклоняет
      (раньше пропускал).
    """
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return None

    # OAuth-колбэки не делают state-change на нашей стороне (только GET'ом),
    # а сами по себе не страдают от CSRF, поскольку код в URL одноразовый.
    # Но всё равно поставим белый список путей где CSRF не нужен:
    if request.path in ('/auth/instagram/callback', '/auth/facebook/callback'):
        return None

    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '')

    origin_host = _host_from_url(origin) if origin else ''
    referer_host = _host_from_url(referer) if referer else ''

    # Хотя бы один из источников должен быть разрешён.
    # Если оба пустые — отклоняем (старый код пропускал).
    if not origin_host and not referer_host:
        logger.warning(
            f'CSRF: запрос без Origin и Referer на {request.path} '
            f'от ip={request.remote_addr}'
        )
        return jsonify({'error': 'CSRF: запрос без заголовков Origin/Referer'}), 403

    if origin_host and not _host_allowed(origin_host):
        logger.warning(f'CSRF: недопустимый Origin={origin_host}')
        return jsonify({'error': 'CSRF: недопустимый Origin'}), 403

    if referer_host and not _host_allowed(referer_host):
        logger.warning(f'CSRF: недопустимый Referer={referer_host}')
        return jsonify({'error': 'CSRF: недопустимый Referer'}), 403

    return None


# ========================================
# SECURITY: Input Validation
# ========================================

def validate_email(email):
    """Проверка формата email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password(password):
    """Проверка силы пароля: минимум 6 символов"""
    if len(password) < 6:
        return False, 'Пароль должен содержать минимум 6 символов'
    return True, ''


def validate_username(username):
    """Проверка формата имени пользователя"""
    if len(username) < 3 or len(username) > 30:
        return False, 'Имя пользователя: 3-30 символов'
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, 'Имя пользователя: только буквы, цифры, _, ., -'
    return True, ''


def sanitize_text(text):
    """Экранирование HTML-тегов в пользовательском вводе.

    ВНИМАНИЕ: антипаттерн. Лучше хранить сырые данные и экранировать
    при выводе (через Jinja autoescape и escapeHtml в JS).
    Оставлено для обратной совместимости с уже созданными лотами.
    """
    if not text:
        return text
    return text.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')


# ========================================
# ДЕКОРАТОРЫ АВТОРИЗАЦИИ
# ========================================

def login_required(f):
    """Требует, чтобы пользователь был залогинен.
    Для /api/* возвращает 401 JSON, для остальных — редирект на /login.
    Залогиненного пользователя кладёт в g.user, чтобы не запрашивать БД повторно.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Необходима авторизация'}), 401
            return redirect(url_for('login_page'))
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Пользователь не найден'}), 401
            return redirect(url_for('login_page'))
        g.user = user
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """Требует, чтобы пользователь был залогинен И был админом."""
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.user.is_admin:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Нужны права администратора'}), 403
            abort(404)  # не выдаём существование админской страницы
        return f(*args, **kwargs)
    return wrapper


# ========================================
# МОДЕЛИ БАЗЫ ДАННЫХ
# ========================================

class User(db.Model):
    """Модель пользователя"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Integer, default=0)  # Баланс в AMD
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    bids = db.relationship('Bid', backref='user', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'balance': self.balance or 0,
            'created_at': self.created_at.isoformat()
        }


class Transaction(db.Model):
    """История транзакций по балансу"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    type = db.Column(db.String(30), nullable=False)  # deposit, withdraw, bid_freeze, bid_unfreeze, payment, refund, commission
    amount = db.Column(db.Integer, nullable=False)  # положительное = поступление, отрицательное = списание
    status = db.Column(db.String(20), default='success')  # success, pending, error, frozen
    description = db.Column(db.String(300))
    payment_method = db.Column(db.String(30))  # visa, applepay, googlepay, idbank, ameria
    related_lot_id = db.Column(db.Integer, db.ForeignKey('lot.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('ix_tx_user_created', 'user_id', 'created_at'),
    )

    user = db.relationship('User', backref='transactions')
    lot = db.relationship('Lot', backref='transactions')
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'amount': self.amount,
            'status': self.status,
            'description': self.description,
            'payment_method': self.payment_method,
            'related_lot_id': self.related_lot_id,
            'lot_title': self.lot.title if self.lot else None,
            'created_at': self.created_at.isoformat()
        }


class Lot(db.Model):
    """Модель лота (концерта)"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=False)
    venue = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    start_price = db.Column(db.Integer, nullable=False)
    current_price = db.Column(db.Integer, nullable=False)
    bid_step = db.Column(db.Integer, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False, index=True)
    is_featured = db.Column(db.Boolean, default=False)
    tags = db.Column(db.String(200))  # Хранится как строка через запятую
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Поля для retry-логики (fallback победителя): запоминаем исходную цену,
    # считаем сколько раз лот уже возвращался в продажу, и в каком раунде сейчас.
    original_start_price = db.Column(db.Integer, nullable=True)
    retry_count = db.Column(db.Integer, default=0, nullable=False)
    current_round = db.Column(db.Integer, default=1, nullable=False)
    # status — жизненный цикл лота:
    #   'active'    — идёт аукцион ИЛИ ждём оплаты победителя/runner-up'a
    #   'finalized' — лот окончательно закрыт (купили либо retry_count исчерпан)
    # На ставки влияет: place_bid принимает ставки только при status='active'.
    status = db.Column(db.String(20), default='active', nullable=False, index=True)

    # Связи
    bids = db.relationship('Bid', backref='lot', lazy=True, order_by='Bid.created_at.desc()')
    favorites = db.relationship('Favorite', backref='lot', lazy=True)

    def to_dict(self):
        """Сериализация лота. Использует SQL-агрегаты для participants/total_bids
        вместо загрузки всех ставок в память (защита от N+1).

        participants/total_bids считаются ТОЛЬКО для ставок текущего раунда —
        ставки прошлых раундов в БД остаются (история), но в UI не светятся.
        """
        # Один SELECT с COUNT и COUNT DISTINCT по ставкам текущего раунда
        row = db.session.execute(
            db.select(
                db.func.count(Bid.id).label('total_bids'),
                db.func.count(db.distinct(Bid.user_id)).label('participants')
            )
            .where(Bid.lot_id == self.id)
            .where(Bid.round == self.current_round)
        ).one()

        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'image_url': self.image_url,
            'venue': self.venue,
            'date': self.date,
            'start_price': self.start_price,
            'current_price': self.current_price,
            'bid_step': self.bid_step,
            'end_time': self.end_time.isoformat(),
            'is_featured': self.is_featured,
            'tags': self.tags.split(',') if self.tags else [],
            'participants': row.participants or 0,
            'total_bids': row.total_bids or 0,
            # Раунд и retry_count показываем — пригодится для UI-бейджа
            # «повторный аукцион» в коммите #4.
            'current_round': self.current_round,
            'retry_count': self.retry_count,
            'status': self.status,
        }


class Bid(db.Model):
    """Модель ставки"""
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('lot.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Номер раунда лота, в котором сделана ставка. Нужен чтобы при возврате
    # лота в продажу не путать старые ставки с новыми.
    round = db.Column(db.Integer, default=1, nullable=False)

    __table_args__ = (
        # Для запроса 'кто лидер' и 'история ставок по лоту, сортировка по amount'
        db.Index('ix_bid_lot_amount', 'lot_id', 'amount'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'user_id': self.user_id,
            'username': self.user.username,
            'lot_id': self.lot_id,
            'created_at': self.created_at.isoformat()
        }


class Favorite(db.Model):
    """Модель избранного"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('lot.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Уникальная комбинация пользователь-лот
    __table_args__ = (db.UniqueConstraint('user_id', 'lot_id', name='_user_lot_uc'),)


class Order(db.Model):
    """Модель заказа победителя аукциона"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('lot.id'), nullable=False, index=True)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, expired, cancelled
    payment_deadline = db.Column(db.DateTime, nullable=False)
    paid_at = db.Column(db.DateTime, nullable=True)
    order_code = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # runner_up_user_id — кто был второй на момент создания Order'a (для fallback'a,
    # если первый победитель не выкупит за payment_deadline).
    # runner_up_amount — сумма ПОСЛЕДНЕЙ ставки runner_up'a на момент finalize.
    # Если первый победитель просрочит оплату, runner_up получит лот за свою
    # собственную сумму (логика реальных аукционов eBay/Sotheby's),
    # а не за сумму победителя.
    # attempt — 1: первый победитель, 2: runner-up, получивший шанс после expired.
    runner_up_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    runner_up_amount = db.Column(db.Integer, nullable=True)
    attempt = db.Column(db.Integer, default=1, nullable=False)

    __table_args__ = (
        db.Index('ix_order_user_status', 'user_id', 'status'),
    )

    # foreign_keys обязателен: на user.id ссылаются и user_id, и runner_up_user_id,
    # без явного указания SQLAlchemy не может вывести путь для backref.
    user = db.relationship('User', backref='orders', foreign_keys=[user_id])
    lot = db.relationship('Lot', backref='orders')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username,
            'lot_id': self.lot_id,
            'lot': self.lot.to_dict(),
            'amount': self.amount,
            'status': self.status,
            'payment_deadline': self.payment_deadline.isoformat(),
            'paid_at': self.paid_at.isoformat() if self.paid_at else None,
            'order_code': self.order_code,
            'created_at': self.created_at.isoformat(),
            # attempt нужен фронту: 1 — заказ для победителя, 2 — для runner-up'a
            # (показываем баннер «Победитель не оплатил, билет ваш»).
            'attempt': self.attempt,
        }


class ShareCheck(db.Model):
    """Модель проверки расшаривания лота"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('lot.id'), nullable=False, index=True)
    platform = db.Column(db.String(20), nullable=False)  # instagram, facebook
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'lot_id', name='_share_user_lot_uc'),)


# ========================================
# МАРШРУТЫ
# ========================================

@app.route('/')
def index():
    """Главная страница"""
    stats = {
        'active_lots': Lot.query.filter(
            Lot.status == 'active',
            Lot.end_time > datetime.utcnow()
        ).count(),
        'total_bids': Bid.query.count(),
        'total_users': User.query.count(),
    }
    return render_template('index.html', stats=stats)


@app.route('/lot/<int:lot_id>')
def lot_detail(lot_id):
    """Страница детального просмотра лота"""
    lot = Lot.query.get_or_404(lot_id)
    return render_template('lot.html', lot=lot)


@app.route('/lot/<int:lot_id>/history')
def lot_history(lot_id):
    """Страница полной истории ставок"""
    lot = Lot.query.get_or_404(lot_id)
    return render_template('bid_history.html', lot=lot)


@app.route('/winner/<int:order_id>')
def winner_page(order_id):
    """Страница победителя аукциона"""
    order = Order.query.get_or_404(order_id)
    return render_template('winner.html', order=order)


@app.route('/ticket/<int:order_id>')
def ticket_page(order_id):
    """Страница электронного билета"""
    order = Order.query.get_or_404(order_id)
    if order.status != 'paid':
        return redirect(url_for('winner_page', order_id=order_id))
    return render_template('ticket.html', order=order)


@app.route('/my-tickets')
@login_required
def my_tickets_page():
    """Страница «Мои билеты»"""
    return render_template('my_tickets.html')


@app.route('/profile')
@login_required
def profile_page():
    """Страница профиля пользователя"""
    return render_template('profile.html')


@app.route('/admin/lot/new')
@admin_required
def admin_create_lot_page():
    """Создание лота — только для админов"""
    return render_template('admin_create_lot.html')


@app.route('/wallet/topup')
@login_required
def wallet_topup_page():
    """Страница пополнения баланса"""
    return render_template('wallet_topup.html')


@app.route('/wallet/payment-method')
@login_required
def wallet_payment_method_page():
    """Выбор способа оплаты"""
    return render_template('wallet_payment_method.html')


@app.route('/wallet/confirm')
@login_required
def wallet_confirm_page():
    """Подтверждение платежа"""
    return render_template('wallet_confirm.html')


@app.route('/wallet/success')
@login_required
def wallet_success_page():
    """Успешная оплата"""
    return render_template('wallet_success.html')


@app.route('/wallet/transactions')
@login_required
def wallet_transactions_page():
    """История транзакций"""
    return render_template('wallet_transactions.html')


@app.route('/insufficient-funds')
@login_required
def insufficient_funds_page():
    """Страница недостатка средств"""
    return render_template('insufficient_funds.html')


@app.route('/api/wallet/topup', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
@login_required
def api_wallet_topup():
    """Пополнение баланса"""
    data = request.get_json() or {}
    amount = data.get('amount', 0)
    method = data.get('method', 'visa')
    next_url = _safe_next_url(data.get('next'))

    try:
        amount = int(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Некорректная сумма'}), 400
    
    if amount <= 0 or amount > 10000000:
        return jsonify({'error': 'Сумма должна быть от 1 до 10,000,000 AMD'}), 400
    
    if method not in ('visa', 'applepay', 'googlepay', 'idbank', 'ameria'):
        return jsonify({'error': 'Неизвестный метод оплаты'}), 400
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    # Симуляция оплаты — успех
    user.balance = (user.balance or 0) + amount
    
    method_names = {
        'visa': 'Visa/MasterCard',
        'applepay': 'Apple Pay',
        'googlepay': 'Google Pay',
        'idbank': 'ID Bank',
        'ameria': 'Ameriabank'
    }
    
    tx = Transaction(
        user_id=user.id,
        type='deposit',
        amount=amount,
        status='success',
        description=f'Пополнение через {method_names[method]}',
        payment_method=method
    )
    db.session.add(tx)
    db.session.commit()
    
    logger.info(f'Пополнение: user={user.username} amount={amount} method={method}')
    
    return jsonify({
        'message': 'Баланс пополнен',
        'balance': user.balance,
        'transaction': tx.to_dict(),
        'next_url': next_url
    })


@app.route('/api/wallet/transactions')
@login_required
def api_wallet_transactions():
    """История транзакций пользователя"""
    txs = Transaction.query.filter_by(user_id=session['user_id']).order_by(Transaction.created_at.desc()).limit(100).all()
    return jsonify([t.to_dict() for t in txs])


@app.route('/api/wallet/balance')
def api_wallet_balance():
    """Текущий баланс пользователя"""
    if 'user_id' not in session:
        return jsonify({'balance': 0, 'authenticated': False})
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'balance': 0, 'authenticated': False})
    
    return jsonify({'balance': user.balance or 0, 'authenticated': True})


@app.route('/faq')
def faq_page():
    """FAQ"""
    return render_template('faq.html')


@app.route('/terms')
def terms_page():
    """Условия использования"""
    return render_template('legal.html', title='Условия использования', content='terms')


@app.route('/privacy')
def privacy_page():
    """Политика конфиденциальности"""
    return render_template('legal.html', title='Политика конфиденциальности', content='privacy')


@app.route('/rules')
def rules_page():
    """Правила аукциона"""
    return render_template('legal.html', title='Правила аукциона', content='rules')


@app.route('/guarantee')
def guarantee_page():
    """Гарантия билета"""
    return render_template('legal.html', title='Гарантия билета', content='guarantee')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/register')
def register_page():
    """Страница регистрации"""
    return render_template('register.html')


@app.route('/login')
def login_page():
    """Страница входа"""
    return render_template('login.html')


@app.route('/api/lots')
def get_lots():
    """Получить все активные лоты"""
    lots = Lot.query.filter(Lot.end_time > datetime.utcnow()).all()
    return jsonify([lot.to_dict() for lot in lots])


@app.route('/api/lots/<int:lot_id>')
def get_lot(lot_id):
    """Получить конкретный лот"""
    lot = Lot.query.get_or_404(lot_id)
    return jsonify(lot.to_dict())


@app.route('/api/lots/<int:lot_id>/bids')
def get_lot_bids(lot_id):
    """Получить историю ставок для лота — только текущий раунд.
    Ставки прошлых раундов в БД остаются (история), но в UI не светятся.
    """
    lot = Lot.query.get_or_404(lot_id)
    bids = (
        Bid.query
           .filter_by(lot_id=lot.id, round=lot.current_round)
           .order_by(Bid.created_at.desc())
           .all()
    )
    return jsonify([bid.to_dict() for bid in bids])


@app.route('/api/register', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)
def register():
    """Регистрация нового пользователя"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Все поля обязательны'}), 400
    
    # Валидация username
    valid, msg = validate_username(data['username'])
    if not valid:
        return jsonify({'error': msg}), 400
    
    # Валидация email
    if not validate_email(data['email']):
        return jsonify({'error': 'Некорректный формат email'}), 400
    
    # Валидация пароля
    valid, msg = validate_password(data['password'])
    if not valid:
        return jsonify({'error': msg}), 400
    
    # Проверка существования пользователя
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Пользователь с таким именем уже существует'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email уже зарегистрирован'}), 400
    
    # Создание пользователя (sanitize username)
    user = User(username=sanitize_text(data['username']), email=data['email'].lower().strip())
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    # Защита от session fixation: чистим старую сессию перед записью user_id
    session.clear()
    session.permanent = True
    session['user_id'] = user.id
    logger.info(f'Новый пользователь зарегистрирован: {user.username} (id={user.id})')
    
    return jsonify({
        'message': 'Регистрация успешна',
        'user': user.to_dict()
    }), 201


@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60, block_seconds=300)
def login():
    """Вход пользователя"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Введите имя пользователя и пароль'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        logger.warning(f'Неудачная попытка входа: username={data["username"]} ip={request.remote_addr}')
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401
    
    # Защита от session fixation: чистим старую сессию перед записью user_id
    session.clear()
    session.permanent = True
    session['user_id'] = user.id
    logger.info(f'Вход: user={user.username} (id={user.id})')
    
    return jsonify({
        'message': 'Вход выполнен успешно',
        'user': user.to_dict()
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    """Выход пользователя"""
    session.clear()
    return jsonify({'message': 'Выход выполнен успешно'})


@app.route('/api/me')
@login_required
def get_current_user():
    """Получить текущего пользователя"""
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    return jsonify(user.to_dict())


@app.route('/api/lots/<int:lot_id>/bid', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)
@login_required
def place_bid(lot_id):
    """Сделать ставку.

    Защита от race condition: используем атомарный UPDATE с условием в WHERE.
    Если две одновременные ставки попытаются обновить current_price,
    только одна с действительно более высокой ставкой пройдёт.
    """
    data = request.get_json() or {}
    amount = data.get('amount')

    if not isinstance(amount, (int, float)) or amount is True or amount is False:
        return jsonify({'error': 'Укажите корректную сумму ставки'}), 400

    amount = int(amount)
    if amount <= 0 or amount > 100_000_000:
        return jsonify({'error': 'Сумма ставки должна быть от 1 до 100,000,000 AMD'}), 400

    lot = Lot.query.get_or_404(lot_id)

    if lot.end_time < datetime.utcnow():
        return jsonify({'error': 'Аукцион завершен'}), 400

    # Лот окончательно закрыт (купили либо лимит возвратов исчерпан).
    # Дополнительная страховка к проверке end_time выше.
    if lot.status != 'active':
        return jsonify({'error': 'Аукцион завершен'}), 400

    # Дисквалификация: если у юзера уже есть expired Order на этот лот
    # (= он выиграл предыдущий раунд этого же лота и не выкупил вовремя),
    # дальнейшие ставки по этому лоту запрещены.
    disqualified = Order.query.filter_by(
        user_id=g.user.id, lot_id=lot_id, status='expired'
    ).first()
    if disqualified:
        return jsonify({
            'error': 'Вы не выкупили этот лот в прошлом раунде, дальнейшие ставки заблокированы',
            'blocked': True
        }), 403

    # По ТЗ: ставка принимается только если пользователь поделился лотом
    # и публикация подтверждена (verified=True).
    share = ShareCheck.query.filter_by(user_id=g.user.id, lot_id=lot_id).first()
    if not share or not share.verified:
        return jsonify({
            'error': 'Перед ставкой нужно поделиться лотом',
            'need_share': True
        }), 403

    # Анти-shill: тот же пользователь не может ставить два раза подряд,
    # перебивая сам себя. Сверяемся ТОЛЬКО с ставками текущего раунда —
    # старые ставки прошлых раундов не считаются.
    last_bid = (
        Bid.query
           .filter_by(lot_id=lot_id, round=lot.current_round)
           .order_by(Bid.amount.desc())
           .first()
    )
    if last_bid and last_bid.user_id == g.user.id:
        return jsonify({'error': 'Вы уже лидер. Дождитесь чужой ставки.'}), 400

    # АТОМАРНЫЙ UPDATE: обновляем current_price только если новая ставка
    # действительно >= current_price + bid_step. Если кто-то опередил —
    # rowcount будет 0 и мы вернём 409.
    result = db.session.execute(
        db.update(Lot)
          .where(Lot.id == lot_id)
          .where(Lot.current_price + Lot.bid_step <= amount)
          .where(Lot.end_time > datetime.utcnow())
          .values(current_price=amount)
    )

    if result.rowcount == 0:
        db.session.rollback()
        # Перечитываем актуальную цену и возвращаем требуемый минимум
        db.session.expire(lot)
        lot = Lot.query.get(lot_id)
        return jsonify({
            'error': f'Ставка не принята. Минимум: {lot.current_price + lot.bid_step} AMD'
        }), 409

    # UPDATE прошёл — создаём запись о ставке. round фиксируем по текущему
    # раунду лота, чтобы при возврате лота в продажу старые ставки не путались
    # с новыми.
    bid = Bid(amount=amount, user_id=g.user.id, lot_id=lot_id, round=lot.current_round)
    db.session.add(bid)
    db.session.commit()

    logger.info(f'Ставка: user={g.user.id} lot={lot_id} amount={amount}')

    # Перечитываем лот чтобы вернуть актуальное состояние
    db.session.expire(lot)
    lot = Lot.query.get(lot_id)

    return jsonify({
        'message': 'Ставка принята',
        'bid': bid.to_dict(),
        'lot': lot.to_dict()
    }), 201


@app.route('/api/lots/<int:lot_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(lot_id):
    """Добавить/удалить из избранного"""
    lot = Lot.query.get_or_404(lot_id)
    user_id = session['user_id']
    
    favorite = Favorite.query.filter_by(user_id=user_id, lot_id=lot_id).first()
    
    if favorite:
        # Удалить из избранного
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({'message': 'Удалено из избранного', 'is_favorite': False})
    else:
        # Добавить в избранное
        favorite = Favorite(user_id=user_id, lot_id=lot_id)
        db.session.add(favorite)
        db.session.commit()
        return jsonify({'message': 'Добавлено в избранное', 'is_favorite': True})


@app.route('/api/lots/<int:lot_id>/share', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
@login_required
def share_lot(lot_id):
    """Зафиксировать факт расшаривания и начать верификацию"""
    data = request.get_json() or {}
    platform = data.get('platform', 'instagram')
    profile_url = data.get('profile_url', '')
    user_id = session['user_id']
    
    Lot.query.get_or_404(lot_id)
    
    share = ShareCheck.query.filter_by(user_id=user_id, lot_id=lot_id).first()
    if not share:
        share = ShareCheck(user_id=user_id, lot_id=lot_id, platform=platform, verified=False)
        db.session.add(share)
    else:
        share.platform = platform
    
    db.session.commit()
    return jsonify({'message': 'Публикация зарегистрирована', 'share_id': share.id})


@app.route('/api/lots/<int:lot_id>/share/verify', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60)
@login_required
def verify_share(lot_id):
    """Верификация публикации через Instagram/Facebook Graph API.

    Поведение:
    - С реальным access_token — проверяет посты через Graph API.
    - Без токена — отказ. Раньше тут была авто-верификация ('демо-режим'),
      которая обходилась одной кнопкой и делала всю механику бесполезной.
    - Если действительно нужно для демо: установите переменную окружения
      SHARE_DEMO_MODE=1 — тогда без токена будет автоматическое подтверждение.
      По умолчанию выключено.

    Этот эндпоинт обязателен: place_bid требует, чтобы у пользователя был
    ShareCheck с verified=True для соответствующего лота.
    """
    user_id = g.user.id
    data = request.get_json() or {}
    access_token = data.get('access_token')

    share = ShareCheck.query.filter_by(user_id=user_id, lot_id=lot_id).first()
    if not share:
        return jsonify({'error': 'Публикация не найдена'}), 404

    # Реальная проверка через Graph API, если передан токен
    if access_token:
        import requests as http_requests
        lot = Lot.query.get(lot_id)
        verified = False

        try:
            if share.platform == 'instagram':
                resp = http_requests.get(
                    'https://graph.instagram.com/me/media',
                    params={
                        'fields': 'caption,timestamp,permalink',
                        'access_token': access_token,
                        'limit': 5
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    posts = resp.json().get('data', [])
                    for post in posts:
                        caption = (post.get('caption') or '').lower()
                        permalink = (post.get('permalink') or '').lower()
                        # Требуем ссылку на лот, а не подстроку #bidstage
                        if f'/lot/{lot_id}' in permalink or f'/lot/{lot_id}' in caption:
                            verified = True
                            break

            elif share.platform == 'facebook':
                resp = http_requests.get(
                    'https://graph.facebook.com/me/feed',
                    params={
                        'fields': 'message,link,created_time',
                        'access_token': access_token,
                        'limit': 5
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    posts = resp.json().get('data', [])
                    for post in posts:
                        message = (post.get('message') or '').lower()
                        link = (post.get('link') or '').lower()
                        if f'/lot/{lot_id}' in link or f'/lot/{lot_id}' in message:
                            verified = True
                            break
        except Exception:
            logger.exception('Ошибка верификации шаринга через Graph API')

        if not verified:
            return jsonify({
                'error': 'Публикация не найдена. Опубликуйте пост со ссылкой на лот.',
                'verified': False
            }), 400

        share.verified = True
        db.session.commit()
        return jsonify({'message': 'Публикация подтверждена', 'verified': True})

    # Без токена — только если явно включён демо-режим
    if os.environ.get('SHARE_DEMO_MODE') == '1':
        share.verified = True
        db.session.commit()
        logger.info(f'Шаринг подтверждён в демо-режиме: user={user_id} lot={lot_id}')
        return jsonify({'message': 'Публикация подтверждена (демо-режим)', 'verified': True})

    return jsonify({
        'error': 'Требуется access_token от Instagram/Facebook для верификации',
        'verified': False
    }), 400


@app.route('/api/lots/<int:lot_id>/share/status')
def share_status(lot_id):
    """Получить статус расшаривания текущего пользователя"""
    if 'user_id' not in session:
        return jsonify({'shared': False, 'verified': False})
    
    user_id = session['user_id']
    share = ShareCheck.query.filter_by(user_id=user_id, lot_id=lot_id).first()
    
    if not share:
        return jsonify({'shared': False, 'verified': False})
    
    return jsonify({
        'shared': True,
        'verified': share.verified,
        'platform': share.platform
    })


@app.route('/auth/instagram')
def auth_instagram():
    """Начало OAuth flow для Instagram.
    В продакшене: redirect на https://api.instagram.com/oauth/authorize
    с client_id, redirect_uri, scope=user_media
    """
    client_id = os.environ.get('INSTAGRAM_CLIENT_ID', '')
    redirect_uri = request.host_url + 'auth/instagram/callback'
    
    if not client_id:
        return jsonify({'error': 'Instagram API не настроен. Установите INSTAGRAM_CLIENT_ID в переменных окружения.'}), 501
    
    auth_url = (
        f'https://api.instagram.com/oauth/authorize'
        f'?client_id={client_id}'
        f'&redirect_uri={redirect_uri}'
        f'&scope=user_profile,user_media'
        f'&response_type=code'
    )
    return redirect(auth_url)


@app.route('/auth/instagram/callback')
def auth_instagram_callback():
    """Callback после авторизации Instagram. Обменивает code на access_token."""
    code = request.args.get('code')
    if not code:
        return redirect('/')
    
    client_id = os.environ.get('INSTAGRAM_CLIENT_ID', '')
    client_secret = os.environ.get('INSTAGRAM_CLIENT_SECRET', '')
    redirect_uri = request.host_url + 'auth/instagram/callback'
    
    import requests as http_requests
    try:
        resp = http_requests.post('https://api.instagram.com/oauth/access_token', data={
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code': code
        }, timeout=10)
        
        if resp.status_code == 200:
            token_data = resp.json()
            session['instagram_token'] = token_data.get('access_token')
            return redirect('/')
    except Exception:
        pass
    
    return redirect('/')


@app.route('/auth/facebook')
def auth_facebook():
    """Начало OAuth flow для Facebook."""
    client_id = os.environ.get('FACEBOOK_APP_ID', '')
    redirect_uri = request.host_url + 'auth/facebook/callback'
    
    if not client_id:
        return jsonify({'error': 'Facebook API не настроен. Установите FACEBOOK_APP_ID в переменных окружения.'}), 501
    
    auth_url = (
        f'https://www.facebook.com/v18.0/dialog/oauth'
        f'?client_id={client_id}'
        f'&redirect_uri={redirect_uri}'
        f'&scope=public_profile,user_posts'
        f'&response_type=code'
    )
    return redirect(auth_url)


@app.route('/auth/facebook/callback')
def auth_facebook_callback():
    """Callback после авторизации Facebook."""
    code = request.args.get('code')
    if not code:
        return redirect('/')
    
    client_id = os.environ.get('FACEBOOK_APP_ID', '')
    client_secret = os.environ.get('FACEBOOK_APP_SECRET', '')
    redirect_uri = request.host_url + 'auth/facebook/callback'
    
    import requests as http_requests
    try:
        resp = http_requests.get('https://graph.facebook.com/v18.0/oauth/access_token', params={
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'code': code
        }, timeout=10)
        
        if resp.status_code == 200:
            token_data = resp.json()
            session['facebook_token'] = token_data.get('access_token')
            return redirect('/')
    except Exception:
        pass
    
    return redirect('/')


@app.route('/api/lots/<int:lot_id>/finalize', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=60)
@login_required
def finalize_lot(lot_id):
    """Завершить аукцион и создать заказ для победителя.
    Срок оплаты — 24 часа с момента создания заказа (момент победы).
    """
    lot = Lot.query.get_or_404(lot_id)

    # Проверяем, нет ли уже заказа в этом раунде. Старые заказы expired-раундов
    # игнорируем — они принадлежат прошлому розыгрышу того же лота.
    existing = Order.query.filter_by(lot_id=lot_id).filter(
        Order.status.in_(('pending', 'paid'))
    ).first()
    if existing:
        return jsonify({'order_id': existing.id, 'message': 'Заказ уже существует', 'order': existing.to_dict()})

    # Находим победителя ТЕКУЩЕГО раунда — максимальная ставка из ставок
    # с round == lot.current_round. Старые ставки прошлых раундов игнорируем.
    winning_bid = (
        Bid.query
           .filter_by(lot_id=lot_id, round=lot.current_round)
           .order_by(Bid.amount.desc())
           .first()
    )
    if not winning_bid:
        return jsonify({'error': 'Нет ставок'}), 400

    # Проверяем что текущий пользователь — победитель или админ
    user = User.query.get(session['user_id'])
    if winning_bid.user_id != session['user_id'] and not (user and user.is_admin):
        return jsonify({'error': 'Только победитель или админ может завершить аукцион'}), 403

    # Runner-up: вторая по сумме ставка в этом же раунде от ДРУГОГО юзера.
    # Если есть — он получит шанс выкупить лот (за СВОЮ ставку, не за сумму
    # победителя — логика реальных аукционов eBay/Sotheby's), когда первый
    # победитель просрочит оплату.
    runner_up_bid = (
        Bid.query
           .filter(Bid.lot_id == lot_id)
           .filter(Bid.round == lot.current_round)
           .filter(Bid.user_id != winning_bid.user_id)
           .order_by(Bid.amount.desc())
           .first()
    )
    runner_up_user_id = runner_up_bid.user_id if runner_up_bid else None
    runner_up_amount = runner_up_bid.amount if runner_up_bid else None

    import secrets
    order_code = f'BS-{datetime.utcnow().year}-WIN-{secrets.token_hex(3).upper()}'

    now = datetime.utcnow()

    # Помечаем аукцион как завершённый
    lot.end_time = now

    order = Order(
        user_id=winning_bid.user_id,
        lot_id=lot_id,
        amount=winning_bid.amount,
        status='pending',
        payment_deadline=now + timedelta(hours=24),
        order_code=order_code,
        created_at=now,
        runner_up_user_id=runner_up_user_id,
        runner_up_amount=runner_up_amount,
        attempt=1,
    )
    db.session.add(order)
    db.session.commit()

    logger.info(
        f'Аукцион завершён: lot={lot_id} round={lot.current_round} '
        f'winner=user_{winning_bid.user_id} amount={winning_bid.amount} '
        f'runner_up={runner_up_user_id} runner_up_amount={runner_up_amount} '
        f'order={order.order_code}'
    )

    return jsonify({'order_id': order.id, 'order': order.to_dict()})


@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    """Получить заказ"""
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())


@app.route('/api/orders/<int:order_id>/pay', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60)
@login_required
def pay_order(order_id):
    """Оплата заказа с баланса пользователя"""
    order = Order.query.get_or_404(order_id)
    user = User.query.get(session['user_id'])
    
    if order.user_id != session['user_id']:
        return jsonify({'error': 'Этот заказ не принадлежит вам'}), 403
    
    if order.status == 'paid':
        return jsonify({'message': 'Заказ уже оплачен', 'order': order.to_dict()})
    
    if order.payment_deadline < datetime.utcnow():
        order.status = 'expired'
        db.session.commit()
        return jsonify({'error': 'Срок оплаты истёк'}), 400
    
    # Проверяем баланс
    user_balance = user.balance or 0
    if user_balance < order.amount:
        deficit = order.amount - user_balance
        return jsonify({
            'error': 'Недостаточно средств на балансе',
            'insufficient_funds': True,
            'balance': user_balance,
            'required': order.amount,
            'deficit': deficit
        }), 402
    
    # Списываем с баланса
    user.balance = user_balance - order.amount
    order.status = 'paid'
    order.paid_at = datetime.utcnow()
    
    # Записываем транзакцию
    tx = Transaction(
        user_id=user.id,
        type='payment',
        amount=-order.amount,
        status='success',
        description=f'Оплата билета: {order.lot.title}',
        related_lot_id=order.lot_id
    )
    db.session.add(tx)
    db.session.commit()
    
    logger.info(f'Оплата заказа: user={user.username} order={order.order_code} amount={order.amount}')
    
    return jsonify({
        'message': 'Оплата прошла успешно',
        'order': order.to_dict(),
        'balance': user.balance,
        'redirect': f'/ticket/{order.id}'
    })


@app.route('/api/my-orders')
@login_required
def my_orders():
    """Получить все заказы текущего пользователя"""
    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.created_at.desc()).all()
    return jsonify([o.to_dict() for o in orders])


@app.route('/api/my-bids')
@login_required
def my_bids():
    """История ставок текущего пользователя — только ставки актуальных раундов.

    Если лот вернулся в продажу (round инкрементировался), старая ставка юзера
    из round=1 в /api/my-bids больше не появится. В БД она остаётся как история.
    """
    user_id = session['user_id']
    # JOIN с Lot, чтобы отфильтровать Bid по current_round самого лота.
    bids = (
        Bid.query
           .join(Lot, Bid.lot_id == Lot.id)
           .filter(Bid.user_id == user_id)
           .filter(Bid.round == Lot.current_round)
           .order_by(Bid.created_at.desc())
           .all()
    )

    result = []
    for bid in bids:
        # «Лидер раунда» — последняя по сумме ставка в текущем раунде лота
        last_bid = (
            Bid.query
               .filter_by(lot_id=bid.lot_id, round=bid.lot.current_round)
               .order_by(Bid.amount.desc())
               .first()
        )
        is_leader = last_bid and last_bid.user_id == user_id and last_bid.id == bid.id
        is_active = bid.lot.end_time > datetime.utcnow()
        
        if is_active and is_leader:
            status = 'active'  # Активный — пока лидер
        elif not is_active and is_leader:
            status = 'won'  # Выигран
        elif is_active and not is_leader:
            status = 'outbid'  # Перебита, но аукцион идёт
        else:
            status = 'lost'  # Проигран
        
        # Найти заказ если выиграл
        order = Order.query.filter_by(lot_id=bid.lot_id, user_id=user_id).first() if status == 'won' else None
        
        result.append({
            'id': bid.id,
            'amount': bid.amount,
            'created_at': bid.created_at.isoformat(),
            'lot': bid.lot.to_dict(),
            'status': status,
            'order_id': order.id if order else None
        })
    
    return jsonify(result)


@app.route('/api/profile/stats')
@login_required
def profile_stats():
    """Статистика пользователя для профиля.

    Ставки учитываются только в текущем раунде каждого лота. Ставки прошлых
    раундов (если лот возвращался в продажу) в статистике не светятся.
    Wins (paid orders) — без round-фильтра: это история выкупов.
    """
    user_id = session['user_id']

    # Уникальные лоты, где юзер ставил в ТЕКУЩЕМ раунде каждого лота.
    bid_lot_ids = (
        db.session.query(Bid.lot_id)
                  .join(Lot, Bid.lot_id == Lot.id)
                  .filter(Bid.user_id == user_id)
                  .filter(Bid.round == Lot.current_round)
                  .distinct()
                  .all()
    )
    total_bids_count = len(bid_lot_ids)

    # Выигрыши = оплаченные заказы (без round-фильтра — это история выкупов)
    paid_orders = Order.query.filter_by(user_id=user_id, status='paid').all()
    wins_count = len(paid_orders)
    total_spent = sum(o.amount for o in paid_orders)

    # Активные ставки = я лидер в текущем раунде живого лота
    active_bids_count = 0
    for (lot_id,) in bid_lot_ids:
        lot = Lot.query.get(lot_id)
        if lot and lot.end_time > datetime.utcnow() and lot.status == 'active':
            last = (
                Bid.query
                   .filter_by(lot_id=lot_id, round=lot.current_round)
                   .order_by(Bid.amount.desc())
                   .first()
            )
            if last and last.user_id == user_id:
                active_bids_count += 1

    return jsonify({
        'wins': wins_count,
        'active_bids': active_bids_count,
        'total_bids': total_bids_count,
        'total_spent': total_spent,
        'level': 'Admin' if g.user.is_admin else ('Premium' if total_spent > 500000 else 'Standard')
    })


@app.route('/api/admin/lots', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=60)
@admin_required
def admin_create_lot():
    """Создание нового лота (только админ)"""
    data = request.get_json()
    
    required = ['title', 'description', 'image_url', 'venue', 'date', 'start_price', 'bid_step', 'end_time']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Поле {field} обязательно'}), 400
    
    # Валидация URL изображения. Допускаются:
    # - внешние http(s), data:image/
    # - локальный путь /static/... для картинок, захостенных у нас
    img_url = data['image_url']
    if not img_url.startswith(('https://', 'http://', 'data:image/', '/static/')):
        return jsonify({'error': 'Некорректный URL изображения'}), 400
    
    try:
        end_time = datetime.fromisoformat(data['end_time'].replace('Z', ''))
    except Exception:
        return jsonify({'error': 'Некорректный формат даты окончания'}), 400
    
    if end_time < datetime.utcnow():
        return jsonify({'error': 'Дата окончания не может быть в прошлом'}), 400
    
    start_price = int(data['start_price'])
    bid_step = int(data['bid_step'])
    
    if start_price < 1 or bid_step < 1:
        return jsonify({'error': 'Цена и шаг должны быть положительными'}), 400
    
    lot = Lot(
        title=sanitize_text(data['title']),
        description=sanitize_text(data['description']),
        image_url=img_url,
        venue=sanitize_text(data['venue']),
        date=sanitize_text(data['date']),
        start_price=start_price,
        current_price=start_price,
        bid_step=bid_step,
        end_time=end_time,
        is_featured=bool(data.get('is_featured', False)),
        tags=sanitize_text(data.get('tags', ''))
    )
    db.session.add(lot)
    db.session.commit()
    
    return jsonify({'message': 'Лот создан', 'lot': lot.to_dict()}), 201


@app.route('/api/favorites')
@login_required
def get_favorites():
    """Получить избранные лоты пользователя"""
    favorites = Favorite.query.filter_by(user_id=session['user_id']).all()
    lots = [fav.lot.to_dict() for fav in favorites]
    
    return jsonify(lots)


# ========================================
# ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
# ========================================

def init_db():
    """Создаёт таблицы. Сидинг тестовых данных — только если задана
    переменная окружения SEED_DEMO=1.

    На проде (где DATABASE_URL задан) сидинг ВСЕГДА выключен, даже если
    случайно установить SEED_DEMO=1 — чтобы не создать тестового админа
    с известным паролем на публичном инстансе.

    Чтобы создать первого админа на проде, используйте CLI-команду:
        flask create-admin <username> <email>
    """
    with app.app_context():
        db.create_all()

        # Сидинг разрешён ТОЛЬКО в dev и ТОЛЬКО при явном флаге
        if _is_production:
            print('✅ База данных инициализирована (production, без сидинга)')
            return

        if os.environ.get('SEED_DEMO') != '1':
            print('✅ База данных инициализирована (для сидинга демо-данных установите SEED_DEMO=1)')
            return

        # Проверяем, есть ли уже данные
        if Lot.query.count() == 0:
            # Создаем тестовые лоты
            lots_data = [
                {
                    'title': 'Стендап + Джаз: Ереванские вечера',
                    'description': 'Концерт лучших комиков Армении и профессиональных джазовых музыкантов. Шоу, которое объединяет настоящий джаз и остроумие стендап-артистов! Мировые хиты джаза прозвучат от резидентов Mezzo Classic House. На сцену выйдут сильнейшие комики Еревана с проверенным материалом. Формат: первый час — джазовое выступление, второй час — стендап от трёх комиков. Сбор гостей за 30 минут до начала.',
                    'image_url': '/static/img/lots/jazz.jpg',
                    'venue': 'Mezzo Classic House, Ереван',
                    'date': '18 мая 2026',
                    'start_price': 1, 'current_price': 2500, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(minutes=30),
                    'is_featured': True, 'tags': 'Стендап,Джаз,Live Music'
                },
                {
                    'title': 'Серж Танкян: Акустика под звёздами',
                    'description': 'Сольный акустический концерт лидера System of a Down на открытой площадке Каскада. Серж исполнит как хиты SOAD в акустической обработке, так и сольный материал. VIP-зона включает автограф-сессию после концерта, доступ в backstage и фото с артистом.',
                    'image_url': '/static/img/lots/rock.jpg',
                    'venue': 'Каскад, открытая площадка, Ереван',
                    'date': '19 мая 2026',
                    'start_price': 1, 'current_price': 4500, 'bid_step': 200,
                    'end_time': datetime.utcnow() + timedelta(days=2),
                    'is_featured': False, 'tags': 'Rock,Acoustic,Автограф'
                },
                {
                    'title': 'Тигран Амасян: Piano Infinite',
                    'description': 'Всемирно известный армянский пианист и композитор Тигран Амасян представляет новую программу «Piano Infinite». Уникальное сочетание джаза, классики и армянского фольклора. Концерт в камерной атмосфере Оперного театра. Первый ряд партера + программка с автографом.',
                    'image_url': '/static/img/lots/piano.jpg',
                    'venue': 'Национальный оперный театр, Ереван',
                    'date': '20 мая 2026',
                    'start_price': 1, 'current_price': 3000, 'bid_step': 150,
                    'end_time': datetime.utcnow() + timedelta(days=3),
                    'is_featured': False, 'tags': 'Piano,Jazz,Classical'
                },
                {
                    'title': 'ARARAT ROCK: Армянский рок-фестиваль',
                    'description': 'Ежегодный фестиваль армянского рока на открытом воздухе. В лайнапе: Vordan Karmir, The Beautified Project, Lav Eli, Dorians и специальные гости. Два дня музыки, фуд-корт с армянской кухней, зона отдыха. VIP-пакет включает: зона у сцены, отдельный бар, лаундж с видом на Арарат.',
                    'image_url': '/static/img/lots/festival.jpg',
                    'venue': 'Площадь Республики, Ереван',
                    'date': '21 мая 2026',
                    'start_price': 1, 'current_price': 1800, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=4),
                    'is_featured': False, 'tags': 'Festival,Rock,Open Air'
                },
                {
                    'title': 'Дудук при свечах: Дживан Гаспарян мл.',
                    'description': 'Магический вечер армянского дудука в исполнении Дживана Гаспаряна-младшего. Концерт проходит при свечах в атмосфере древнего храма Гарни. В программе: традиционные армянские мелодии, импровизации и мировые хиты в обработке для дудука. Трансфер из Еревана включён в VIP-пакет.',
                    'image_url': '/static/img/lots/duduk.jpg',
                    'venue': 'Храм Гарни, Котайк',
                    'date': '22 мая 2026',
                    'start_price': 1, 'current_price': 2000, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=5),
                    'is_featured': False, 'tags': 'Дудук,Traditional,Candle Light'
                },
                {
                    'title': 'Gor Sujyan Stand-Up: Большой сольник',
                    'description': 'Самый популярный армянский стендап-комик Гор Суджян с новой программой «Без фильтра». 2 часа чистого юмора о жизни в Армении, отношениях и культурных различиях. Внимание: возможна нецензурная лексика. Первые 3 ряда — splash zone. VIP включает meet & greet + фото после шоу.',
                    'image_url': '/static/img/lots/standup.jpg',
                    'venue': 'Kami Music Hall, Ереван',
                    'date': '23 мая 2026',
                    'start_price': 1, 'current_price': 1500, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=6),
                    'is_featured': False, 'tags': 'Стендап,Comedy,Meet & Greet'
                },
                {
                    'title': 'Симфонический оркестр: Хачатурян & Комитас',
                    'description': 'Государственный симфонический оркестр Армении исполняет шедевры Арама Хачатуряна и обработки Комитаса. Дирижёр — Сергей Смбатян. В программе: «Танец с саблями», «Маскарад», «Гаянэ» и армянские народные песни в симфонической обработке. VIP-ложа на 2 персоны с шампанским в антракте.',
                    'image_url': '/static/img/lots/symphony.jpg',
                    'venue': 'Национальный оперный театр, Ереван',
                    'date': '24 мая 2026',
                    'start_price': 1, 'current_price': 3500, 'bid_step': 200,
                    'end_time': datetime.utcnow() + timedelta(days=7),
                    'is_featured': False, 'tags': 'Symphony,Classical,VIP Ложа'
                },
                {
                    'title': 'DJ Night: Erevan After Dark',
                    'description': 'Ночь электронной музыки с топовыми армянскими и приглашёнными DJ. Лайнап: Menua (deep house), Arni (techno), специальный гость из Берлина. Начало в 23:00, окончание в 06:00. VIP-столик на 4 персоны + бутылка + отдельный вход без очереди. Dress code: smart casual. 21+.',
                    'image_url': '/static/img/lots/dj.jpg',
                    'venue': 'Paparazzi Club, Ереван',
                    'date': '25 мая 2026',
                    'start_price': 1, 'current_price': 800, 'bid_step': 50,
                    'end_time': datetime.utcnow() + timedelta(days=8),
                    'is_featured': False, 'tags': 'DJ,Electronic,Night Club'
                },
                {
                    'title': 'Этно-фолк вечер: Армения в песнях',
                    'description': 'Уникальный концерт армянского этно-фолка. Живые инструменты: дудук, зурна, дхол, каманча, канон. Исполнители в национальных костюмах. В программе: древние армянские песни, танцевальные мелодии, эпические баллады. После концерта — дегустация армянских вин и сыров.',
                    'image_url': '/static/img/lots/duduk.jpg',
                    'venue': 'Дом камерной музыки, Ереван',
                    'date': '26 мая 2026',
                    'start_price': 1, 'current_price': 1200, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=9),
                    'is_featured': False, 'tags': 'Ethno,Folk,Wine Tasting'
                },
                {
                    'title': 'Севак Ханагян: Голос Армении',
                    'description': 'Победитель X-Factor Севак Ханагян с большим сольным концертом. В программе: хиты из шоу, авторские песни и каверы мировых хитов на армянском языке. Живой оркестр из 12 музыкантов. VIP-пакет: первые 2 ряда + backstage + совместное фото + подписанный альбом.',
                    'image_url': '/static/img/lots/jazz.jpg',
                    'venue': 'СКК им. Карена Демирчяна, Ереван',
                    'date': '27 мая 2026',
                    'start_price': 1, 'current_price': 2800, 'bid_step': 150,
                    'end_time': datetime.utcnow() + timedelta(days=10),
                    'is_featured': False, 'tags': 'Pop,Live Band,Backstage'
                },
                {
                    'title': 'Импровизационное шоу «Без сценария»',
                    'description': 'Команда армянских импровизаторов представляет шоу, где ВСЁ решает зрительный зал! Никаких заготовок — только ваши подсказки и мгновенная реакция артистов. Смех гарантирован. Формат: 4 раунда по 20 минут + финальная импровизация.',
                    'image_url': '/static/img/lots/standup.jpg',
                    'venue': 'Hamalir Theatre, Ереван',
                    'date': '28 мая 2026',
                    'start_price': 1, 'current_price': 600, 'bid_step': 50,
                    'end_time': datetime.utcnow() + timedelta(days=11),
                    'is_featured': False, 'tags': 'Improv,Comedy,Interactive'
                },
                {
                    'title': 'Ночь кино под открытым небом',
                    'description': 'Кинопоказ культового армянского фильма «Цвет граната» Параджанова на большом экране под звёздным небом Еревана. Перед показом — лекция киноведа о символизме фильма. VIP-зона: кресла-мешки, пледы, попкорн и глинтвейн включены.',
                    'image_url': '/static/img/lots/cinema.jpg',
                    'venue': 'Кинотеатр «Москва», крыша, Ереван',
                    'date': '29 мая 2026',
                    'start_price': 1, 'current_price': 400, 'bid_step': 50,
                    'end_time': datetime.utcnow() + timedelta(days=12),
                    'is_featured': False, 'tags': 'Cinema,Open Air,Paradjanov'
                },
                {
                    'title': 'Vahe Berberyan: Поэтический вечер',
                    'description': 'Известный армянский писатель и художник Ваге Берберян читает свои новые произведения. Атмосферный вечер с живой музыкой на дудуке. Включены: бокал вина, авторская книга с автографом и встреча с автором.',
                    'image_url': '/static/img/lots/piano.jpg',
                    'venue': 'Дом-музей Ованеса Туманяна, Ереван',
                    'date': '30 мая 2026',
                    'start_price': 1, 'current_price': 700, 'bid_step': 50,
                    'end_time': datetime.utcnow() + timedelta(days=13),
                    'is_featured': False, 'tags': 'Poetry,Books,Wine'
                },
                {
                    'title': 'Lav Eli: Acoustic Session',
                    'description': 'Армянская инди-группа Lav Eli с камерным акустическим концертом. Новые песни и переосмысленные хиты в неожиданных аранжировках. Зона у сцены — стоячие места. После концерта — встреча с группой.',
                    'image_url': '/static/img/lots/rock.jpg',
                    'venue': 'Stop Club, Ереван',
                    'date': '31 мая 2026',
                    'start_price': 1, 'current_price': 1100, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=14),
                    'is_featured': False, 'tags': 'Indie,Acoustic,Meet & Greet'
                },
                {
                    'title': 'Армянский балет: Спартак',
                    'description': 'Легендарный балет Хачатуряна на сцене Оперного театра. Лучшие солисты Армянского театра оперы и балета. Партер VIP-зона + программка-сувенир + бокал шампанского в антракте. Продолжительность 2.5 часа с двумя антрактами.',
                    'image_url': '/static/img/lots/ballet.jpg',
                    'venue': 'Национальный оперный театр, Ереван',
                    'date': '1 июня 2026',
                    'start_price': 1, 'current_price': 3200, 'bid_step': 150,
                    'end_time': datetime.utcnow() + timedelta(days=4, hours=12),
                    'is_featured': False, 'tags': 'Ballet,Khachaturian,VIP'
                },
                {
                    'title': 'Hayko Cepkin: Rock Night',
                    'description': 'Турецкая рок-легенда Hayko Cepkin впервые в Армении. Энергичное шоу с фирменным звуком и пиротехникой. Fan Pit (стоячие у сцены) + эксклюзивная футболка тура + ранний вход.',
                    'image_url': '/static/img/lots/rock.jpg',
                    'venue': 'Hamalir Arena, Ереван',
                    'date': '2 июня 2026',
                    'start_price': 1, 'current_price': 2400, 'bid_step': 200,
                    'end_time': datetime.utcnow() + timedelta(days=8, hours=12),
                    'is_featured': False, 'tags': 'Rock,Fan Pit,Pyro'
                },
                {
                    'title': 'Pasadena: Tribute to Queen',
                    'description': 'Шоу-трибьют легендарной группе Queen в исполнении армянских музыкантов. Все самые знаменитые хиты Фредди Меркьюри: Bohemian Rhapsody, We Will Rock You, We Are The Champions. Живой звук, костюмы, шоу света.',
                    'image_url': '/static/img/lots/festival.jpg',
                    'venue': 'Hard Rock Cafe, Ереван',
                    'date': '3 июня 2026',
                    'start_price': 1, 'current_price': 1300, 'bid_step': 100,
                    'end_time': datetime.utcnow() + timedelta(days=12, hours=12),
                    'is_featured': False, 'tags': 'Tribute,Queen,Rock'
                }
            ]
            
            for lot_data in lots_data:
                lot = Lot(**lot_data)
                db.session.add(lot)
            
            db.session.commit()
            
            # Создаем тестовых пользователей
            test_users = [
                {'username': 'Suren_V', 'email': 'suren@test.com', 'password': 'test123', 'is_admin': True},
                {'username': 'Armen_91', 'email': 'armen@test.com', 'password': 'test123', 'is_admin': False},
                {'username': 'Hayk_Jan', 'email': 'hayk@test.com', 'password': 'test123', 'is_admin': False},
                {'username': 'Karen88', 'email': 'karen@test.com', 'password': 'test123', 'is_admin': False},
            ]
            
            for user_data in test_users:
                user = User(username=user_data['username'], email=user_data['email'], is_admin=user_data['is_admin'])
                user.set_password(user_data['password'])
                db.session.add(user)
            
            db.session.commit()
            
            # Создаем тестовые ставки для первого лота (50 Cent)
            lot_50cent = Lot.query.filter_by(title='50 CENT: The Final Lap Tour').first()
            if lot_50cent:
                test_bids = [
                    {'username': 'Karen88', 'amount': 435000, 'minutes_ago': 50},
                    {'username': 'Hayk_Jan', 'amount': 440000, 'minutes_ago': 45},
                    {'username': 'Armen_91', 'amount': 445000, 'minutes_ago': 40},
                    {'username': 'Suren_V', 'amount': 450000, 'minutes_ago': 20},
                ]
                
                for bid_data in test_bids:
                    user = User.query.filter_by(username=bid_data['username']).first()
                    if user:
                        bid = Bid(
                            amount=bid_data['amount'],
                            user_id=user.id,
                            lot_id=lot_50cent.id,
                            created_at=datetime.utcnow() - timedelta(minutes=bid_data['minutes_ago'])
                        )
                        db.session.add(bid)
                
                db.session.commit()
            
            print('✅ База данных инициализирована с тестовыми данными')
        else:
            print('✅ База данных уже содержит данные')


# ========================================
# CLI КОМАНДЫ (flask create-admin, flask seed)
# ========================================

@app.cli.command('create-admin')
def create_admin_cli():
    """Создать админа интерактивно. Использовать на проде вместо сидинга.
    Запуск: flask create-admin
    """
    import getpass
    username = input('Имя пользователя: ').strip()
    email = input('Email: ').strip()
    password = getpass.getpass('Пароль: ')

    valid, msg = validate_username(username)
    if not valid:
        print(f'❌ {msg}')
        return
    if not validate_email(email):
        print('❌ Некорректный email')
        return
    valid, msg = validate_password(password)
    if not valid:
        print(f'❌ {msg}')
        return

    if User.query.filter_by(username=username).first():
        print('❌ Пользователь с таким именем уже существует')
        return
    if User.query.filter_by(email=email).first():
        print('❌ Email уже зарегистрирован')
        return

    user = User(username=username, email=email.lower(), is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f'✅ Админ {username} создан (id={user.id})')


@app.cli.command('seed-refresh')
def seed_refresh_cli():
    """Сдвигает end_time у уже существующих лотов на будущее, не пересоздавая БД.

    Распределение совпадает с сидером: первый featured-лот — ~30 минут до конца
    («горящий», для демо таймера), остальные — равномерно по 2..14 дням.
    """
    lots = Lot.query.order_by(Lot.id.asc()).all()
    if not lots:
        print('❌ В БД нет лотов. Сначала запустите сидер (SEED_DEMO=1).')
        return

    now = datetime.utcnow()
    # Один «горящий» лот: featured, либо первый по id
    burning = next((l for l in lots if l.is_featured), lots[0])
    burning.end_time = now + timedelta(minutes=30)

    rest = [l for l in lots if l.id != burning.id]
    # Хвост — между 2 и 14 днями, шаг подбираем по числу лотов
    if rest:
        span_days = 14 - 2  # 12 дней
        step = span_days / len(rest)
        for i, lot in enumerate(rest):
            offset_days = 2 + step * i
            lot.end_time = now + timedelta(days=offset_days)

    db.session.commit()
    active = Lot.query.filter(Lot.end_time > now).count()
    print(f'✅ Обновлено лотов: {len(lots)}. Живых сейчас: {active}.')
    print(f'   «Горящий» (id={burning.id}): "{burning.title}" — до {burning.end_time.isoformat()}')


@app.cli.command('process-expired-orders')
def process_expired_orders_cli():
    """Обрабатывает просроченные заказы.

    Шаги:
    - Находит все Order со status='pending' AND payment_deadline < utcnow().
    - Для каждого:
      * attempt==1 и есть runner_up_user_id + runner_up_amount, и runner_up ещё
        НЕ дисквалифицирован (нет другого expired Order'а на этот же лот) →
        старый Order помечается 'expired', создаётся новый Order для runner_up
        с amount=runner_up_amount (его СОБСТВЕННАЯ ставка, не сумма победителя),
        payment_deadline=utcnow+24ч, attempt=2, runner_up_user_id/amount=NULL
        (третьего шанса нет).
      * иначе (attempt==2, нет runner_up, нет runner_up_amount, или runner_up
        сам уже expired-должник по этому лоту) → старый Order просто помечается
        'expired'.

    Возврат лота в продажу — задача отдельного шага, тут не делается.

    Идемпотентно: повторный запуск ничего не делает, потому что после первого
    прохода нет больше pending Order'ов с истёкшим payment_deadline (новый Order
    runner_up'а свежий, а expired-Order'ы уже не в выборке).
    """
    import secrets

    now = datetime.utcnow()
    expired_pending = (
        Order.query
             .filter(Order.status == 'pending')
             .filter(Order.payment_deadline < now)
             .all()
    )

    if not expired_pending:
        print('— нет просроченных Order\'ов для обработки')
        return

    promoted = 0
    expired_without_successor = 0

    for order in expired_pending:
        runner_up_valid = False
        if (
            order.attempt == 1
            and order.runner_up_user_id is not None
            and order.runner_up_amount is not None
        ):
            # Проверяем что runner_up не дисквалифицирован по этому же лоту
            # (на случай если он сам уже когда-то не выкупил этот лот).
            disq = Order.query.filter_by(
                lot_id=order.lot_id,
                user_id=order.runner_up_user_id,
                status='expired'
            ).first()
            runner_up_valid = disq is None

        # В любом случае помечаем старый Order expired
        order.status = 'expired'

        if runner_up_valid:
            new_code = f'BS-{now.year}-RU-{secrets.token_hex(3).upper()}'
            new_order = Order(
                user_id=order.runner_up_user_id,
                lot_id=order.lot_id,
                # Runner-up платит СВОЮ последнюю ставку, а не сумму победителя
                # (логика реальных аукционов eBay/Sotheby's).
                amount=order.runner_up_amount,
                status='pending',
                payment_deadline=now + timedelta(hours=24),
                order_code=new_code,
                created_at=now,
                runner_up_user_id=None,  # третьего шанса нет
                runner_up_amount=None,
                attempt=2,
            )
            db.session.add(new_order)
            promoted += 1
            logger.info(
                f'Runner-up promoted: lot={order.lot_id} '
                f'old_order={order.order_code} new_order={new_code} '
                f'user={order.runner_up_user_id} '
                f'winner_amount={order.amount} runner_up_amount={order.runner_up_amount}'
            )
            print(
                f'✓ lot={order.lot_id}: runner-up user_{order.runner_up_user_id} '
                f'получил Order {new_code} за {order.runner_up_amount} AMD '
                f'(вместо {order.amount} AMD победителя)'
            )
        else:
            expired_without_successor += 1
            logger.info(
                f'Order expired without successor: lot={order.lot_id} '
                f'order={order.order_code} attempt={order.attempt} '
                f'runner_up_id={order.runner_up_user_id}'
            )
            print(f'✗ lot={order.lot_id}: Order {order.order_code} expired без преемника')

            # Возврат лота в продажу: ни победитель, ни runner-up не выкупили
            # этот раунд. Сбрасываем цену в исходную, продлеваем +3 дня,
            # инкрементируем round и retry_count. Старые Bid НЕ удаляем —
            # они остаются как история и фильтруются по round в UI.
            lot = Lot.query.get(order.lot_id)
            if lot is None:
                logger.warning(f'Лот {order.lot_id} не найден при возврате в продажу')
                continue

            if lot.retry_count >= 2:
                # Защита от бесконечного цикла: после двух возвратов
                # окончательно закрываем лот.
                lot.status = 'finalized'
                logger.info(
                    f'Lot id={lot.id} окончательно закрыт: retry_count={lot.retry_count} '
                    f'(достигнут лимит возвратов)'
                )
                print(f'  ⛔ lot={lot.id}: лимит возвратов исчерпан, лот finalized')
            else:
                # original_start_price может быть NULL у легаси-данных до миграции:
                # подстраховываемся текущим start_price.
                base_price = lot.original_start_price or lot.start_price
                lot.current_price = base_price
                lot.end_time = now + timedelta(days=3)
                lot.retry_count = (lot.retry_count or 0) + 1
                lot.current_round = (lot.current_round or 1) + 1
                lot.status = 'active'
                logger.info(
                    f'Lot id={lot.id} returned to auction '
                    f'(round={lot.current_round}, retry_count={lot.retry_count})'
                )
                print(
                    f'  ↻ lot={lot.id}: возвращён в продажу '
                    f'(round={lot.current_round}, retry_count={lot.retry_count}, '
                    f'price сброшен в {base_price} AMD, end_time +3 дня)'
                )

    db.session.commit()

    print(f'— promoted to runner-up: {promoted}')
    print(f'— expired without successor: {expired_without_successor}')


@app.cli.command('db-upgrade-custom')
def db_upgrade_custom_cli():
    """Идемпотентная миграция под fallback-логику победителя.

    Добавляет недостающие колонки в lot/bid/order. Безопасно повторно запускать:
    уже существующие колонки пропускаются. Работает и под SQLite (instance/bidstage.db),
    и под PostgreSQL (Railway). После добавления делает бэкфилл
    Lot.original_start_price = start_price там, где NULL.
    """
    # Описание целевых изменений: (table, column, ddl_type_with_default)
    # DDL пишем вручную — Alembic в проекте сознательно не используется.
    targets = [
        ('lot', 'original_start_price', 'INTEGER'),
        ('lot', 'retry_count',          'INTEGER NOT NULL DEFAULT 0'),
        ('lot', 'current_round',        'INTEGER NOT NULL DEFAULT 1'),
        ('lot', 'status',               "VARCHAR(20) NOT NULL DEFAULT 'active'"),
        ('bid', 'round',                'INTEGER NOT NULL DEFAULT 1'),
        ('"order"', 'runner_up_user_id','INTEGER'),
        ('"order"', 'runner_up_amount', 'INTEGER'),
        ('"order"', 'attempt',          'INTEGER NOT NULL DEFAULT 1'),
    ]

    dialect = db.engine.dialect.name  # 'sqlite' | 'postgresql' | ...
    print(f'→ диалект БД: {dialect}')

    def existing_columns(table_name_quoted):
        # Для information_schema нужен plain (без кавычек), для PRAGMA — c кавычками,
        # потому что "order" — зарезервированное слово в SQLite.
        plain = table_name_quoted.strip('"')
        if dialect == 'sqlite':
            rows = db.session.execute(db.text(f'PRAGMA table_info({table_name_quoted})')).fetchall()
            return {r[1] for r in rows}  # PRAGMA: cid, name, type, notnull, dflt_value, pk
        else:
            rows = db.session.execute(
                db.text(
                    'SELECT column_name FROM information_schema.columns '
                    'WHERE table_name = :t'
                ),
                {'t': plain}
            ).fetchall()
            return {r[0] for r in rows}

    added = 0
    skipped = 0
    cols_cache = {}
    for table, column, ddl in targets:
        if table not in cols_cache:
            cols_cache[table] = existing_columns(table)
        if column in cols_cache[table]:
            print(f'= {table}.{column} — есть, пропуск')
            skipped += 1
            continue
        # SQLite до 3.35 не понимает IF NOT EXISTS у ADD COLUMN, поэтому полагаемся
        # на проверку выше. Для Postgres IF NOT EXISTS даёт дополнительный страховой пояс.
        if dialect == 'sqlite':
            stmt = f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'
        else:
            stmt = f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {ddl}'
        db.session.execute(db.text(stmt))
        db.session.commit()
        cols_cache[table].add(column)
        print(f'✓ {table}.{column} — добавлено')
        added += 1

    # Бэкфилл: для существующих лотов заполняем original_start_price.
    res = db.session.execute(
        db.text('UPDATE lot SET original_start_price = start_price WHERE original_start_price IS NULL')
    )
    db.session.commit()
    backfilled = res.rowcount if res.rowcount is not None else 0

    # Sanity-чек: счётчики записей, чтобы визуально убедиться что миграция
    # не потеряла данные.
    lot_count = db.session.execute(db.text('SELECT COUNT(*) FROM lot')).scalar()
    order_count = db.session.execute(db.text('SELECT COUNT(*) FROM "order"')).scalar()

    print(f'— added: {added}, skipped: {skipped}, backfilled: {backfilled}')
    print(f'— lots в БД: {lot_count}, orders в БД: {order_count}')


# Инициализация при импорте (для gunicorn на Railway)
init_db()


if __name__ == '__main__':
    print('🚀 Запуск Encore сервера...')
    print('📍 Откройте http://127.0.0.1:5000 в браузере')
    # debug=True раньше включался безусловно. Теперь только если явно задано.
    # На проде Procfile запускает gunicorn, этот блок не выполняется.
    debug_mode = os.environ.get('FLASK_DEBUG') == '1' and not _is_production
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
