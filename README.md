# 🎫 Encore — Аукцион билетов на концерты

## 📋 Описание проекта

**Encore** — это полноценная веб-платформа для аукционной продажи билетов на концерты в Армении с backend на Flask и базой данных SQLite.

### Что реализовано:

✅ **Backend на Flask**:
- RESTful API для всех операций
- SQLAlchemy ORM для работы с БД
- Сессии для авторизации
- Хеширование паролей

✅ **База данных SQLite**:
- Таблица пользователей (User)
- Таблица лотов (Lot)
- Таблица ставок (Bid)
- Таблица избранного (Favorite)

✅ **Функциональность**:
- Регистрация и авторизация
- Просмотр активных аукционов
- Создание ставок
- Добавление в избранное
- История ставок
- Автоматическое обновление цен

---

## 🚀 Как запустить проект

### Шаг 1: Установка зависимостей

```bash
# Установите Python 3.8+ если еще не установлен

# Установите зависимости
pip install -r requirements.txt
```

### Шаг 2: Запуск приложения

```bash
# Запустите Flask сервер
python app.py
```

### Шаг 3: Откройте в браузере

```
http://127.0.0.1:5000
```

**Готово!** База данных создастся автоматически при первом запуске с тестовыми данными.

---

## 📂 Структура проекта

```
bidstage/
│
├── app.py                  # Главный файл Flask приложения
├── requirements.txt        # Зависимости Python
├── .gitignore             # Игнорируемые файлы
│
├── templates/             # HTML шаблоны
│   └── index.html         # Главная страница
│
├── static/                # Статические файлы
│   └── script.js          # JavaScript с API интеграцией
│
├── bidstage.db            # База данных SQLite (создается автоматически)
│
└── README.md              # Документация
```

---

## �️ Структура базы данных

### Таблица `user` (Пользователи)
```sql
id              INTEGER PRIMARY KEY
username        VARCHAR(80) UNIQUE NOT NULL
email           VARCHAR(120) UNIQUE NOT NULL
password_hash   VARCHAR(200) NOT NULL
created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
```

### Таблица `lot` (Лоты/Концерты)
```sql
id              INTEGER PRIMARY KEY
title           VARCHAR(200) NOT NULL
description     TEXT NOT NULL
image_url       VARCHAR(500) NOT NULL
venue           VARCHAR(200) NOT NULL
date            VARCHAR(100) NOT NULL
start_price     INTEGER NOT NULL
current_price   INTEGER NOT NULL
bid_step        INTEGER NOT NULL
end_time        DATETIME NOT NULL
is_featured     BOOLEAN DEFAULT FALSE
tags            VARCHAR(200)
created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
```

### Таблица `bid` (Ставки)
```sql
id              INTEGER PRIMARY KEY
amount          INTEGER NOT NULL
user_id         INTEGER FOREIGN KEY -> user.id
lot_id          INTEGER FOREIGN KEY -> lot.id
created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
```

### Таблица `favorite` (Избранное)
```sql
id              INTEGER PRIMARY KEY
user_id         INTEGER FOREIGN KEY -> user.id
lot_id          INTEGER FOREIGN KEY -> lot.id
created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
UNIQUE(user_id, lot_id)
```

---

## 🔌 API Endpoints

### Аутентификация

**POST** `/api/register` — Регистрация нового пользователя
```json
{
  "username": "david",
  "email": "david@example.com",
  "password": "password123"
}
```

**POST** `/api/login` — Вход пользователя
```json
{
  "username": "david",
  "password": "password123"
}
```

**POST** `/api/logout` — Выход пользователя

**GET** `/api/me` — Получить текущего пользователя

### Лоты

**GET** `/api/lots` — Получить все активные лоты

**GET** `/api/lots/<id>` — Получить конкретный лот

**GET** `/api/lots/<id>/bids` — Получить историю ставок для лота

**POST** `/api/lots/<id>/bid` — Сделать ставку
```json
{
  "amount": 55000
}
```

**POST** `/api/lots/<id>/favorite` — Добавить/удалить из избранного

**GET** `/api/favorites` — Получить избранные лоты пользователя

---

## 🎨 Дизайн

### Современный премиальный стиль:
- **Темная тема** с золотыми акцентами (#D4AF37)
- **Профессиональные шрифты**: Cabinet Grotesk, Satoshi, JetBrains Mono
- **Tailwind CSS** для стилизации
- **Iconify** для векторных иконок

---

## 💡 Как работает код

### Backend (app.py)

**Модели SQLAlchemy**:
- `User` — пользователи с хешированными паролями
- `Lot` — лоты концертов
- `Bid` — ставки пользователей
- `Favorite` — избранные лоты

**Маршруты Flask**:
- `/` — главная страница (render_template)
- `/api/*` — RESTful API endpoints (jsonify)

**Инициализация БД**:
- `init_db()` — создает таблицы и добавляет тестовые данные

### Frontend (static/script.js)

**Основные функции**:
- `loadLots()` — загружает лоты через API
- `displayLots()` — отображает карточки лотов
- `openBidModal()` — открывает модальное окно ставки
- `submitBid()` — отправляет ставку на сервер
- `login()` / `register()` — авторизация
- `toggleFavorite()` — добавление в избранное

**Таймеры**:
- Обновляются каждую секунду
- Показывают оставшееся время до конца аукциона
- Красный цвет для срочных (< 3 часов)

---

## 🔐 Безопасность

✅ Хеширование паролей с помощью Werkzeug  
✅ Сессии Flask для авторизации  
✅ Валидация данных на сервере  
✅ Проверка прав доступа  
✅ SQL-инъекции защищены через SQLAlchemy ORM  

---

## 🎯 Тестовые данные

При первом запуске создаются 4 тестовых лота:

1. **System of a Down** — 50,000 AMD (2 часа)
2. **Imagine Dragons** — 120,000 AMD (2ч 15мин)
3. **Arctic Monkeys** — 45,000 AMD (5ч 40мин)
4. **Armenian State Symphony** — 85,000 AMD (22 часа)

Для тестирования создайте пользователя через форму регистрации.

---

## 🚀 Что можно добавить

### Функциональность:
🔹 WebSocket для обновления ставок в реальном времени  
🔹 Email уведомления о перебитой ставке  
🔹 Интеграция с платежными системами  
🔹 Проверка публикаций в соцсетях через API  
🔹 Админ-панель для управления лотами  
🔹 Генерация QR-кодов для билетов  
🔹 Экспорт истории ставок  

### Технологии:
🔹 PostgreSQL вместо SQLite для production  
🔹 Redis для кэширования  
🔹 Celery для фоновых задач  
🔹 Docker для контейнеризации  
🔹 Nginx для production  
🔹 JWT токены вместо сессий  

---

## 🐛 Отладка

### Проблема: База данных не создается
**Решение**: Удалите файл `bidstage.db` и перезапустите `python app.py`

### Проблема: Ошибка импорта Flask
**Решение**: Установите зависимости `pip install -r requirements.txt`

### Проблема: Порт 5000 занят
**Решение**: Измените порт в `app.py`: `app.run(port=5001)`

### Проблема: Статические файлы не загружаются
**Решение**: Проверьте структуру папок `templates/` и `static/`
git push -u origin main
---

## � Статистика проекта

```
Файлов Python:         1 (app.py)
Файлов HTML:           1 (index.html)
Файлов JavaScript:     1 (script.js)
Строк Python:          ~400
Строк JavaScript:      ~500
Таблиц в БД:           4
API Endpoints:         11
```

---

## 🎤 Для собеседования

### Ключевые моменты:

**Архитектура:**
"Это полноценное веб-приложение с разделением на frontend и backend. Flask обрабатывает запросы и работает с базой данных, JavaScript делает асинхронные запросы к API."

**База данных:**
"Использую SQLite для разработки — легко запустить без настройки. В production можно переключиться на PostgreSQL, изменив только строку подключения."

**Безопасность:**
"Пароли хешируются с помощью Werkzeug, используются сессии Flask для авторизации, SQLAlchemy защищает от SQL-инъекций."

**API:**
"RESTful API с понятными endpoints. GET для чтения данных, POST для создания. Все ответы в JSON формате."

**Что дальше:**
"Можно добавить WebSocket для обновления ставок в реальном времени, интеграцию с платежными системами, email уведомления."

---

## 📞 Контакты

**Проект создан для**: Демонстрации навыков fullstack-разработки  
**Автор**: Давид  

---

## 📄 Лицензия

Этот проект создан в образовательных целях и свободен для использования и модификации.

---

**Encore** — Премиальная платформа для аукционов билетов на концерты в Армении. 🎫✨

**Запустите сейчас**: `python app.py`
