# Site Admin Console — epsok.ru

Отдельная веб-консоль для управления пользователями демо без ISPmanager.

## URL

- Консоль: `https://epsok.ru/console/`
- API: `https://epsok.ru/api/`

## Первый запуск на хостинге

1. Скопируйте конфиг:
   ```bash
   cp demo/public/api/config.local.php.example demo/public/api/config.local.php
   ```
2. Заполните `db.pass`, `setup_token`, пароль `bootstrap_admin`.
3. Залейте на хостинг (`FTP_PASS=… node demo/deploy-public-ftp.mjs`).
4. Один раз откройте в браузере:
   ```
   https://epsok.ru/api/setup.php?token=ВАШ_SETUP_TOKEN
   ```
5. Войдите в консоль: `https://epsok.ru/console/`  
   Логин по умолчанию: `siteadmin` (пароль из `bootstrap_admin` в config).

6. **Смените** `setup_token` и пароль супер-админа после установки.

## Возможности

| Модуль | Описание |
|--------|----------|
| Пользователи | CRUD в `epsok_users`, bcrypt-пароли, persona, блокировка |
| Журнал | `epsok_admin_audit` — входы и изменения |
| Демо-вход | `/api/auth/login.php` — главный сайт читает MySQL |

## Локальная разработка

PHP + MySQL нужны для API. Без PHP работает **fallback** на встроенные демо-логины в JS.

```bash
cd demo/public
php -S 127.0.0.1:8080
```

## ISPmanager

По-прежнему нужен для DNS, SSL, тарифа и создания БД. Ежедневное управление пользователями — через `/console/`.
