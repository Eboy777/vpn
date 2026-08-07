# VPN Control MVP

Реализация control plane браузерного VPN на FastAPI, PostgreSQL 16 и GOST HTTPS proxy.

## Локальный запуск

1. Создайте локальную конфигурацию и замените демонстрационные значения:

   ```bash
   cp -n .env.example .env
   ```

2. Запустите PostgreSQL, миграции, API, worker и reverse proxy:

   ```bash
   docker compose up -d --build
   ```

3. Проверьте сервис:

   ```bash
   curl http://127.0.0.1:8080/health/live
   curl http://127.0.0.1:8080/health/ready
   ```

4. Запустите тесты на Python 3.12 и PostgreSQL 16:

   ```bash
   docker compose --profile test run --rm tests
   ```

## Реализовано к завершению этапа 2

- `POST /api/pairing/init` — создаёт или безопасно перезапускает pairing устройства;
- `GET /api/pairing/status` — возвращает pending либо новый device token после привязки;
- `POST /integrations/telegram/webhook/{path_secret}` — идемпотентно обрабатывает private `/start`;
- единственный 24-часовой trial на Telegram-пользователя, лимит устройств и автоматическое назначение active-ноды;
- HMAC-SHA-256 для токенов, AES-256-GCM для proxy-пароля и общие PostgreSQL rate limits.

Локальные значения Telegram в `.env.example` подходят только для автоматических тестов. Для проверки
через настоящий Telegram требуются BotFather token, username бота и внешний HTTPS webhook.

`.env.example` содержит только заведомо небезопасные локальные значения. Production-профиль
отклоняет placeholder URL, dummy keys и включение реальных платежей до закрытия fiscal gate.
PostgreSQL публикуется только на loopback-порту `127.0.0.1:55439` для локальных миграционных
тестов; наружу он не доступен.
