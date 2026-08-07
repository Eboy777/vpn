# VPN Control MVP

Реализация control plane браузерного VPN на FastAPI, PostgreSQL 16 и GOST HTTPS proxy.

## Локальный запуск этапа 1

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

`.env.example` содержит только заведомо небезопасные локальные значения. Production-профиль
отклоняет placeholder URL, dummy keys и включение реальных платежей до закрытия fiscal gate.
PostgreSQL публикуется только на loopback-порту `127.0.0.1:55439` для локальных миграционных
тестов; наружу он не доступен.

