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

## Реализовано к программному gate этапа 5

- `POST /api/pairing/init` — создаёт или безопасно перезапускает pairing устройства;
- `GET /api/pairing/status` — возвращает pending либо новый device token после привязки;
- `POST /integrations/telegram/webhook/{path_secret}` — идемпотентно обрабатывает private `/start`;
- единственный 24-часовой trial на Telegram-пользователя, лимит устройств и автоматическое назначение active-ноды;
- HMAC-SHA-256 для токенов, AES-256-GCM для proxy-пароля и общие PostgreSQL rate limits.
- `GET /api/status` — проверяет доступ, выполняет failover и выдаёт credentials только разрешённому устройству;
- `GET /api/nodes` и `POST /api/nodes/select` — paid-only список и ручной выбор локации;
- транзакционное распределение по относительной загрузке с жёстким соблюдением `capacity_users`.
- защищённые node snapshots с ETag, lease и идемпотентным подтверждением revision;
- node sync-agent с атомарной заменой GOST auth-файла, rollback и fail-closed после lease;
- безопасные `warming`/`quiescing` переходы для bootstrap и планового drain;
- локальный `vpn-admin` для добавления нод и двухфазной ротации node token;
- эталонный primary/fallback HTTP-клиент: переключение только при network/timeout и
  `408/502/503/504`, без обхода `429` через резервный ingress;
- production-шаблоны двух TLS ingress, WireGuard A/B→origin, firewall и отдельного
  Compose control origin без публичного PostgreSQL;
- защита client IP: backend доверяет только двум точным WireGuard peer-адресам, а ingress
  перезаписывает пользовательский `X-Forwarded-For`;
- исходящий long polling GOST-нод: изменение списка пользователей обнаруживается примерно за
  0,5 секунды без открытия входящего webhook на ноде;
- worker-watchdog: три пропущенных ack-окна или stale heartbeat автоматически блокируют ноду,
  после чего пользователи переносятся на другую active-ноду с доступной capacity;
- команда проверки обоих ingress:

  ```bash
  vpn-api-proxy-check \
    --url https://api-a.vpn.example \
    --url https://api-b.vpn.example
  ```

Для полного закрытия этапа 4 остаётся развернуть код минимум на двух реальных VPS и выполнить
HTTPS CONNECT через GOST. Локальные и компонентные проверки реальный сетевой тест не заменяют.

Для полного закрытия этапа 5 остаётся арендовать два API proxy VPS у разных провайдеров/ASN,
назначить домены, выпустить TLS-сертификаты и развернуть шаблоны из `deploy/api-proxy`. Затем
нужно с внешнего узла доказать доступность обоих маршрутов, primary→fallback и прямую
недоступность origin. Общий FastAPI/PostgreSQL origin остаётся сознательной точкой отказа MVP.

Локальные значения Telegram в `.env.example` подходят только для автоматических тестов. Для проверки
через настоящий Telegram требуются BotFather token, username бота и внешний HTTPS webhook.

`.env.example` содержит только заведомо небезопасные локальные значения. Production-профиль
отклоняет placeholder URL, dummy keys и включение реальных платежей до закрытия fiscal gate.
PostgreSQL публикуется только на loopback-порту `127.0.0.1:55439` для локальных миграционных
тестов; наружу он не доступен.
