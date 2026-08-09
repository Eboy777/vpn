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

## Реализовано к программному gate этапа 6

- `POST /api/pairing/init` — создаёт или безопасно перезапускает pairing устройства;
- `GET /api/pairing/status` — возвращает pending либо новый device token после привязки;
- `POST /integrations/telegram/webhook/{path_secret}` — идемпотентно обрабатывает private messages,
  callback-кнопки и pairing `/start`;
- Telegram-бот Virgo: приветствие, профиль, постоянное нижнее меню, динамический хаб подключения,
  тарифный экран, FAQ через редактирование сообщений и deep-link в поддержку;
- ответы Telegram доставляются worker-ом через transactional outbox с повторами, а напоминания об
  окончании подписки создаются за 3 дня и за 1 день без дублей;
- телефонный VLESS/3X-UI/Marzban сценарий и кнопка оплаты отображаются как явные пустышки до
  подключения соответствующих адаптеров;
- единственный 24-часовой trial на Telegram-пользователя, лимит устройств и автоматическое назначение active-ноды;
- HMAC-SHA-256 для токенов, AES-256-GCM для proxy-пароля и общие PostgreSQL rate limits.
- `GET /api/status` — проверяет доступ, выполняет failover и выдаёт credentials только разрешённому устройству;
- `GET /api/nodes` и `POST /api/nodes/select` — paid-only список и ручной выбор локации;
- транзакционное распределение по относительной загрузке с жёстким соблюдением `capacity_users`.
- защищённые node snapshots с ETag, lease и идемпотентным подтверждением revision;
- node sync-agent с атомарной заменой GOST auth-файла, rollback и fail-closed после lease;
- hardening-шаблоны GOST-ноды: отдельный системный пользователь, запрет исходящих SSH/SMTP и
  private/link-local сетей, лимиты скорости, запросов и соединений, idle timeout и локальные метрики;
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

- Manifest V3 расширение Virgo с интерфейсом по утверждённым макетам, Telegram pairing и локальным
  QR-кодом без внешнего QR-сервиса;
- primary/fallback API client расширения с сохранением общего `Retry-After` между перезапусками
  service worker;
- `chrome.proxy.settings` в режиме HTTPS `fixed_servers`, обязательный bypass двух control hosts и
  автоматическая смена ноды по `/api/status`;
- proxy credentials выдаются через `onAuthRequired` только для точного challenge текущей ноды и
  не передаются popup либо обычной HTTP-аутентификации сайта;
- минутный alarm восстанавливается при старте браузера, истечение/блокировка/отзыв снимают proxy,
  а paid-пользователь может выбрать ноду или вернуться к автоматической балансировке;
- CORS разрешает точные extension-facing access routes только для allowlist extension origins.

Для полного закрытия этапа 4 остаётся развернуть код минимум на двух реальных VPS и выполнить
HTTPS CONNECT через GOST. Локальные и компонентные проверки реальный сетевой тест не заменяют.

Для полного закрытия этапа 5 остаётся арендовать два API proxy VPS у разных провайдеров/ASN,
назначить домены, выпустить TLS-сертификаты и развернуть шаблоны из `deploy/api-proxy`. Затем
нужно с внешнего узла доказать доступность обоих маршрутов, primary→fallback и прямую
недоступность origin. Общий FastAPI/PostgreSQL origin остаётся сознательной точкой отказа MVP.

Код программной части этапа 6 находится в `extension/`. Для полного gate нужны реальные URL двух
ingress, стабильный ID подписанной сборки, URL пользовательского соглашения, установка в текущую и
предыдущую стабильные версии Chrome/Яндекс Браузера и HTTPS CONNECT через настоящую GOST-ноду.
Контейнеры и реальный browser/GOST E2E в этой итерации не запускались по указанию владельца.

Локальные значения Telegram в `.env.example` подходят только для автоматических тестов. Для проверки
через настоящий Telegram достаточно положить BotFather token и username бота в `.env`: локальный
worker использует long polling и не требует публичного домена. Production-профиль по-прежнему
принимает обновления только через внешний HTTPS webhook.

Контейнерные тесты используют отдельный временный `postgres-test` и не изменяют локальную рабочую
базу `postgres`.

`.env.example` содержит только заведомо небезопасные локальные значения. Production-профиль
отклоняет placeholder URL, dummy keys и включение реальных платежей до закрытия fiscal gate.
PostgreSQL публикуется только на loopback-порту `127.0.0.1:55439` для локальных миграционных
тестов; наружу он не доступен.
