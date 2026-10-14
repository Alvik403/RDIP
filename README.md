# Реестр договоров и платежей

Стенд ДиП: снаружи только nginx на порту 443, внутри Keycloak, приложение и Postgres. Пароли и токены Keycloak в браузер не попадают. Сессия хранится в Postgres, cookie `Secure` и `HttpOnly`.

## Состав

| Сервис | Где слушает | Снаружи |
| --- | --- | --- |
| nginx | 443 | да |
| Keycloak 26.5.7 | 8080, путь `/auth` | нет |
| web (FastAPI) | 8000 | нет |
| Postgres 16 | 5432 | нет |

Группы: `DiP-Viewers`, `DiP-Editors`, `DiP-Auditors`, `DiP-Admins`.

Просмотр есть у всех четырёх групп. Договоры и платежи меняют `editor` и `admin`. Журнал видят `editor`, `auditor` и `admin`. Откат записи журнала доступен только `admin`.

Учётные записи стенда, пароль совпадает с именем: `viewer`, `editor`, `auditor`, `admin`.

## Запуск

Нужны Docker и Docker Compose. Порт 443 должен быть свободен. Каталог `secrets/` в git не входит.

```bash
install -d -m 700 secrets
umask 077
openssl rand -base64 48 | tr -dc A-Za-z0-9 | head -c 32 > secrets/postgres_password
openssl rand -base64 48 | tr -dc A-Za-z0-9 | head -c 24 > secrets/kc_admin_password
openssl rand -base64 48 | tr -dc A-Za-z0-9 | head -c 32 > secrets/kc_client_secret
openssl rand -base64 64 | tr -dc A-Za-z0-9 | head -c 48 > secrets/session_secret
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout secrets/tls.key -out secrets/tls.crt -subj "/CN=localhost"
docker compose up --build -d
```

Открыть `https://localhost/login`. Сертификат самоподписанный, браузер попросит подтверждение. После входа адрес становится `https://localhost/`.

Проверка: `https://localhost/health` и `https://localhost/ready`.

## Адреса

- `GET /login` — страница входа
- `GET /` — реестр
- `GET /health`, `GET /ready` — без входа
- `GET /api/me`
- `GET|POST /api/contracts`, `PATCH|DELETE /api/contracts/{id}`
- `GET|POST /api/specifications`, `PATCH|DELETE /api/specifications/{id}`
- `GET|POST /api/payments`, `PATCH|DELETE /api/payments/{id}`
- `GET /api/audit` — журнал
- `POST /api/audit/{id}/rollback` — откат, только `admin`
- `POST /api/logout`

Изменяющие запросы передают заголовок `X-CSRF-Token` из `/api/me`. Если строку уже сохранил другой редактор, ответ `409`.

Суммы в Postgres хранятся как `numeric`. Остаток лимита и остаток оплат считает сервер. Журнал операций пишется в stdout контейнера `web`.

Первый пустой запуск загружает демонстрационные договоры из `data/data.json`.

Имя `https://localhost` задано в `docker-compose.yml` (`PUBLIC_BASE` и `--hostname` Keycloak) и в `keycloak/realm-template.json` (адреса возврата). Для другого имени сервера эти три места нужно заменить до первого запуска.
