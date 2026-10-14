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

Контейнеры не запускаются от root. Файл секрета принадлежит uid процесса внутри контейнера и доступен только ему: Keycloak — `1000`, приложение — `10001`. Каталог `secrets` остаётся доступен только root.

```bash
install -d -m 700 secrets
umask 077
openssl rand -hex 16 > secrets/postgres_password
openssl rand -hex 12 > secrets/kc_admin_password
openssl rand -hex 16 > secrets/kc_client_secret
openssl rand -hex 24 > secrets/session_secret
chown 1000:1000 secrets/kc_admin_password
chmod 400 secrets/kc_admin_password
chown 10001:10001 secrets/postgres_password secrets/kc_client_secret secrets/session_secret
chmod 400 secrets/postgres_password secrets/kc_client_secret secrets/session_secret
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout secrets/tls.key -out secrets/tls.crt -subj "/CN=localhost"
chmod 600 secrets/tls.key
chmod 644 secrets/tls.crt
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
