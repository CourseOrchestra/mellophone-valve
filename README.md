# mellophone-valve

Python-клиент для Mellophone (`sync` + `async`) с unit- и интеграционными тестами.

## Требования

- Python `>= 3.13`
- [uv](https://docs.astral.sh/uv/)
- Docker + Docker Compose (для интеграционных тестов)

## Установка

```bash
uv sync --extra httpx
# или
uv sync --extra requests
```

Примечание:

- `async`-методы требуют `httpx` (`mellophone-valve[httpx]`).
- При установке только `requests` доступны только `sync`-методы.

## Быстрый старт

```python
from mellophone import Mellophone

client = Mellophone(base_url="http://localhost:8082/mellophone")
session_id = client.login("user", "password")
print(client.is_authenticated(session_id))
client.logout(session_id)
```

## API клиента

Класс `Mellophone` поддерживает пары методов `sync/async`:

- Авторизация: `login/login_async`, `logout/logout_async`, `is_authenticated/is_authenticated_async`
- Проверки: `check_credentials/check_credentials_async`, `check_name/check_name_async`
- Пароли и сессии: `change_pwd/change_pwd_async`, `change_user_pwd/change_user_pwd_async`, `change_app_ses_id/change_app_ses_id_async`
- Провайдеры и пользователи: `import_gp/import_gp_async`, `get_provider_list/get_provider_list_async`, `get_user_list/get_user_list_async`
- Настройки и user management: `set_settings/set_settings_async`, `create_user/create_user_async`, `update_user/update_user_async`

Также доступны исключения:

- `HttpError`
- `BadRequestError`
- `UnauthorizedError`
- `ForbiddenError`
- `NotFoundError`
- `ServerError`
- `TransportError`
- `RequestTimeoutError`
- `ResponseParseError`
- `AsyncClientUnavailableError`

## Локальный стенд через Docker

```bash
docker compose up -d
```

Сервисы:

- Mellophone: `http://localhost:8082/mellophone`
- PostgreSQL: `localhost:5430`

Инициализация БД выполняется автоматически из `docker-config/init-db.sql` через mount в `db:/docker-entrypoint-initdb.d/init-db.sql`.

Важно: скрипты из `/docker-entrypoint-initdb.d` выполняются только при первичной инициализации Postgres volume.

## Тесты

Все тесты:

```bash
uv run pytest -q
```

Только unit-тесты:

```bash
uv run pytest tests/test_mellophone.py -q
```

Интеграционные:

```bash
uv run pytest tests/test_integration_smoke.py -q
uv run pytest tests/test_integration_mellophone.py -q
```

## Coverage

```bash
uv run --with coverage --with pytest-cov pytest --cov=. --cov-report=term-missing -q
```

## VS Code Tasks

В `.vscode/tasks.json` добавлены задачи:

- `uv sync`
- `uv update` (`uv lock --upgrade`)
- `pytest coverage`
