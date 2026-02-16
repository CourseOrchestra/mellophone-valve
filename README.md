# mellophone-valve

[![CI Push](https://github.com/CourseOrchestra/mellophone-valve/actions/workflows/ci-push.yml/badge.svg)](https://github.com/CourseOrchestra/mellophone-valve/actions/workflows/ci-push.yml)
[![CodeQL](https://github.com/CourseOrchestra/mellophone-valve/actions/workflows/codeql.yml/badge.svg)](https://github.com/CourseOrchestra/mellophone-valve/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-tested%203.7%E2%80%933.14%20%7C%20runtime%20%3E%3D3.13-blue)](tox.ini)

Python-клиент для Mellophone (`sync` + `async`).

## Требования для использования

- Python `>= 3.7`

## Для разработки

Документация для разработчиков вынесена в `DEVELOPMENT.md`.

## Установка

Установка из Git (рекомендуется фиксировать тег, например `v3.1.0`):

### pip

```bash
pip install "mellophone-valve[httpx] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
pip install "mellophone-valve[requests] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
pip install "mellophone-valve[httpx,requests] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
```

### Pipfile (Pipenv)

Для `Pipenv` надежнее указывать Git-зависимость с extras напрямую в `Pipfile`.

```toml
[packages]
mellophone-valve = {git = "https://github.com/CourseOrchestra/mellophone-valve.git", ref = "v3.1.0", extras = ["httpx"]}
# или
mellophone-valve = {git = "https://github.com/CourseOrchestra/mellophone-valve.git", ref = "v3.1.0", extras = ["requests"]}
# или
mellophone-valve = {git = "https://github.com/CourseOrchestra/mellophone-valve.git", ref = "v3.1.0", extras = ["httpx", "requests"]}
```

### poetry

Для `Poetry` надежнее фиксировать Git-зависимость с extras в `pyproject.toml`:

```toml
[tool.poetry.dependencies]
mellophone-valve = { git = "https://github.com/CourseOrchestra/mellophone-valve.git", rev = "v3.1.0", extras = ["httpx"] }
# или
mellophone-valve = { git = "https://github.com/CourseOrchestra/mellophone-valve.git", rev = "v3.1.0", extras = ["requests"] }
# или
mellophone-valve = { git = "https://github.com/CourseOrchestra/mellophone-valve.git", rev = "v3.1.0", extras = ["httpx", "requests"] }
```

CLI-вариант для `Poetry`:

```bash
poetry add "git+https://github.com/CourseOrchestra/mellophone-valve.git#v3.1.0" --extras httpx
poetry add "git+https://github.com/CourseOrchestra/mellophone-valve.git#v3.1.0" --extras requests
poetry add "git+https://github.com/CourseOrchestra/mellophone-valve.git#v3.1.0" --extras "httpx requests"
```

### uv

```bash
uv add "mellophone-valve[httpx] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
uv add "mellophone-valve[requests] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
uv add "mellophone-valve[httpx,requests] @ git+https://github.com/CourseOrchestra/mellophone-valve.git@v3.1.0"
```

Примечания:

- `async`-методы требуют `httpx` (`mellophone-valve[httpx]`).
- При установке только `requests` доступны только `sync`-методы.
- В качестве `ref` можно использовать `tag`, `branch` или `commit SHA`.

## Быстрый старт

```python
from mellophone import Mellophone

client = Mellophone(base_url="http://localhost:8082/mellophone")
session_id = client.login("user", "password")
print(client.is_authenticated(session_id))
client.logout(session_id)
```

## API клиента

Класс `Mellophone` поддерживает пары методов `sync/async`.

Авторизация и сессия:

- `login/login_async` - выполняет логин, сохраняет `session_id` в клиенте и возвращает `ses_id` (если не передан, генерируется автоматически).
- `logout/logout_async` - завершает сессию по `ses_id` (или по `self.session_id`).
- `is_authenticated/is_authenticated_async` - проверяет сессию; возвращает словарь `user` при успехе или `False` при `403`.

Проверки:

- `check_credentials/check_credentials_async` - проверяет логин/пароль без создания сессии, возвращает данные `user`.
- `check_name/check_name_async` - проверяет логин/имя пользователя в текущей или переданной сессии, возвращает данные `user`.

Пароли и идентификатор сессии:

- `change_pwd/change_pwd_async` - меняет пароль пользователя, связанного с переданным `ses_id` (если `ses_id` не передан, используется `self.session_id`).
- `change_user_pwd/change_user_pwd_async` - меняет пароль указанного пользователя `username`.
- `change_app_ses_id/change_app_ses_id_async` - меняет `ses_id` сессии (`oldsesid` -> `newsesid`); `self.session_id` обновляется только если `ses_id` не передан.

Провайдеры и списки пользователей:

- `import_gp/import_gp_async` - импортирует groups/providers, возвращает список строк из ответа API.
- `get_provider_list/get_provider_list_async` - возвращает список или структуру провайдеров по учетным данным.
- `get_user_list/get_user_list_async` - возвращает список пользователей по `gp` (опционально `ip`, `pid`); токен берется из `self.user_manage_token`.

Настройки и user management:

- `set_settings/set_settings_async` - обновляет настройки (`lockout_time`, `login_attempts_allowed`); токен берется из `self.set_settings_token`.
- `create_user/create_user_async` - создает пользователя (`POST /user/create`, XML payload); токен берется из `self.user_manage_token`.
- `update_user/update_user_async` - обновляет пользователя по `sid` (`POST /user/{sid}`, XML payload); токен берется из `self.user_manage_token`.
- `delete_user/delete_user_async` - удаляет пользователя по `sid` (`DELETE /user/{sid}`); токен берется из `self.user_manage_token`.

Состояние сессии:

- `set_state/set_state_async` - сохраняет произвольное состояние для `ses_id`.
- `get_state/get_state_async` - возвращает ранее сохраненное состояние для `ses_id`.

Исключения:

- `HttpError` - базовая HTTP-ошибка API (`status_code`, `response_text`).
- `BadRequestError` - ошибка `HTTP 400` (некорректный запрос).
- `UnauthorizedError` - ошибка `HTTP 401` (неавторизован).
- `ForbiddenError` - ошибка `HTTP 403` (доступ запрещен).
- `NotFoundError` - ошибка `HTTP 404` (ресурс не найден).
- `ServerError` - серверная ошибка `HTTP 5xx`.
- `TransportError` - транспортная ошибка HTTP-клиента (сеть/соединение).
- `RequestTimeoutError` - превышен таймаут запроса.
- `ResponseParseError` - не удалось распарсить XML-ответ API.
- `MissingTokenError` - в клиенте не задан обязательный токен (`set_settings_token` или `user_manage_token`).
- `AsyncClientUnavailableError` - вызваны `async`-методы без установленного `httpx`.
