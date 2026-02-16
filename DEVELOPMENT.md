# Development Guide

## Требования для разработки

- Python `>= 3.13` (см. `pyproject.toml`)
- [uv](https://docs.astral.sh/uv/)
- Docker + Docker Compose (для интеграционных тестов и `tox`-прогонов)

Примечание: тесты в CI/tox гоняются на Python `3.7-3.14`.

## Локальный стенд через Docker

```bash
docker compose up -d
```

Сервисы:

- Mellophone: `http://localhost:8082/mellophone`
- PostgreSQL: `localhost:5430`

Инициализация БД выполняется автоматически из `docker-config/init-db.sql` через mount в `db:/docker-entrypoint-initdb.d/init-db.sql`.

Важно: скрипты из `/docker-entrypoint-initdb.d` выполняются только при первичной инициализации Postgres volume.

## Линт

```bash
uv run pre-commit run --all-files
```

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
uv run pytest tests/test_integration_mellophone.py -q
```

Матрица `tox` (Docker, Python `3.7-3.14`):

```bash
tox -p auto
```

## Coverage

```bash
uv run --with coverage --with pytest-cov pytest --cov=. --cov-report=term-missing -q
```

## Релизы

Релиз создается автоматически при `push` в `master` workflow'ом `CI Push`.

Условия для релиза:

- `Tests` завершился успешно.
- `Version Check` завершился успешно (версия в `pyproject.toml` увеличена по правилам `vuh`).

Как формируется релиз:

- версия берется из `vuh lv -q`;
- создается тег формата `v<version>` и GitHub Release;
- если тег уже существует, релиз пропускается.

## VS Code Tasks

В `.vscode/tasks.json` добавлены задачи:

- `docker:stop` - остановить `docker compose` и удалить volume (`docker compose down -v`).
- `docker:start` - поднять локальный стенд в фоне (`docker compose up -d`).
- `docker:restart` - последовательно выполнить `docker:stop` и `docker:start`.
- `uv:sync` - синхронизировать окружение и зависимости (`uv sync`).
- `uv:update` - обновить lock-файл зависимостей (`uv lock --upgrade`).
- `pytest:coverage` - запустить тесты с coverage в терминал.
- `pytest:coverage:html` - запустить тесты с coverage в терминал и HTML-отчет (`htmlcov/`).
- `tox:test` - запустить матрицу `tox` (`tox -p auto`).
- `lint:ruff` - проверить код через `ruff check .`.
- `lint:ruff:fix` - исправить автоисправляемые проблемы `ruff`.
- `lint:pre-commit` - прогнать `pre-commit` по всем файлам.
