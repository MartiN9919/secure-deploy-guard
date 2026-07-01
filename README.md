# Secure Deploy Guard (SDG)

**Secure Deploy Guard** — это пре-деплойный сканер безопасности на базе AI-агентов.  
Он автоматически проверяет код на уязвимости перед выкаткой в продакшн, используя многоагентную оркестрацию, MCP-серверы, политики безопасности, песочницу, Human-in-the-Loop и команды Red/Blue/Green.

---

## 1. Для чего этот проект?

В эпоху vibe coding и AI-генерации кода скорость разработки выросла на порядок, но вместе с ней выросла и скорость появления уязвимостей. SDG решает проблему **пропущенных уязвимостей** в CI/CD пайплайне, проверяя код до момента деплоя.

### Ключевые задачи, которые решает SDG

| Задача | Как решает SDG |
|---|---|
| **SAST** (статический анализ) | Сканирует исходный код на SQL-инъекции, XSS, command injection, hardcoded secrets, buffer overflow, path traversal, SSRF, insecure deserialization |
| **SCA** (анализ зависимостей) | Проверяет `requirements.txt` на известные CVE-уязвимости с обогащением через CVE Intelligence Gathering (NVD, MITRE, OSV) |
| **Конфигурационный анализ** | Проверяет Dockerfile, docker-compose, Kubernetes-манифесты на ошибки безопасности |
| **Политики безопасности** | Structural Gate (роли/окружения) + Semantic Gate (LLM-проверка PII/политик) |
| **Adversarial-скан** | Red Team ищет instruction injection, скрытые команды, zero-width символы |
| **Human-in-the-Loop** | HITL-гейт запрашивает одобрение человека при низком Trust Score или критических находках |
| **Trust Score** | 1.0 → 0.0 в зависимости от severity найденных уязвимостей |
| **LLM-Judge** | Оценка качества сканирования через OpenRouter/Gemini |
| **Green Team** | Авто-генерация исправлений для типовых уязвимостей |
| **Отчётность** | JSON + Markdown + CLI table + веб-дашборд |

### Целевая аудитория
- Разработчики, которые хотят проверить код перед коммитом/PR
- DevOps-инженеры, которые встраивают сканирование в CI/CD
- Security-инженеры, которым нужен лёгкий пре-деплойный сканер
- Команды, практикующие vibe coding / agentic engineering, которым нужна дисциплина и guardrails

---

## 2. Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                       Developer / CI/CD                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    OrchestratorAgent                         │
│              (ADK Custom Agent pattern)                      │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
       ┌───────▼───────┐              ┌────────▼──────┐
       │ Policy Server  │              │  Sub-Agents   │
       │ Structural +   │              │  SAST / SCA   │
       │ Semantic gates │              │  Config       │
       └───────┬───────┘              └───────┬───────┘
               │                              │
               ▼                              ▼
       ┌───────────────┐              ┌───────────────┐
       │  HITL Gate    │              │  Findings     │
       │  Approval     │              │  Collection   │
       └───────┬───────┘              └───────┬───────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
              ┌───────────────────────────────┐
              │  Evaluation Engine            │
              │  Trust Score + LLM Judge      │
              └───────────────┬───────────────┘
                              ▼
              ┌───────────────────────────────┐
              │  Report Generator             │
              │  Markdown / JSON / Dashboard  │
              └───────────────────────────────┘
```

### Поток выполнения сканирования

1. **OrchestratorAgent** получает `ScanTarget` (путь к проекту), роль и окружение
2. **StructuralGate** проверяет: разрешено ли действие `scan` для данной роли и окружения?
   - Если действие требует одобрения — выбрасывает `ApprovalRequiredError`, и запрос идёт на HITL
   - Если действие запрещено — скан немедленно блокируется
3. **SASTAgent** обходит все `.py`, `.js`, `.c`, `.cpp`, `.java`, `.go`, `.rb` файлы (исключая `.venv`, `node_modules`, `.git` и др.) и применяет 11 regex-паттернов
4. **SCAAgent** читает `requirements.txt`, парсит версии пакетов, сверяет с базой известных уязвимостей и обогащает CVE-информацией через `CVEIntelligenceGatherer`
5. **ConfigAgent** проверяет Dockerfile, docker-compose, Kubernetes manifests
6. **SemanticGate** отправляет critical findings в LLM для семантической проверки (PII, API keys, деструктивные операции). Если LLM не сконфигурирован — пропускается
7. **TrustScoreCalculator** вычисляет оценку: `1.0 - (critical*0.3 + high*0.15 + medium*0.05 + low*0.01)`, clamped [0,1]
8. **BlueTeam** проверяет на аномалии (слишком много агентов, спайк critical)
9. **ApprovalGate** — если требуется approval, score < 0.7 или есть critical, запрашивает одобрение человека
10. **LLMJudge** оценивает качество скана (1-5), используя JSON mode при наличии API ключа
11. **ReportGenerator** собирает отчёт (Markdown + JSON)

---

## 3. Компоненты системы

### 3.1. Агенты сканирования (`sdg/agents/`)

| Агент | Файл | Назначение |
|---|---|---|
| **SASTAgent** | `sast_agent.py` | Статический анализ кода по regex-паттернам |
| **SCAAgent** | `sca_agent.py` | Анализ зависимостей requirements.txt + CVE Intelligence Gathering |
| **ConfigAgent** | `config_agent.py` | Проверка Docker, docker-compose, Kubernetes конфигов |

### 3.2. MCP-серверы (`sdg/mcp_servers/`)

MCP (Model Context Protocol) — это "USB-C для AI-инструментов". Каждый MCP-сервер — это независимый процесс, общающийся через stdio по протоколу MCP.

| Сервер | Инструмент | Описание |
|---|---|---|
| `bandit-scanner` | `bandit_scan` | Запускает Bandit CLI, парсит JSON-результат |
| `semgrep-scanner` | `semgrep_scan` | Regex-based SAST через `sdg.utils.patterns` |
| `docker-scanner` | `scan_dockerfile` | 7 правил для Dockerfile + 3 для compose |
| `secret-detector` | `scan_secrets` | 12 паттернов для разных типов секретов |

### 3.3. Движок политик (`sdg/policy_engine/`)

| Компонент | Назначение |
|---|---|
| **StructuralGate** | Быстрые бинарные проверки по ролям и окружениям |
| **SemanticGate** | LLM-проверка интента и содержимого на PII/политики |
| **PIIMask** | Маскирование email, API keys, IP, SSN в тексте |
| **ContextHygiene** | Подстановка `[[VAR]]` placeholder'ов и рекурсивная санитизация аргументов |

### 3.4. CVE Intelligence Gathering (`sdg/cve_intelligence/`)

Реализация готового skill'а [CVE Intelligence Gathering](https://mcpmarket.com/tools/skills/cve-intelligence-gathering) через прямые HTTP API:

| Источник | API | Что предоставляет |
|---|---|---|
| **NVD** | `services.nvd.nist.gov` | CVSS score, severity, CWE, affected CPE |
| **MITRE** | `cveawg.mitre.org` | Официальное описание, ссылки |
| **OSV** | `api.osv.dev` | GHSA, Go vulndb, PyPI advisories, affected versions |

Использование:

```bash
python3 -m sdg.cve_intelligence.cli CVE-2023-46695
```

### 3.5. Red / Blue / Green Teams (`sdg/red_blue_green/`)

| Команда | Файл | Назначение |
|---|---|---|
| **Red Team** | `red_team.py` | Поиск adversarial-паттернов (instruction injection, hidden commands, zero-width chars) |
| **Blue Team** | `blue_team.py` | Аналитика аномалий (количество агентов, находок, critical spike) |
| **Green Team** | `green_team.py` | Авто-генерация исправлений для SQLi, command injection, hardcoded secrets |

### 3.6. Фронтенд (`sdg/frontend/`)

FastAPI-приложение с Jinja2-шаблонами и локальными Bootstrap 5 ассетами.

**Возможности дашборда:**
- Trust Score gauge с цветовой индикацией
- Карточки статистики по severity (Critical / High / Medium / Low)
- Форма запуска скана с выбором роли, окружения и auto-approve
- Таблица находок с фильтром по тексту
- Agent trajectory panel — какие агенты выполнялись
- Policy log — решения structural/semantic gates
- Red Team scan
- Green Team — suggested fixes
- Экспорт результатов в JSON и Markdown

**Безопасность фронтенда:**
- Весь динамический контент рендерится через `textContent` / `createElement`
- Никакого `innerHTML` с пользовательскими данными
- Все ассеты Bootstrap загружаются локально, нет внешних CDN

---

## 4. Установка и настройка

### 4.1. Системные требования

- Python 3.14+
- Linux, macOS или Windows с WSL
- Docker (опционально, для контейнерного запуска)
- Интернет (опционально, только для CVE Intelligence Gathering и LLM-оценки)

### 4.2. Установка зависимостей

```bash
pip install -r requirements.txt
```

Основные зависимости:
- `bandit` — SAST-сканер
- `pyyaml` — YAML-парсер
- `pydantic` — валидация данных
- `httpx` — HTTP-клиент
- `python-dotenv` — загрузка `.env`
- `mcp` — MCP SDK
- `fastapi`, `uvicorn`, `jinja2`, `anyio` — веб-фреймворк
- `pytest`, `pytest-cov` — тестирование

### 4.3. Настройка окружения

Скопируйте пример и вставьте свой OpenRouter API ключ:

```bash
cp sdg/.env.example .env
# отредактируйте .env
```

```env
OPENROUTER_API_KEY=sk-or-v1-ваш_ключ
OPENROUTER_MODEL=google/gemini-2.5-flash-lite-preview-05-2025
```

**Важно:** `.env` добавлен в `.gitignore` и не должен попадать в репозиторий. Если ключ был случайно закоммичен — немедленно отзовите его в OpenRouter и создайте новый.

### 4.4. Запуск тестов

```bash
python3 -m pytest tests/ -v
# 86 тестов должны пройти
```

---

## 5. Использование

### 5.1. CLI

```bash
# Полный скан с авто-одобрением (для CI)
python3 -m sdg.cli scan ./my-project --auto-approve

# Скан с выбором роли и окружения
python3 -m sdg.cli scan ./my-project --role admin --environment production

# JSON-вывод
python3 -m sdg.cli scan . --format json

# Сохранить отчёт в файл
python3 -m sdg.cli scan . --output report.md

# Red Team scan (adversarial)
python3 -m sdg.cli red-team ./my-project

# Green Team (авто-фикс из findings)
python3 -m sdg.cli green-team findings.json

# CVE Intelligence Gathering
python3 -m sdg.cve_intelligence.cli CVE-2023-46695
```

### 5.2. Веб-интерфейс

```bash
python3 -m uvicorn sdg.frontend.app:app --host 0.0.0.0 --port 8000
```

Откройте в браузере: http://localhost:8000

**Как пользоваться фронтендом:**

1. На главной странице введите путь к сканируемому проекту (по умолчанию `.`)
2. Выберите роль (`developer`, `admin`, `reviewer`, `viewer`) и окружение (`local`, `ci`, `staging`, `production`)
3. Опционально включите **Auto-approve**, чтобы пропустить HITL-гейт
4. Нажмите **Run Full Scan**
5. После завершения появятся:
   - Trust Score и pass/fail статус
   - Карточки с количеством находок по severity
   - Таблица находок с фильтром
   - Agent trajectory и policy log
   - Raw results (полный JSON)
6. Для adversarial-скана нажмите **Red Team Scan**
7. Для экспорта используйте кнопки **JSON** и **Markdown**

### 5.3. Docker

```bash
# Сборка и запуск
docker-compose up --build

# Только сборка образа
docker build -t sdg .

# Запуск контейнера
docker run -p 8000:8000 --env-file .env sdg
```

Контейнер:
- Запускается от непривилегированного пользователя `sdg`
- Имеет HEALTHCHECK
- Не включает `.env`, `.venv`, тесты и git-историю (`.dockerignore`)

---

## 6. Работа в PyCharm

### 6.1. Открытие проекта

1. Откройте PyCharm
2. `File` → `Open` → выберите папку `/home/dev/PycharmProjects/PythonProject3`
3. PyCharm автоматически распознает Python 3.14 и структуру проекта

### 6.2. Настройка интерпретатора

1. `File` → `Settings` → `Project: PythonProject3` → `Python Interpreter`
2. Выберите системный Python 3.14 или создайте виртуальное окружение
3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

### 6.3. Запуск фронтенда из PyCharm

1. Создайте Run Configuration:
   - `Run` → `Edit Configurations` → `+` → `Python`
   - **Script path:** `uvicorn`
   - **Parameters:** `sdg.frontend.app:app --host 0.0.0.0 --port 8000 --reload`
   - **Working directory:** `/home/dev/PycharmProjects/PythonProject3`
2. Нажмите `Run` или `Debug`
3. Откройте http://localhost:8000 в браузере

### 6.4. Запуск CLI из PyCharm

1. `Run` → `Edit Configurations` → `+` → `Python`
2. **Module name:** `sdg.cli`
3. **Parameters:** `scan . --auto-approve --format json`
4. **Working directory:** `/home/dev/PycharmProjects/PythonProject3`

### 6.5. Запуск тестов

В терминале PyCharm:

```bash
python3 -m pytest tests/ -v
```

Или через интерфейс: правый клик на папке `tests` → `Run pytest in tests`.

---

## 7. Развёртывание на GitHub

### 7.1. Подготовка репозитория

Проект уже инициализирован как git-репозиторий. Основная ветка — `main`. Новая функциональность (CVE Intelligence Gathering) разрабатывалась в git worktree:

```
/home/dev/PycharmProjects/PythonProject3              # main ветка
/home/dev/PycharmProjects/PythonProject3/.worktrees/cve-intelligence  # feature/cve-intelligence
```

### 7.2. Завершение работы в worktree

Перейдите в worktree, закоммитьте изменения:

```bash
cd /home/dev/PycharmProjects/PythonProject3/.worktrees/cve-intelligence
git add .
git commit -m "feat: add CVE Intelligence Gathering integration"
```

### 7.3. Слияние в main

```bash
cd /home/dev/PycharmProjects/PythonProject3
git checkout main
git merge feature/cve-intelligence
```

### 7.4. Публикация на GitHub

```bash
# Создайте репозиторий на GitHub через веб-интерфейс, затем:
git remote add origin https://github.com/ВАШ_ЮЗЕРНЕЙМ/secure-deploy-guard.git
git branch -M main
git push -u origin main

# Для публикации feature-ветки:
git checkout feature/cve-intelligence
git push -u origin feature/cve-intelligence
```

### 7.5. CI/CD (GitHub Actions)

Пример workflow находится в `.github/workflows/`. Он запускает тесты при каждом push и pull request:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.14'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
```

---

## 8. Безопасность

- Секреты хранятся в `.env`, который исключён из git
- Semantic Gate работает по принципу fail-closed при реальных ошибках LLM; при отсутствии API ключа пропускается
- Structural Gate поддерживает `required_approval` с корректной маршрутизацией на HITL
- Frontend использует только безопасный DOM-рендеринг (`textContent`/`createElement`), никакого `innerHTML` с пользовательскими данными
- Все статические ассеты Bootstrap загружаются локально (нет внешних CDN)
- Docker-контейнер запускается от непривилегированного пользователя
- Sandbox executor валидирует пути через `Path.relative_to` и запрещает shell-строки
- CVE-запросы выполняются с таймаутом и не блокируют основной поток
- Соответствие 7-pillar архитектуре описано в `docs/security/7-pillars-mapping.md`

---

## 9. Trust Score

| Severity | Вычет |
|---|---|
| CRITICAL | -0.30 |
| HIGH | -0.15 |
| MEDIUM | -0.05 |
| LOW | -0.01 |

Скан считается **пройденным** (`passed: true`), если `trust_score >= 0.5` и нет critical findings.

---

## 10. Agent Skills (`.agent/skills/`)

Каждый skill — это папка с `SKILL.md` и YAML frontmatter, соответствующая canonical формату из whitepaper "Agent Skills":

| Навык | Тип | Описание |
|---|---|---|
| `security-sast` | read-only | SAST-скан через Bandit + regex-паттерны |
| `security-sca` | read-only | Аудит CVE-уязвимостей в зависимостях |
| `security-config` | read-only | Проверка Docker/K8s/Terraform конфигов |
| `red-team` | read-only | Поиск adversarial-паттернов |
| `blue-team` | read-only | Мониторинг аномалий |
| `green-team` | draft-only | Авто-генерация патчей |

---

## 11. Структура проекта

```
.
├── .agent/skills/               # Навыки агентов (6 шт.)
│   ├── security-sast/SKILL.md
│   ├── security-sca/SKILL.md
│   ├── security-config/SKILL.md
│   ├── red-team/SKILL.md
│   ├── blue-team/SKILL.md
│   └── green-team/SKILL.md
├── docs/
│   ├── security/7-pillars-mapping.md
│   └── superpowers/specs/
│       └── 2026-07-01-sdg-frontend-compliance-redesign.md
├── sdg/
│   ├── adk/                     # ADK-агенты (оркестрация)
│   ├── agents/                  # Агенты сканирования
│   ├── cve_intelligence/        # CVE Intelligence Gathering
│   ├── mcp_servers/             # MCP-серверы (4 шт.)
│   ├── orchestrator/            # Сессия Orchestrator
│   ├── policy_engine/           # Политики безопасности
│   ├── sandbox/                 # Песочница
│   ├── evaluation/              # Оценка (Trust, Judge, Report)
│   ├── hitl/                    # Human-in-the-Loop
│   ├── red_blue_green/          # Команды безопасности
│   ├── frontend/                # Веб-интерфейс
│   │   ├── app.py
│   │   ├── templates/
│   │   │   └── dashboard.html
│   │   └── static/
│   │       ├── bootstrap.min.css
│   │       ├── bootstrap.bundle.min.js
│   │       ├── sdg-dashboard.css
│   │       └── sdg-dashboard.js
│   ├── utils/                   # Утилиты (LLM, паттерны)
│   ├── config.py / config.yaml  # Конфигурация
│   └── models.py                # Модели данных
├── tests/                       # 86 тестов
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
└── requirements.txt
```

---

## 12. Технологии

- **Python 3.14** — язык реализации
- **OpenRouter API** — LLM-запросы (Gemini 2.5 Flash Lite)
- **FastAPI + Starlette + Uvicorn** — веб-фреймворк
- **MCP SDK (1.28+)** — Model Context Protocol для серверов
- **Jinja2** — шаблонизатор
- **Bootstrap 5 (dark)** — UI
- **httpx** — HTTP-клиент для LLM и CVE API
- **pytest** — тестирование
- **Bandit** — SAST-сканер (опционально)

---

## 13. Troubleshooting

### `ModuleNotFoundError: No module named 'sdg'`

Запускайте команды из корня проекта `/home/dev/PycharmProjects/PythonProject3`, а не из подпапок.

### LLM Judge возвращает "judge skipped: no API key"

Это нормально при отсутствии `OPENROUTER_API_KEY`. Скан продолжит работу. Для включения LLM-оценки создайте `.env` с ключом.

### Semantic policy violation без API ключа

Semantic Gate пропускается, если LLM не сконфигурирован. При наличии ключа он выполняет реальную проверку.

### Docker образ не собирается

Убедитесь, что у вас есть `.env` файл (можно пустой) рядом с `docker-compose.yml`, или закомментируйте строку `env_file` в `docker-compose.yml`.

### Фронтенд не загружает статику

Проверьте, что файлы `bootstrap.min.css`, `bootstrap.bundle.min.js`, `sdg-dashboard.css`, `sdg-dashboard.js` находятся в `sdg/frontend/static/`.

### CVE Intelligence Gathering медленный

По умолчанию таймаут 10 секунд на источник. Можно изменить в `config.yaml`:

```yaml
enable_cve_intelligence: true
cve_intelligence_timeout: 5.0
```

Или отключить:

```yaml
enable_cve_intelligence: false
```

---

## 14. Лицензия

MIT
