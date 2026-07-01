# Secure Deploy Guard (SDG)

**Secure Deploy Guard** — это пре-деплойный сканер безопасности на базе AI-агентов.  
Он автоматически проверяет код на уязвимости перед выкаткой в продакшн, используя многоагентную оркестрацию, MCP-серверы, политики безопасности, песочницу, Human-in-the-Loop и команды Red/Blue/Green.

---

## 1. ДЛЯ ЧЕГО ЭТОТ ПРОЕКТ?

SDG решает проблему **пропущенных уязвимостей** в CI/CD пайплайне.  
Он делает четыре вещи:

| Задача | Как решает SDG |
|---|---|
| **SAST** (статический анализ) | Сканирует исходный код на SQL-инъекции, XSS, command injection, hardcoded secrets, buffer overflow |
| **SCA** (анализ зависимостей) | Проверяет `requirements.txt` на известные CVE-уязвимости |
| **Конфигурационный анализ** | Проверяет Dockerfile, docker-compose, Kubernetes-манифесты на ошибки безопасности |
| **Политики безопасности** | Structural Gate (роли/окружения) + Semantic Gate (LLM-проверка PII/политик) |
| **Adversarial-скан** | Red Team ищет instruction injection, скрытые команды, zero-width символы |
| **Human-in-the-Loop** | HITL-гейт запрашивает одобрение человека при низком Trust Score |
| **Trust Score** | 1.0 → 0.0 в зависимости от severity найденных уязвимостей |
| **LLM-Judge** | Оценка качества сканирования через OpenRouter/Gemini |
| **Green Team** | Авто-генерация исправлений для типовых уязвимостей |

---

## 2. АРХИТЕКТУРА

```
                    ┌───────────────────┐
                    │  OrchestratorAgent │
                    │  (ADK CustomAgent) │
                    └────────┬──────────┘
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
      ┌──────────┐    ┌──────────┐    ┌──────────────┐
      │SASTAgent │    │SCAAgent  │    │ ConfigAgent  │
      │(паттерны)│    │(CVE check)│   │(Docker/K8s)  │
      └──────────┘    └──────────┘    └──────────────┘
            │                │                │
            ▼                ▼                ▼
      ┌──────────────────────────────────────────┐
      │         Policy Engine Gate                │
      │  Structural (разрешено по роли/окружению) │
      │  Semantic (LLM-проверка PII/политик)      │
      └──────────────────────────────────────────┘
            │
            ▼
      ┌─────────────┐    ┌──────────┐
      │ Trust Score  │◄───│ Blue Team│ (аномалии)
      └─────────────┘    └──────────┘
            │
            ▼
      ┌──────────────┐
      │ HITL Approval│ (человек при score < 0.7)
      └──────────────┘
            │
            ▼
      ┌──────────┐    ┌──────────────┐
      │LLM Judge │    │ReportGenerator│
      └──────────┘    └──────────────┘
```

### Компоненты

| Компонент | Папка | Что делает |
|---|---|---|
| **ADK-агенты** | `sdg/adk/` | `OrchestratorAgent`, `LlmAgent`, `SequentialAgent`, `ParallelAgent`, `LoopAgent` |
| **Агенты сканирования** | `sdg/agents/` | `SASTAgent`, `SCAAgent`, `ConfigAgent` |
| **MCP-серверы** | `sdg/mcp_servers/` | bandit, semgrep, docker, secrets — по протоколу MCP |
| **Движок политик** | `sdg/policy_engine/` | Structural + Semantic gates, PII mask, context hygiene |
| **Песочница** | `sdg/sandbox/` | Эфемерный executor для изолированного запуска |
| **Оценка** | `sdg/evaluation/` | Trust Score, LLM Judge, Report Generator |
| **HITL** | `sdg/hitl/` | VibeDiff summary + Approval Gate |
| **Red/Blue/Green** | `sdg/red_blue_green/` | Red Team (adversarial), Blue Team (аномалии), Green Team (фиксы) |
| **Фронтенд** | `sdg/frontend/` | FastAPI + Bootstrap dark dashboard |
| **Навыки агентов** | `.agent/skills/` | 6 SKILL.md с YAML frontmatter |

### MCP-серверы (Model Context Protocol)

Каждый MCP-сервер — это独立ный процесс, общающийся через stdio по протоколу MCP:

```
MCP Client → [stdio] → MCP Server (bandit/semgrep/docker/secrets)
```

Серверы реализованы через `mcp.server.Server` с декораторами `@server.list_tools()` и `@server.call_tool()`.

---

## 3. КАК ПОЛЬЗОВАТЬСЯ

### 3.1. Установка

```bash
pip install -r requirements.txt
```

Зависимости: `bandit`, `pyyaml`, `pydantic`, `httpx`, `python-dotenv`, `mcp`, `fastapi`, `uvicorn`, `jinja2`, `anyio`.

### 3.2. Настройка

Скопируйте `sdg/.env.example` в `.env` и вставьте свой ключ:

```bash
cp sdg/.env.example .env
# отредактируйте .env
```

```env
OPENROUTER_API_KEY=sk-or-v1-ваш_ключ
OPENROUTER_MODEL=google/gemini-2.5-flash-lite-preview-05-2025
```

**Важно:** файл `.env` не должен попадать в git (уже добавлен в `.gitignore`).

### 3.3. CLI

```bash
# Полный скан
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
```

### 3.4. Веб-интерфейс

```bash
python3 -m uvicorn sdg.frontend.app:app --host 0.0.0.0 --port 8000
# Открыть http://localhost:8000
```

Дашборд (A2UI-ориентированный, без внешних CDN):
- Trust Score gauge и severity cards
- Форма запуска скана с выбором роли/окружения и auto-approve
- Таблица находок с фильтром
- Agent trajectory panel
- Policy gate log
- Red Team / Green Team панели
- Экспорт JSON / Markdown

### 3.5. Docker

```bash
docker-compose up --build
# Открыть http://localhost:8000
```

Контейнер запускается от непривилегированного пользователя `sdg`, имеет HEALTHCHECK, `.dockerignore` исключает `.env` и `.venv`.

### 3.6. Тесты

```bash
python3 -m pytest tests/ -v
# 81 тест, покрытие всех модулей + frontend + sandbox + repo hygiene
```

---

## 4. КАК ЭТО РАБОТАЕТ (ПОД КАПОТОМ)

### 4.1. Пайплайн сканирования

1. **OrchestratorAgent** получает `ScanTarget` (путь к проекту)
2. **StructuralGate** проверяет: разрешено ли действие `scan` для данной роли и окружения? Если действие требует одобрения — выбрасывает `ApprovalRequiredError`, и запрос идёт на HITL.
3. **SASTAgent** обходит все `.py`, `.js`, `.c`, `.cpp`, `.java`, `.go`, `.rb` файлы (исключая `.venv`, `node_modules`, `.git` и др.)
   - Для каждого файла применяются 11 regex-паттернов (SQLi, XSS, hardcoded secrets, command injection, SSRF, pickle, buffer overflow...)
4. **SCAAgent** читает `requirements.txt`, парсит версии пакетов, сверяет с Known Vulnerabilities
5. **ConfigAgent** проверяет Dockerfile (USER, HEALTHCHECK, latest tag), docker-compose (privileged mode), Kubernetes manifests (resource limits, securityContext)
6. **SemanticGate** отправляет critical findings в LLM для семантической проверки (PII, API keys, деструктивные операции). Если LLM не сконфигурирован — пропускается.
7. **TrustScoreCalculator** вычисляет оценку: `1.0 - (critical*0.3 + high*0.15 + medium*0.05 + low*0.01)`, clamped [0,1]
8. **BlueTeam** проверяет на аномалии (слишком много агентов, спайк critical)
9. **ApprovalGate** — если требуется approval, score < 0.7 или есть critical, запрашивает одобрение человека
10. **LLMJudge** оценивает качество скана (1-5), используя JSON mode при наличии API ключа
11. **ReportGenerator** собирает отчёт (Markdown + JSON)

### 4.2. Trust Score

| Severity | Вычет |
|---|---|
| CRITICAL | -0.30 |
| HIGH | -0.15 |
| MEDIUM | -0.05 |
| LOW | -0.01 |

Скан считается **пройденным** (`passed: true`), если score >= 0.5 и нет critical findings.

### 4.3. Agent Skills (`.agent/skills/`)

6 навыков агентов, каждый с SKILL.md и YAML frontmatter:

| Навык | Тип | Описание |
|---|---|---|
| `security-sast` | read-only | SAST-скан через Bandit + regex-паттерны |
| `security-sca` | read-only | Аудит CVE-уязвимостей в зависимостях |
| `security-config` | read-only | Проверка Docker/K8s/Terraform конфигов |
| `red-team` | read-only | Поиск adversarial-паттернов |
| `blue-team` | read-only | Мониторинг аномалий |
| `green-team` | draft-only | Авто-генерация патчей |

### 4.4. MCP-серверы

| Сервер | Инструмент | Описание |
|---|---|---|
| `bandit-scanner` | `bandit_scan` | Запускает Bandit CLI, парсит JSON-результат |
| `semgrep-scanner` | `semgrep_scan` | Regex-based SAST через `sdg.utils.patterns` |
| `docker-scanner` | `scan_dockerfile` | 7 правил для Dockerfile + 3 для compose |
| `secret-detector` | `scan_secrets` | 12 паттернов для разных типов секретов (AWS, GitHub, JWT, SSH keys...) |

### 4.5. Формат находки (Finding)

```python
@dataclass
class Finding:
    severity: Severity       # CRITICAL | HIGH | MEDIUM | LOW
    category: ScanCategory   # sql_injection | xss | hardcoded_secret | ...
    message: str             # Описание проблемы
    file_path: str           # Путь к файлу
    line_number: int | None  # Номер строки
    snippet: str | None      # Фрагмент кода
    recommendation: str | None  # Рекомендация по исправлению
```

---

## 5. ПРИМЕР РАБОТЫ

```bash
$ python3 -m sdg.cli scan . --auto-approve

Session: abb0a57c-1234-5678-9abc-def012345678
Trust Score: 0.0
Passed: False
Findings: 7
  sast: 4 findings
  sca: 0 findings
  config_agent: 3 findings
Judge Score: 3
Quality: fair
Report saved: /home/user/sdg-report.md
```

---

## 6. БЕЗОПАСНОСТЬ

- Секреты хранятся в `.env`, который исключён из git
- Semantic Gate работает по принципу fail-closed при реальных ошибках LLM; при отсутствии API ключа пропускается
- Structural Gate поддерживает `required_approval` с корректной маршрутизацией на HITL
- Frontend использует только безопасный DOM-рендеринг (`textContent`/`createElement`), никакого `innerHTML` с пользовательскими данными
- Все статические ассеты Bootstrap загружаются локально (нет внешних CDN)
- Docker-контейнер запускается от непривилегированного пользователя
- Sandbox executor валидирует пути и запрещает shell-строки
- Соответствие 7-pillar архитектуре описано в `docs/security/7-pillars-mapping.md`

---

## 7. ТЕХНОЛОГИИ

- **Python 3.14** — язык реализации
- **OpenRouter API** — LLM-запросы (Gemini 2.5 Flash Lite)
- **FastAPI + Starlette** — веб-фреймворк
- **MCP SDK (1.28+)** — Model Context Protocol для серверов
- **Jinja2** — шаблонизатор
- **Bootstrap 5 (dark)** — UI
- **httpx** — HTTP-клиент для LLM
- **pytest** — тестирование
- **Bandit** — SAST-сканер (опционально)

---

## 8. СТРУКТУРА ПРОЕКТА

```
.
├── .agent/skills/               # Навыки агентов (6 шт.)
│   ├── security-sast/SKILL.md
│   ├── security-sca/SKILL.md
│   ├── security-config/SKILL.md
│   ├── red-team/SKILL.md
│   ├── blue-team/SKILL.md
│   └── green-team/SKILL.md
├── sdg/
│   ├── adk/                     # ADK-агенты (оркестрация)
│   ├── agents/                  # Агенты сканирования
│   ├── mcp_servers/             # MCP-серверы (4 шт.)
│   ├── orchestrator/            # Сессия Orchestrator
│   ├── policy_engine/           # Политики безопасности
│   ├── sandbox/                 # Песочница
│   ├── evaluation/              # Оценка (Trust, Judge, Report)
│   ├── hitl/                    # Human-in-the-Loop
│   ├── red_blue_green/          # Команды безопасности
│   ├── frontend/                # Веб-интерфейс
│   ├── utils/                   # Утилиты (LLM, паттерны)
│   ├── config.py / config.yaml  # Конфигурация
│   └── models.py                # Модели данных
├── tests/                       # 81 тест
├── Dockerfile / docker-compose.yml
├── .dockerignore
├── .gitignore
└── requirements.txt
```
