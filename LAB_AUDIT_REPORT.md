# 🔬 АУДИТ ПРОЕКТА: Lab Vault

**Дата:** 2026-06-09
**Аудитор:** Главный Лаборант AI (Штрейкбрехер)
**Объём:** 2840 строк main.go + 3 CLI + 4 файла тестов (~1500 строк)
**Метод:** Полное чтение исходного кода, grep-анализ, проверка тестового покрытия

---

## 1. ДНК Проекта и Сильные Стороны

### Суть
Lab Vault — **секретный менеджер для AI-агентов** Лаборатории. Решает задачу безопасной передачи секретов (API keys, пароли, токены) агентам без записи на диск в открытом виде. Архитектура: секреты живут в RAM, на диске — только зашифрованный снапшот (ChaCha20-Poly1305).

### Стек
Go 1.22, ChaCha20-Poly1305 (x/crypto), Argon2id KDF, Telegram Bot API v5, YAML config, HTTP API

### Архитектурные слои
```
ЗавЛаб → TG Bot → POST /secrets → Store (RAM) → snapshot.enc (ChaCha20-Poly1305)
                                   ↓
Лаборант → lab-vault-env → GET /secrets/:project → eval $(export ...)
```

### Ключевые сущности
- **Store** — потокобезопасное хранилище секретов с версионированием и аудитом
- **Server** — HTTP API с rate limiter, lease management, one-time tokens
- **Bot** — Telegram Bot с FSM-диалогом для управления секретами
- **Config** — YAML-конфигурация с миграцией форматов и подгрузкой из env vars
- **agentRegistry** — реестр автономных агентов с heartbeat и TTL
- **leaseRegistry** — аренда секретов на ограниченное время (1h по умолчанию)

### Сильные стороны

**1. Криптография — сделано правильно (`main.go#L841-L880`)**
ChaCha20-Poly1305 с Argon2id KDF, случайный salt и nonce per-write. Шифротекст содержит [salt(16)][nonce(12)][ciphertext]. Атомарная запись через tmp+rename. Отличная реализация.

**2. Версионирование секретов с rollback (`main.go#L631-L680`)**
Полная история версий, автоматический инкремент, возможность отката. При откате старая версия уходит в историю — потери данных нет. Audit-запись при каждом действии.

**3. Token expiry + миграция Legacy (`main.go#L370-L420`)**
Плавная митация `Agents` (token→project) в `AgentTokens` (token→{project, created, expires}). Agent-токены с TTL 720ч (30 дней). API backwards-compatible.

**4. Тестирование — 1500+ строк, 70+ тестов**
Fuzzing-тесты шифрования (corrupted ciphertext, wrong password, short inputs), concurrency-тесты (100 goroutines), race condition проверки, nonce uniqueness, timing attack awareness, path traversal. Это уровень security-aware тестирования.

---

## 2. Диагноз: Найденные Проблемы

| Серьёзность | Файл#строки | Категория | Симптом и Причина | Доказательство |
|-------------|-------------|-----------|-------------------|----------------|
| **HIGH** | `main.go#L1690-L1700` | **Security: Timing Attack** | `isAdmin()` использует `hmac.Equal` для SHA-256 хешей — что правильно, НО в тесте `TestIsAdminTiming` указано что Go `==` для строк НЕ константное время. Сравнение длин через `==` утекает по таймингу. `hmac.Equal` защищает от content timing, но НЕ от length timing — переменные `adminHash` и `tokenHash` разной длины (при разной длине входного токена). | [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html) |
| **HIGH** | `main.go#L1648-L1662` | **Security: One-Time Token не инвалидируется после использования** | `handleOneTimeAccess` отдаёт значение секрета при валидном токене, но **НЕ помечает токен как revoked**. Токен остаётся действительным до истечения TTL (1 час). Повторный запрос тем же токеном снова вернёт секрет. | [OWASP: Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication) |
| **HIGH** | `main.go#L701` | **Race Condition / Goroutine Leak** | `go s.auditToFile(entry)` — запись в файл вызывается в отдельной goroutine ПОСЛЕ освобождения `auditMu`. Но при shutdown (`main()`) файл **никогда не закрывается** (`s.auditFile` не имеет `Close()`). Goroutine может висеть в открытом дескрипторе. При каждом audit-событии — новая goroutine. | [Go: Goroutine leak by unclosed file handle](https://go.dev/doc/articles/race_detector) |
| **HIGH** | `main.go#L1504-L1510` | **Security: Rate Limiter Bypass для критических эндпоинтов** | `handleOneTimeAccess` (L1576-L1610) и `handleMetrics` (L1613+) вызываются **БЕЗ rate limiter middleware**. `/metrics` публичен — ок. Но `/access/:token` — это эндпоинт, отдающий секреты в открытом виде, без rate limiter и без авторизации. Атакующий может брутфорсить токены. | [OWASP: Rate Limiting](https://owasp.org/www-project-api-security/) |
| **HIGH** | `config.yaml` (репозиторий) | **Security: Хардкод секретов** | `tg_bot_token`, `admin_token`, и все `agents`/`one_time_tokens` хранятся в **открытом тексте** в файле, который попал в **.gitignore с опозданием** (сейчас в .gitignore только `*.local.yaml`). Файл `config.yaml` — фактически секретоноситель, попадающий в git. | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| **MEDIUM** | `main.go#L2284-L2295` | **Race Condition: agentRegistry без блокировки** | В FSM-хендлере бота (`stateAgentWaitingName`) — **прямой доступ** к `b.agentRegistry.agents` через `b.agentRegistry.mu.Lock()` ВНЕ штатных методов `register()`. Это оборачивает внутренний mutex вручную. Но метод `validateToken()` использует `sync.RWMutex.RLock()` — одновременный вызов `list()` с `RLock` и прямой `Lock` может привести к deadlock при высокой конкурентности. | [Go Memory Model](https://go.dev/ref/mem) |
| **MEDIUM** | `main.go#L710-L715` | **Performance: Unbounded audit-массив + Goroutine per entry** | При каждом audit-событии: 1) копирование всего `auditLog` слайса (`AuditLog()`), 2) новая goroutine для файловой записи. 10,000 событий = 10,000 goroutines в пике + раздувание слайса (хотя есть обрезание до maxAuditLog). | Go best practice: reuse buffers, worker pool |
| **MEDIUM** | `main.go#L590-L603` | **Performance: N+1 при GetByProject** | `GetByProject(project)` итерирует ВСЕ секреты и проверяет `vs.Projects`. С ростом числа секретов (1000+) это O(n) на каждый запрос. Нет индекса по проекту. | Database normalization: inverted index |
| **MEDIUM** | `cmd/lab-vault-cli/main.go#L103-L108` | **Bug: Type assertion без проверки** | `name := s["name"].(string)` — если API вернёт unexpected JSON, это **panic**. Всего 3 type assertions в `cmdList`, `cmdAudit`, `cmdProjectSecretsInline` и других местах. | Go best practice: check-ok pattern |
| **MEDIUM** | `main.go#L1431-L1435` | **Security: XSS в Dashboard** | HTML-dashboard (`handleDashboard`) экранирует через `escapeHTML`, НО `escapeHTML` не экранирует `"` в значениях HTML-атрибутов. Добро, но значения в таблице (ячейки `<td>`) — ок. Однако URL в `fmt.Fprintf` с `%s` без `html.EscapeString` — path traversal в URL-пути. | [OWASP: XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html) |
| **MEDIUM** | `main.go#L1295-L1310` | **Logic: GET /secrets/ (список) для агента возвращает ВСЕ секреты, не только проекта** | `handleSecrets(GET)`: агент получает `s.store.List()` если `!isAdmin`. Это значит что **любой агент с валидным токеном видит имена ВСЕХ секретов**, даже не из своего проекта. Leak metadata. | [OWASP: Information Exposure](https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration) |
| **LOW** | `cmd/lab-vault-cli/main.go#L140` | **Bug: cmdGet читает ВСЕ секреты чтобы найти один** | `cmdGet` делает `GET /secrets` (получает полный список) и затем ищет по имени в коде. Если секретов 1000 — все передаются по сети. | Performance: GET /secret/:name доступен |
| **LOW** | `main.go#L30-L35` | **Code Quality: Unused `context` import** | В `auditToFile` — `go s.auditToFile(entry)` без возможности отмены через `context`. Graceful shutdown не дожидается завершения audit-горутин. | Go idiomatic: context-aware goroutines |
| **LOW** | `main.go#L590-L595` | **Logic: `count` после `s.mu.RLock()`** | В `GetByProject` — `count := len(result)` вызывается ВНУТРИ блокировки, хотя `result` уже может быть собран и подсчёт можно вынести для снижения времени блокировки. | Lock-free counting pattern |
| **LOW** | `cmd/lab-vault-cli/main.go#L25` | **Code Quality: Magic number** | `version = "1.0.0"` вместо `ldflags -X` для автоматизации. При каждом релизе — ручное обновление. | Go best practice: build-time variables |

---

## 3. План Лечения (Бэклог)

| Приоритет | Действие | Время | Файлы | Зависимости |
|-----------|----------|-------|-------|-------------|
| **HIGH** | Инвалидация one-time токена после первого использования: добавить `Revoked = true` и проверку в `handleOneTimeAccess` | 15м | `main.go` | Нет |
| **HIGH** | Закрытие `auditFile` при shutdown + flush перед выходом: добавить `auditMu`-protected `Close()`, `Flush()` + `sync.WaitGroup` для горутин | 1ч | `main.go` | Нет |
| **HIGH** | Добавить rate limiter и rate-limit-aware middleware на `/access/:token` | 15м | `main.go`, `cmd/` | rate limiter |
| **HIGH** | Исправить GET /secrets для агентов: возвращать только секреты проекта агента, а не все | 1ч | `main.go` | Изменение semantics API |
| **HIGH** | Нарушение принципа минимальных привилегий: `/metrics` без auth — ок, но `/access/` (отдающий секреты) — **нет**. Немедленно исправить. | 15м | `main.go` | Нет |
| **MEDIUM** | Попытка фикса race condition в `agentRegistry`: убрать прямой доступ к `agents`, обернуть в `Register()` или `AddDirect()` | 1ч | `main.go` | Тесты конкурентности |
| **MEDIUM** | Исправить type assertions в CLI: добавить `ok` проверки ко всем `.(string)`, `.([]interface{})` | 30м | `cmd/lab-vault-cli/main.go` | Тесты |
| **MEDIUM** | Добавить инвертированный индекс `project→secretNames` в `Store` для O(1)-lookup вместо O(n) | 4ч | `main.go` | Миграция snapshot формата |
| **MEDIUM** | Консолидация аудита: worker pool для `auditToFile` вместо goroutine-per-event | 1ч | `main.go` | goroutine leak fix |
| **LOW** | Миграция `version` CLI на `ldflags -X main.version=...` | 15м | `cmd/lab-vault-cli/main.go`, `Makefile` | Нет |
| **LOW** | Исправить `cmdGet`: использовать `GET /secret/:name` напрямую | 15м | `cmd/lab-vault-cli/main.go` | Нет |
| **LOW** | Добавить экранирование `"` в `escapeHTML` для полной XSS-защиты | 15м | `main.go` | Dashboard UI |
| **LOW** | Убрать unused `context` (если не используется) или добавить context-aware goroutines | 15м | `main.go` | audit refactor |

---

## 4. Эволюция: Идеи для Развития

### 4.1. Secret Templating & Rotation Engine
**Суть:** Механизм автоматической ротации секретов с уведомлением агентов. Когда секрет истекает (или TTL на секрет, не только токен) — генерация нового значения, сохранение с новой версией, отправка уведомления через бота лаборанту. Затронет: `Store` (добавить `SecretTTL`, `RotationPolicy`), `Bot` (команда `/rotate`), `API` (POST /secrets/:name/rotate). **Почему:** Ручная ротация = забытые пароли. В проекте отличная база (версионирование, audit), не хватает только TTL на сам секрет.

### 4.2. gRPC API + mTLS для Production-Grade Security
**Суть:** Параллельно REST API запустить gRPC endpoint с mutual TLS для агентов. mTLS обеспечивает аутентификацию на уровне соединения, а не токена. Это элиминирует risk утечки токена через логи/expired tokens. Затронет: новый `cmd/lab-vault-rpc/`, protobuf definitions, сертификаты агентов. **Почему:** Один из слабых мест — bearer-токены в HTTP-заголовках. mTLS = zero-trust подход.

### 4.3. HA Snapshot с Remote Storage Backend
**Суть:** Текущий snapshot — локальный файл. Добавить поддержку S3/MinIO/ftp для снапшота. При — `спользовать `encrypted/s3://bucket/snapshot.enc` как snapshot_path. Полезно для бэкапов и disaster recovery. Затронет: `saveEncrypted`/`loadEncrypted` → `saveToBackend`/`loadFromBackend` интерфейс. **Почему:** Потеря локального snapshot.enc = потеря всех секретов. Для production-сервиса лаборатории это критично.
