# Bulk abuse-report submitter

Автоматическая отправка формы https://linkreclamatiogrwc.uk/ для списка целей
(Domain / IP / URL / Raw source). reCAPTCHA v2 решается через 2captcha.

Без браузера, без Puppeteer, без Selenium — чистый HTTP на Node.js.

## Что внутри

- `server.js` — HTTP-сервер (встроенный `node:http`): UI, очередь, retry.
- `submitter.js` — пайплайн одной отправки: GET → 2captcha → POST → парсинг.
- `multipart.js` — минимальный парсер `multipart/form-data` для входящей формы.
- `public/index.html` — форма оператора.
- `public/batch.html` — страница статуса с живым обновлением.
- `package.json` — только метаданные, **зависимостей нет**.

## Запуск

Требование: Node.js **18+** (нужны встроенные `fetch` / `FormData` / `Blob`).

```bash
cd test-task
node server.js
```

Открыть в браузере:

```
http://127.0.0.1:5000/
```

Всё. `npm install` запускать не нужно — зависимостей нет.

### Конфиг

Ключ 2captcha лежит в файле `.env` рядом с `server.js` (шаблон —
`.env.example`, скопировать и вписать свой ключ):

```bash
cp .env.example .env
# затем открыть .env и подставить настоящий TWOCAPTCHA_API_KEY
```

```ini
TWOCAPTCHA_API_KEY=your_2captcha_api_key_here
```

`.env` подхватывается автоматически при любом способе запуска
(встроенный минимальный loader в `server.js`, zero-dependency). Реальные
переменные окружения перекрывают `.env`:

```bash
TWOCAPTCHA_API_KEY=xxxxxxxxxxxx node server.js
```

Порт по умолчанию — `5000`, при коллизии задаётся `PORT=8080 node server.js`.

## Как пользоваться

1. Выбрать **Submission Type** — Domain / IP / URL / Raw source.
2. В **Targets** вставить список целей, **одна на строку**. Каждая строка
   уходит отдельным POST'ом с отдельно решённой капчей (форма принимает
   только одну цель за раз).
3. Выбрать **Threat Type** (Spam, Phishing, Malware, Botnet C&C, Fraud / Scam, Other).
4. Написать **Reason** (до 2000 символов).
5. При желании прикрепить файл: JPG/JPEG/PNG/PDF до 2 МБ. Прикреплённый
   файл идёт вместе с каждой строкой батча.
6. **Submit batch** — откроется страница со статусами, которая сама
   обновляется каждые 2 секунды.

На странице батча для каждой строки видно:

- **Status** — `queued` → `running` → `success` / `failed`
- **Result** — код подтверждения вида `CF-XXXXXXXX` (успех) или причина
  (ошибка капчи, валидация формы, сеть, …)
- **Attempts** — сколько раз строка отправлялась
- **Action** — кнопка **Retry** появляется у упавших строк

Параллельно крутится до **3 задач** (`MAX_WORKERS` в `server.js`).

### Автонормализация целей

Чтобы не ловить ошибку целевой формы `Please fix the highlighted fields`
из-за неправильного формата, сервер перед отправкой выравнивает цели под
выбранный Submission Type:

| Submission Type | Что делает сервер |
|---|---|
| **URL**    | если нет схемы — добавляет `https://`: `test.com` → `https://test.com` |
| **Domain** | срезает схему и всё после `/` `?` `#`: `https://test.com/x?a=1` → `test.com` |
| **IP**     | то же срезание: `http://1.2.3.4:80/x` → `1.2.3.4:80`, `https://1.2.3.4` → `1.2.3.4` |
| **Raw source** | не трогает |

На странице батча отображаются уже нормализованные targets, чтобы было
видно, что реально улетело на сервер.

### Pre-submit валидация формата

Перед тем, как тратить капчу, сервер проверяет формат самой цели:

| Submission Type | Что считается валидным |
|---|---|
| **Domain** | FQDN: лейблы из `[a-z0-9-]`, разделены точками, длина до 253 |
| **IP**     | IPv4 (4 октета 0-255) или IPv6 (с `:`) |
| **URL**    | парсится `new URL()`, схема только `http://` / `https://` |
| **Raw source** | без проверки, не пустой |

Если цель не прошла — строка сразу `failed` с причиной
(`Not a valid IPv4 (octet > 255)`, `Not a valid domain (expected e.g. example.com)`,
…), **без** обращения к 2captcha. В логах рядом с таким событием стоит
пометка `(no captcha used)`.

### Raw source

Для **Raw source** split по строкам отключён: поле textarea — это один
многострочный email с заголовками, поэтому вся textarea отправляется
**одним** submit'ом (и одной капчей). UI при выборе типа меняет placeholder
и подпись под полем, чтобы это было явно. В логе многострочный raw target
сжимается до одной строки (`\n` экранируется, длина обрезается до 80
символов).

### События в логе

Сервер пишет компактный лог **и** в stdout, **и** дописывает в
`server.log` рядом со скриптом (автоматически, без редиректов):

```
[11:56:50] server up on http://127.0.0.1:5000/
[11:56:52] batch=067c4be51ae8 CREATED type=ip threat="Spam" targets=1
[11:56:52] batch=067c4be51ae8 row=0 target=111.255.231 RUNNING (attempt 1)
[11:56:52] batch=067c4be51ae8 row=0 target=111.255.231 FAILED Not a valid IP (expected e.g. 192.0.2.1) (no captcha used)
[11:07:47] batch=c0371d8dda60 row=0 target=test.com SUCCESS CF-I1SLBQY6
```

Удобно смотреть `tail -f server.log`.

## Как это работает

Один сабмит одной цели:

1. **GET** `https://linkreclamatiogrwc.uk/` — забираем сессионную cookie
   (`Set-Cookie: session=…`) и скрытый `form_token` (CSRF-like поле).
2. **2captcha**: `POST /in.php` с `method=userrecaptcha`,
   `googlekey=6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28`,
   `pageurl=https://linkreclamatiogrwc.uk/`. Потом long-poll `GET /res.php`
   каждые 5 с, до готового токена. Таймаут 180 с.
3. **POST** `https://linkreclamatiogrwc.uk/submit` (multipart/form-data) с
   теми же cookie, `Referer`, собранными полями
   (`form_token`, `submission_type`, целевое поле
   `domain|ip|url|raw_source`, `threat_type`, `reason`, `accept_terms=1`,
   `g-recaptcha-response=<token>`) и файлом, если он есть.
4. Парсим ответ: regex `CF-[A-Z0-9]{6,16}` на весь body. Если нет —
   забираем текст из `.alert` или `.field-error`, иначе возвращаем код HTTP.

Каждая строка — свежий GET + свежий captcha-токен: токен одноразовый и
привязан к сессии.

## Проверка

Инструмент был прогнан вживую против целевой формы и реальной 2captcha:

| Прогон | Submission Type | Target | Результат |
|---|---|---|---|
| curl (эталон) | domain | `example.com` | ✅ `CF-APSUCFQF` |
| через сервер  | domain | `example.com` | ✅ `CF-I6JO8XTX` |
| через сервер  | domain | `test.net`    | ✅ `CF-09H8MB58` |
| через сервер  | domain | `test.com`    | ✅ `CF-I1SLBQY6` |
| через сервер  | domain | `test.net`    | ✅ `CF-UR5VRYLH` |
| через сервер  | url    | `test.com` (без схемы) | ❌ до нормализации: `HTTP 400: Please fix the highlighted fields.` |
| через сервер  | domain | `https://test.com/` (со схемой) | ❌ до нормализации: `HTTP 400: Please fix the highlighted fields.` |

После добавления автонормализации targets (см. выше) оба неудачных кейса
проходят.

## Ограничения / заметки

- Состояние батчей живёт **в памяти процесса**. Перезапуск `server.js`
  сбрасывает их.
- Captcha-таймаут — 180 с. Увеличить можно в
  `submitter.js → solveRecaptchaV2(... { timeoutMs })`.
- `MAX_WORKERS = 3` — низкое намеренно: больше параллельных запросов на
  один endpoint могут упереться в rate-limit целевого сайта.
- Папка `uploads/` зарезервирована, но сейчас не используется: файл
  приёмника держится в памяти батча и переиспользуется для всех строк.
