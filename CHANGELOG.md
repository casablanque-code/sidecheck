# Changelog

Формат по [Keep a Changelog](https://keepachangelog.com/), версии по [SemVer](https://semver.org/).

## [Unreleased]

## [0.2.0] — TBD

### Added
- `--json-body` — шаблон тела запроса для `--json-field`, чтобы можно было задать остальные обязательные поля (username, email и т.д.), которые бэкенду нужны, чтобы дойти до сравнения секрета
- `rust-version` (MSRV) в Cargo.toml + отдельный CI-джоб, собирающий workspace на заявленном MSRV, чтобы регресс по этой границе ловился в CI, а не у пользователя при `cargo install`
- Автоматизация релиза: `Prepare Release` (ручной триггер, бампает версию/тег) → `Release` (публикует sidecheck-core и sidecheck на crates.io идемпотентно, собирает бинарники под linux/macos/windows, создаёт GitHub Release)

### Fixed
- README: команда `cargo install` теперь с `--locked`, чтобы использовать закоммиченный Cargo.lock вместо повторного резолва зависимостей — обходит `feature edition2024 is required` на более старых системных toolchain (например Ubuntu 24.04 LTS, cargo 1.75)

### Changed
- Уточнена формулировка `sidecheck doctor`: `recommended samples` — оценка по формуле power analysis для сравнения средних (прокси через MAD-джиттер), а не точный расчёт мощности box-test/бутстрапа; для reference-точки используется фиксированный condition ~1μs

## [0.1.0] — retroactive, no formal GitHub release was cut at the time

Первая рабочая версия. Добавлено задним числом в changelog по факту публикации sidecheck-core и sidecheck на crates.io.

### Added
- `sidecheck check` — box test (Crosby–Wallach–Riedi) с бутстрап-доверительными интервалами по низкому перцентилю (p10 по умолчанию), рандомизированное чередование классов блоками, автоподбор числа сэмплов по пилотному прогону
- Инъекция значения в header / query param / одно поле JSON body
- Способы передачи секрета: `--secret`, `--secret-env`, `--secret-stdin` (с предупреждением о видимости в `ps aux`/истории для `--secret`)
- `sidecheck doctor` — pre-flight проверка сети (median RTT, jitter, packet loss, рекомендованное число сэмплов, классификация окружения)
- MAD-based (робастная к выбросам) оценка джиттера — заменила более раннюю дисперсионную оценку
- `--repeat N` — повторные полные прогоны для проверки стабильности результата
- Экспорт сырых данных в CSV и машиночитаемый JSON-отчёт (`--report`) для CI
- `--seed` для воспроизводимости порядка чередования запросов
- Guard от заведомо бессмысленного прогона: если по оценке джиттера мощности не хватит даже на `--max-samples`, sidecheck останавливается заранее (обход — `--force`)
- E2E CI на реальном fixture-сервере (Python), unit-тесты статистики, cargo-audit, Dependabot
- Документированное ограничение: утечка ~25 байт не обнаружима через публичный интернет (джиттер маскирует эффект)
