# log_analyzer

Данный скрипт предназначен для анализа логов веб-сервера. Для корректной работы необходим Python версии 3.

### Запуск

Для запуска скрипта необходима команда:

```bash
$ python3 log_analyzer.py
```
При этом скрипт обрабатывает последний (с самой свежей датой в имени) лог в LOG_DIR (смотреть конфигурационный файл). Результат работы сохраняется в файле report-yyyy.mm.dd.html. Если отчет с подобным именем уже существует в папке для отчетов REPORT_DIR, то скрипт не пересчитывает работу по новой.

Для того, чтобы переписать отчет, используется флаг --force
```bash
$ python3 log_analyzer.py --force
```
Для анализа конкретного лога, используется флаг --file
```bash
$ python3 log_analyzer.py --file path/to/custom.log
```
Флаг --config нужен для указания пути к пользовательскому конфигурационному файлу.
```bash
$ python3 log_analyzer.py --config path/to/config
```

### Конфигурационный файл
Конфигурационный файл используется для задания настроек скрипта. Конфигурационный файл пишется в формате json.

Пример:
```json
{
    "LOG_DIR": "./log",
    "LOG_PREFIX": "nginx-access-ui",
    "REPORT_DIR": "./reports"
}
```

Возможны следующие настройки:

* LOG_DIR - путь к директории с логами для анализа;
* LOG_PREFIX - префикс имени лога для анализа;
* REPORT_SIZE - количество записей в отчете;
* REPORT_DIR - путь к директории для отчетов;
* REPORT_PREFIX - префикс к имени отчета;
* MAX_PARS_ERRORS_PERC - процент ошибок при парсинге лога, по достижению которого скрипт прекратит работу;
* LOGFILE - путь к лог-файлу, в который скрипт сохраняет служебную информацию о проделанной работе. Если не указан, то данная информация будет выводиться в stdout.

### Запуск тестов
```bash
python3 -m unittest
```
