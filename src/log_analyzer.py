#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] '$request' '
#                     '$status $body_bytes_sent '$http_referer' '
#                     ''$http_user_agent' '$http_x_forwarded_for' '$http_X_REQUEST_ID' '$http_X_RB_USER' '
#                     '$request_time';
import argparse
import collections
import functools
import gzip
import json
import logging
import os
import re
from datetime import datetime
from statistics import median
from string import Template

config = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'LOG_PREFIX': 'nginx-access-ui',
    'MAX_PARS_ERRORS_PERC': 10,
}

LogMeta = collections.namedtuple('LogMeta', ['path', 'date'])


def log_time_execution(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        start = datetime.now()
        result = func(*args, **kwargs)
        logging.info('Time execution of %s: %s', func.__name__,
                     datetime.now() - start)
        return result
    return wrapped


def date_from_name(name):
    """ Returns datetime object with date from name. """
    if name:
        date_match = re.search(r'\d{8}', name)
        if date_match:
            return datetime.strptime(date_match.group(), '%Y%m%d')


def get_last_log(log_prefix, log_dir):
    last_log = ''
    last_date = datetime(1, 1, 1)
    pattern = r'%s.log-\d{8}(\.gz)?$' % log_prefix

    files = os.listdir(log_dir)
    for file in files:
        if re.match(pattern, file):
            date = date_from_name(file)
            if date > last_date:
                last_date = date
                last_log = file
    if last_log:
        path = os.path.join(log_dir, last_log)
        return LogMeta(path, last_date)


def construct_report_name(logmeta, report_dir, report_prefix='report'):
    # sample.log-20170630 -> report-2017.06.30.html
    date = logmeta.date
    report_name = '%s-%s.html' % (report_prefix, date.strftime('%Y.%m.%d'))
    return os.path.join(report_dir, report_name)


def read_lines(log_path: str):
    if log_path.endswith('.gz'):
        open_func = gzip.open
        mode = 'rt'
    else:
        open_func = open
        mode = 'r'
    with open_func(log_path, mode=mode) as log:
        logging.info('File "%s" is opened for analysis.', log_path)
        for line in log:
            yield line
    logging.info('File "%s" is closed.', log_path)


def convert_col_type(col, value):
    if col in ('status', 'body_bytes_sent'):
        value = int(value)
    elif col == 'request_time':
        value = float(value)
    return value


def parse_line(line: str):
    """ Parses one line from log. Returns dict. """
    if not isinstance(line, str):
        raise TypeError('line must be a string, but get %s' % type(line))

    cols_regexp = {
        'remote_addr': r'[\d\.]+',
        'remote_user': r'\S*',
        'http_x_real_ip': r'\S*',
        'time_local': r'\[.*?\]',
        'request': r'"(?:GET|POST|HEAD|PUT|DELETE) \S+ \S+"',
        'status': r'\d+',
        'body_bytes_sent': r'\d+',
        'http_referer': r'".*?"',
        'http_user_agent': r'".*?"',
        'http_x_forwarded_for': r'".*?"',
        'http_X_REQUEST_ID': r'".*?"',
        'http_X_RB_USER': r'".*?"',
        'request_time': r'\d+\.\d+',
    }

    parsed_dict = {}
    start = 0

    for col in cols_regexp:
        match = re.match(cols_regexp[col], line[start:].strip())

        if not match:
            msg = "Cannot parse %s in line '%s'" % (col, line.strip())
            logging.error(msg)
            raise ValueError(msg)

        start += match.end() + 1
        value = match.group().strip('[]"" ')
        value = convert_col_type(col, value)
        parsed_dict[col] = value

    return parsed_dict


@log_time_execution
def parse_log(log_path, errors_threshold):
    total = 0
    errors = 0

    logging.info('Start parsing file %s' % log_path)
    for line in read_lines(log_path):
        total += 1
        try:
            yield parse_line(line)
        except ValueError as err:
            errors += 1
            continue

    logging.info('End of parsing file.')

    errors_perc = errors * 100 / total
    if errors_perc > errors_threshold:
        raise RuntimeError('Тoo many errors (%.2f%) in the analyzed file.',
                           errors_perc)


def collect_time_data(log):
    time_data = {
        'total_time_sum': 0,
        'requests_count': 0,
        'items': {},
    }
    for line in log:
        req_time = line.get('request_time')
        url = line.get('request').split()[1]
        time_data['total_time_sum'] += req_time
        time_data['requests_count'] += 1
        time_data['items'].setdefault(url, []).append(req_time)
    time_data['total_time_sum'] = round(time_data['total_time_sum'], 3)
    return time_data


@log_time_execution
def calculate_statistics(log, round_digits=3):
    logging.info('Start calculating statistics.')
    stats = []
    time_data = collect_time_data(log)
    for url, times in time_data['items'].items():
        count = len(times)
        count_perc = count * 100 / time_data['requests_count']
        time_sum = sum(times)
        time_perc = time_sum / time_data['total_time_sum']
        time_avg = time_sum / count
        time_max = max(times)
        time_med = median(times)

        data = {
            'url': url,
            'count': count,
            'count_perc': round(count_perc, round_digits),
            'time_sum': round(time_sum, round_digits),
            'time_perc': round(time_perc, round_digits),
            'time_avg': round(time_avg, round_digits),
            'time_max': time_max,
            'time_med': round(time_med, round_digits),
        }
        stats.append(data)
    logging.info('End of calculation of statistics.')
    return stats


def stats_to_html(stats, report_size):
    template_name = 'report.html'
    template_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        template_name
    )
    with open(template_path) as template_file:
        template = Template(template_file.read())
        logging.info('Render report with template %s', template_path)

        data = sorted(
            stats,
            key=lambda x: x['time_sum'],
            reverse=True)

        data_str = json.dumps(data[:report_size])

        return template.safe_substitute(table_json=data_str)


def save_report(report, path):
    with open(path, 'w') as report_file:
        report_file.write(report)
    logging.info('Report saved as %s', path)


def process_log(config, force=False):
    log = get_last_log(config.get('LOG_PREFIX'), config.get('LOG_DIR'))
    if not log:
        logging.info('No files to analyze')
        return
    report_name = construct_report_name(log, config.get('REPORT_DIR'))
    if force or not os.path.isfile(report_name):
        log = parse_log(log.path, config.get('MAX_PARS_ERRORS_PERC'))
        stats = calculate_statistics(log)
        report_html = stats_to_html(stats, config.get('REPORT_SIZE'))
        save_report(report_html, report_name)
    else:
        logging.info(
            'Report for %s already exists. Use --force to rewrite it.',
            log.path)


def parse_args():
    analyzer_dir = os.path.dirname(os.path.abspath(__file__))
    default_config_path = os.path.join(analyzer_dir, 'log_analyzer.conf')

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--config',
        dest='config',
        default=default_config_path,
        help='Path to the config file',
    )
    parser.add_argument(
        '--force',
        dest='force',
        action='store_true',
        help='Force analyze log file',
    )
    args = parser.parse_args()
    return args


def load_config(configfile, defaults: dict=None):
    config = {}
    defaults = defaults or {}
    config.update(defaults)
    with open(configfile) as fileobj:
        conf_str = fileobj.read()
        if conf_str:
            new_conf = json.loads(conf_str)
            config.update(new_conf)
    return config


def setup_logger(logfile):
    if logfile:
        log_dir = os.path.dirname(os.path.abspath(logfile))
        path_exists = os.path.exists(log_dir)
        logging.basicConfig(
            format='[%(asctime)s] %(levelname).1s %(message)s',
            filename=logfile,
            datefmt='%Y.%m.%d %H:%M:%S',
            level=logging.INFO,
        )
        if not path_exists:
            logging.info('Can not create log file. Instead, stdout is used.')
    else:
        logging.basicConfig(
            format='[%(asctime)s] %(levelname).1s %(message)s',
            datefmt='%Y.%m.%d %H:%M:%S',
            level=logging.INFO,
        )


def main(default_config):
    args = parse_args()
    config = load_config(args.config, default_config)
    setup_logger(config.get('LOGFILE'))

    logging.info('[START]')
    try:
        process_log(config, args.force)
    except RuntimeError as err:
        logging.error(err)
    except KeyboardInterrupt:
        logging.error('Terminated by KeyboardInterrupt')
    except Exception as err:
        logging.exception(err)
    logging.info('[END]')


if __name__ == '__main__':
    main(config)
