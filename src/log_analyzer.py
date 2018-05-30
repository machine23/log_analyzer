#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] '$request' '
#                     '$status $body_bytes_sent '$http_referer' '
#                     ''$http_user_agent' '$http_x_forwarded_for' '$http_X_REQUEST_ID' '$http_X_RB_USER' '
#                     '$request_time';
import argparse
import configparser
import gzip
import json
import os
import re
from datetime import datetime
from statistics import median

config = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'LOG_PREFIX': 'nginx-access-ui',
}


class LogAnalyzer:
    cols_regexp = {
        'remote_addr': r'[\d\.]+',
        'remote_user': r'\S*',
        'http_x_real_ip': r'\S*',
        'time_local': r'\[.*?\]',
        'request': r'"(?:GET|POST) \S+ \S+"',
        'status': r'\d+',
        'body_bytes_sent': r'\d+',
        'http_referer': r'".*?"',
        'http_user_agent': r'".*?"',
        'http_x_forwarded_for': r'".*?"',
        'http_X_REQUEST_ID': r'".*?"',
        'http_X_RB_USER': r'".*?"',
        'request_time': r'\d+\.\d+',
    }

    def __init__(self, config, logname=None, force=False):
        self.force = force
        # self.config = config
        self.log_dir = config.get('LOG_DIR')
        self.log_prefix = config.get('LOG_PREFIX')
        self.report_size = config.get('REPORT_SIZE', 1000)
        self.report_dir = config.get('REPORT_DIR', './reports')
        self.report_prefix = config.get('REPORT_PREFIX', 'report')

        if not logname:
            logname = self.get_last_log()
        self.logname_for_analyze = logname

        self.logfile_for_analyze = None
        self.requests_count = 0
        self.requests_time_sum = 0
        self.request_times = {}
        self.urls_stats = []
        self.parsing_errors = 0
        self._line_cols = (
            'remote_addr',
            'remote_user',
            'http_x_real_ip',
            'time_local',
            'request',
            'status',
            'body_bytes_sent',
            'http_referer',
            'http_user_agent',
            'http_x_forwarded_for',
            'http_X_REQUEST_ID',
            'http_X_RB_USER',
            'request_time',
        )

    @property
    def line_cols(self):
        return self._line_cols

    @line_cols.setter
    def line_cols(self, value):
        self._line_cols = value

    def date_in_logname(self, logname):
        """ Returns datetime object with date from logname. """
        if logname is None:
            return
        date_match = re.search(r'\d{8}', logname)
        if date_match:
            return datetime.strptime(date_match.group(), '%Y%m%d')

    def get_last_log(self):
        """ Returns path to log file with latest date in name. """
        try:
            files = os.listdir(self.log_dir)
        except FileNotFoundError:
            return
        logs = [
            log for log in files
            if log.startswith(self.log_prefix)
            if self.date_in_logname(log)
        ]
        if logs:
            logname = max(logs, key=self.date_in_logname)
            logpath = os.path.join(self.log_dir, logname)
            return logpath

    def _parse_line(self, line: str):
        """ Parses one line from log. Returns dict. """
        if not isinstance(line, str):
            raise TypeError('line must be a string, but get %s' % type(line))

        parsed_dict = {}
        start = 0

        for col in self.line_cols:
            match = re.match(self.cols_regexp[col], line[start:].strip())

            if not match:
                msg = 'Cannot parse %s in line \'%s\'' % (col, line)
                raise ValueError(msg)

            start += match.end() + 1
            value = match.group().strip('[]"" ')
            if col in ('status', 'body_bytes_sent'):
                value = int(value)
            elif col == 'request_time':
                value = float(value)
            parsed_dict[col] = value

        return parsed_dict

    def _parse_log(self, logfile):
        for line in logfile:
            try:
                req = self._parse_line(line)
            except ValueError as err:
                self.parsing_errors += 1
                continue

            req_time = req.get('request_time')
            url = req.get('request').split()[1]
            self.requests_count += 1
            self.requests_time_sum += req_time
            self.request_times.setdefault(url, []).append(req_time)

    def _compute_stats(self, round_digits=2):
        for url, times in self.request_times.items():
            count = len(times)
            count_perc = count * 100 / self.requests_count
            time_sum = sum(times)
            time_perc = time_sum / self.requests_time_sum
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
            self.urls_stats.append(data)

    def open(self):
        if self.logfile_for_analyze is None and self.logname_for_analyze:
            ext = self.logname_for_analyze.split('.')[-1]
            if ext == 'gz':
                self.logfile_for_analyze = gzip.open(
                    self.logname_for_analyze, 'rt')
            else:
                self.logfile_for_analyze = open(self.logname_for_analyze)

    def close(self):
        if self.logfile_for_analyze:
            self.logfile_for_analyze.close()
            self.logfile_for_analyze = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc_details):
        self.close()

    def default_template(self):
        file_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(file_dir, 'report.html')

    def save(self, report, report_name):
        report_dir = os.path.dirname(os.path.abspath(report_name))
        if not report_dir:
            os.makedirs(report_dir)

        with open(report_name, 'w') as report_file:
            report_file.write(report)

    def render_to_template(self, template, replace_str):
        with open(template) as template_file:
            template_str = template_file.read()

        data = sorted(
            self.urls_stats,
            key=lambda x: x['time_sum'],
            reverse=True)

        template_str = template_str.replace(
            replace_str,
            json.dumps(data[:self.report_size]))
        return template_str

    def _construct_report_name(self, logname):
        date = self.date_in_logname(logname)
        if date:
            report_name = '%s-%s.html' % (self.report_prefix,
                                          date.strftime('%Y.%m.%d'))
        else:
            report_name = '%s_for_%s.html' % (self.report_prefix, logname)
        report_name = os.path.join(self.report_dir, report_name)
        return report_name

    def process(self, save=True):
        if not self.logfile_for_analyze:
            return

        report_name = self._construct_report_name(self.logname_for_analyze)
        if not self.force and os.path.isfile(report_name):
            return

        self._parse_log(self.logfile_for_analyze)
        self._compute_stats()
        if save:
            template = self.default_template()
            report = self.render_to_template(template, '$json_table')
            self.save(report, report_name)


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
    parser.add_argument(
        '--file',
        dest='file',
        default=None,
        help='Path to the log file for analyze'
    )
    parser.add_argument(
        '--report',
        dest='report',
        default=None,
        help='The custom name for report'
    )
    args = parser.parse_args()
    if not os.path.isfile(args.config):
        parser.error('Config file not found')
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


def main(default_config):
    args = parse_args()

    config = load_config(args.config, default_config)

    with LogAnalyzer(config) as analyzer:
        analyzer.process()


if __name__ == '__main__':
    main(config)
