#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] '$request' '
#                     '$status $body_bytes_sent '$http_referer' '
#                     ''$http_user_agent' '$http_x_forwarded_for' '$http_X_REQUEST_ID' '$http_X_RB_USER' '
#                     '$request_time';
import os
import re
from datetime import datetime

config = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'LOG_PREFIX': 'nginx-access-ui',
}


class LogAnalyzer:
    cols_regexp = {
        'remote_addr': r'[\d\.]+\s',
        'remote_user': '\S*\s+',
        'http_x_real_ip': r'\S*\s',
        'time_local': r'\[.*?\]\s',
        'request': r'".*?"\s',
        'status': r'\d+\s',
        'body_bytes_sent': r'\d+\s',
        'http_referer': r'".*?"\s',
        'http_user_agent': r'".*?"\s',
        'http_x_forwarded_for': r'".*?"\s',
        'http_X_REQUEST_ID': r'".*?"\s',
        'http_X_RB_USER': r'".*?"\s',
        'request_time': r'\d+\.\d+',
    }

    def __init__(self, config):
        self.config = config
        self.line_cols = (
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

    def date_in_logname(self, logname):
        """ Returns datetime object with date from logname. """
        date_match = re.search(r'\d{8}', logname)
        if date_match:
            return datetime.strptime(date_match.group(), '%Y%m%d')

    def get_last_log(self):
        """ Returns path to log file with latest date in name. """
        files = os.listdir(self.config.get('LOG_DIR'))
        logs = [
            log for log in files
            if log.startswith(self.config['LOG_PREFIX'])
            if self.date_in_logname(log)
        ]
        if logs:
            logname = max(logs, key=self.date_in_logname)
            logpath = os.path.join(self.config['LOG_DIR'], logname)
            return logpath

    def parse_line(self, line: str):
        """ Parses one line from log. Returns dict. """
        if not isinstance(line, str):
            raise TypeError('line must be a string, but get %s' % type(line))

        parsed_dict = {}
        start = 0

        for col in self.line_cols:
            match = re.match(self.cols_regexp[col], line[start:])

            if not match:
                msg = 'Cannot parse %s in line \'%s\'' % (col, line)
                raise ValueError(msg)

            start += match.end()
            value = match.group().strip('[]"" ')
            if col in ('status', 'body_bytes_sent'):
                value = int(value)
            elif col == 'request_time':
                value = float(value)
            parsed_dict[col] = value

        return parsed_dict


def main():
    pass


if __name__ == '__main__':
    main()
