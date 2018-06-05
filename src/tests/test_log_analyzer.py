import unittest
import os
from datetime import datetime
from unittest import mock
from unittest.mock import mock_open

# from ..log_analyzer import LogAnalyzer
from ..log_analyzer import (
    LogMeta,
    collect_time_data,
    get_last_log,
    date_from_name,
    construct_report_name,
    read_lines,
    parse_line,
    parse_log,
    calculate_statistics,
    stats_to_html,
    save_report,
)


class TestLogAnalyzer(unittest.TestCase):
    def test_date_from_name(self):
        logname = 'sample.log-20170630.gz'
        expected = datetime(2017, 6, 30)
        result = date_from_name(logname)
        self.assertEqual(expected, result)

    def test_get_last_log(self):
        expect = LogMeta('./log/sample.log-20170930', datetime(2017, 9, 30))
        with mock.patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = [
                'sample.log-20170630.gz',
                'sample.log-20170712.gz',
                'sample.log-20170930',
                'sample.log',
                'nginx-any.log-20170630.gz'
            ]
            self.assertEqual(get_last_log('sample', './log'), expect)

    def test_construct_report_name(self):
        cases = (
            (
                LogMeta('sample.log-20170630', datetime(2017, 5, 8)),
                './reports/report-2017.05.08.html'
            ),
            (
                LogMeta('sample.log-20170630.gz', datetime(2017, 6, 10)),
                './reports/report-2017.06.10.html'
            )
        )
        for logmeta, expect in cases:
            with self.subTest(logmeta=logmeta):
                result = construct_report_name(logmeta, './reports')
                self.assertEqual(expect, result)

    def test_read_lines_with_gz(self):
        filename_gz = 'test.log.gz'
        expect = iter(('test1', 'test2', 'test3'))

        with mock.patch('gzip.open', mock_open(read_data='test1\ntest2\ntest3')) as m:
            for e in read_lines(filename_gz):
                self.assertEqual(e, next(expect))

    def test_read_lines_with_plain(self):
        filename_gz = 'test.log'
        expect = iter(('test1', 'test2', 'test3'))

        with mock.patch('builtins.open', mock_open(read_data='test1\ntest2\ntest3')) as m:
            for e in read_lines(filename_gz):
                self.assertEqual(e, next(expect))

    def test_parse_line(self):
        line = ('1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300]'
                ' "GET /api/1/photogenic_banners/list/?server_name=WIN7RB4'
                ' HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-"'
                ' "1498697422-32900793-4708-9752770" "-" 0.133')
        expected = {
            'remote_addr': '1.99.174.176',
            'remote_user': '3b81f63526fa8',
            'http_x_real_ip': '-',
            'time_local': '29/Jun/2017:03:50:22 +0300',
            'request': 'GET /api/1/photogenic_banners/list/?server_name='
                       'WIN7RB4 HTTP/1.1',
            'status': 200,
            'body_bytes_sent': 12,
            'http_referer': '-',
            'http_user_agent': 'Python-urllib/2.7',
            'http_x_forwarded_for': '-',
            'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770',
            'http_X_RB_USER': '-',
            'request_time': 0.133,
        }
        result = parse_line(line)
        self.assertDictEqual(expected, result)

    def test_parse_line_without_str(self):
        cases = ({}, 123, 1.1, [], set())
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(TypeError):
                    parse_line(case)

    def test_parse_line_with_bad_line(self):
        cases = (
            '',
            'asdf vaasd vsdf',
            '1.22.234.122 1fq12   - - - - - - - -',
            '1.196.116.32 -  - - "GET /api/v2/banner" 200 927 "-" "-" "-" "-" "-" 0.300',
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    parse_line(case)

    def test_parse_log(self):
        data = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.300',
            '1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET /api/1/photo HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.100',
        )

        expect = [{'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.3},
                  {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1}]
        with mock.patch('src.log_analyzer.read_lines', return_value=data):
            result = list(parse_log('sample.log', 10))
            self.assertListEqual(expect, result)

    def test_collect_time_data(self):
        data = (
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.3},
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.4},
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.5},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
        )
        expect = {
            'total_time_sum': 1.6,
            'requests_count': 7,
            'items': {
                '/api/v2/banner': [0.3, 0.4, 0.5],
                '/api/1/photo': [0.1, 0.1, 0.1, 0.1],
            }
        }
        result = collect_time_data(data)
        self.assertEqual(result, expect)


    def test_parse_log_raise_too_many_errors(self):
        data = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.300',
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.400',
            '---',
            '1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET /api/1/photo HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.100',
            '123',
            '1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET /api/1/photo HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.100',
            '1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET /api/1/photo HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.100',
        )

        with mock.patch('src.log_analyzer.read_lines', return_value=data):
            with self.assertRaises(RuntimeError):
                list(parse_log('sample.log', 10))

    def test_calculate_statistics(self):
        round_digits = 3
        log = (
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.3},
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.4},
            {'remote_addr': '1.196.116.32', 'remote_user': '-', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/v2/banner HTTP/1.1', 'status': 200, 'body_bytes_sent': 927, 'http_referer': '-', 'http_user_agent': 'Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-2190034393-4708-9752759', 'http_X_RB_USER': 'dc7161be3', 'request_time': 0.5},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
            {'remote_addr': '1.99.174.176', 'remote_user': '3b81f63526fa8', 'http_x_real_ip': '-', 'time_local': '29/Jun/2017:03:50:22 +0300', 'request': 'GET /api/1/photo HTTP/1.1', 'status': 200, 'body_bytes_sent': 12, 'http_referer': '-', 'http_user_agent': 'Python-urllib/2.7', 'http_x_forwarded_for': '-', 'http_X_REQUEST_ID': '1498697422-32900793-4708-9752770', 'http_X_RB_USER': '-', 'request_time': 0.1},
        )
        expect_stats = [
            {
                'url': '/api/v2/banner',
                'count': 3,
                'count_perc': round(3*100/7, round_digits),
                'time_sum': round(1.2, round_digits),
                'time_perc': round(1.2/1.6, round_digits),
                'time_avg': round(1.2/3, round_digits),
                'time_max': 0.5,
                'time_med': 0.4,
            },
            {
                'url': '/api/1/photo',
                'count': 4,
                'count_perc': round(4*100/7, round_digits),
                'time_sum': round(0.4, round_digits),
                'time_perc': round(0.4/1.6, round_digits),
                'time_avg': round(0.4/4, round_digits),
                'time_max': 0.1,
                'time_med': 0.1,
            },
        ]
        result = calculate_statistics(log)
        self.assertEqual(result, expect_stats)

    def test_stats_to_html(self):
        template = '''<html>
        <script>
        var table = $table_json;
        </script>
        </html>'''

        expect = '''<html>
        <script>
        var table = [{"time_sum": 5}, {"time_sum": 3}];
        </script>
        </html>'''

        stats = [
            {'time_sum': 1},
            {'time_sum': 5},
            {'time_sum': 2},
            {'time_sum': 3},
            {'time_sum': 0.1},
        ]

        with mock.patch('builtins.open', mock_open(read_data=template)):
            result = stats_to_html(stats, report_size=2)
            self.assertEqual(result, expect)

    def test_save_report(self):
        report = '<html><body>report</body></html>'
        report_name = 'report-2017.06.08.html'
        m = None
        with mock.patch('builtins.open', mock_open()) as m:
            save_report(report, report_name)
            m.assert_called_once_with(report_name, 'w')
            handle = m()
            handle.write.assert_called_with(report)


if __name__ == '__main__':
    unittest.main()
