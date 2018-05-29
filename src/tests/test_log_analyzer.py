import unittest
import os
from datetime import datetime
from unittest import mock
from unittest.mock import mock_open

from ..log_analyzer import LogAnalyzer


class TestLogAnalyzer(unittest.TestCase):
    @staticmethod
    def find_file(filename):
        test_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(test_dir, filename)

    def setUp(self):
        self.test_config = {
            'REPORT_SIZE': 1000,
            'REPORT_DIR': './reports',
            'LOG_DIR': './log',
            'LOG_PREFIX': 'sample',
        }
        self.analyzer = LogAnalyzer(self.test_config)
        self.maxDiff = None
        self.epsilon = 0.0001

    def test_date_in_logname(self):
        logname = 'sample.log-20170630.gz'
        expected = datetime(2017, 6, 30)
        result = self.analyzer.date_in_logname(logname)
        self.assertEqual(expected, result)

    def test_date_in_logname_with_none(self):
        self.assertIsNone(self.analyzer.date_in_logname(None))

    def test_date_in_logname_without_date(self):
        logname = 'sample.log'
        self.assertIsNone(self.analyzer.date_in_logname(logname))

    def test_get_last_log(self):
        with mock.patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = [
                'sample.log-20170630.gz',
                'sample.log-20170712.gz',
                'sample.log-20170930',
                'sample.log',
                'nginx-any.log-20170630.gz'
            ]
            self.assertEqual(self.analyzer.get_last_log(),
                             './log/sample.log-20170930')

    def test_get_last_log_without_right_log(self):
        with mock.patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = [
                'sample.log',
                'something-else.log',
                'may_be_any',
            ]
            self.assertIsNone(self.analyzer.get_last_log())

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
        result = self.analyzer._parse_line(line)
        self.assertDictEqual(expected, result)

    def test_parse_line_without_str(self):
        cases = ({}, 123, 1.1, [], set())
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(TypeError):
                    self.analyzer._parse_line(case)

    def test_parse_line_with_bad_line(self):
        cases = (
            '',
            'asdf vaasd vsdf',
            '1.22.234.122 1fq12   - - - - - - - -'
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    self.analyzer._parse_line(case)

    def test_parse_log(self):
        with open(self.find_file('log/sample.log-1')) as logfile:
            self.analyzer._parse_log(logfile)
            expect_requests_count = 7
            expect_requests_time_sum = 1.6
            expect_parsing_errors = 0
            expect_request_times = {
                '/api/v2/banner': [0.3, 0.4, 0.5],
                '/api/1/photo': [0.1, 0.1, 0.1, 0.1],
            }
            self.assertEqual(
                self.analyzer.requests_count,
                expect_requests_count
            )
            self.assertLess(
                abs(self.analyzer.requests_time_sum - expect_requests_time_sum),
                self.epsilon
            )
            self.assertDictEqual(
                self.analyzer.request_times,
                expect_request_times
            )
            self.assertEqual(
                self.analyzer.parsing_errors,
                expect_parsing_errors
            )

    def test_parse_log_with_bad_lines(self):
        with open(self.find_file('log/sample.log-2')) as logfile:
            self.analyzer._parse_log(logfile)
            expect_requests_count = 7
            expect_requests_time_sum = 1.6
            expect_parsing_errors = 2
            expect_request_times = {
                '/api/v2/banner': [0.3, 0.4, 0.5],
                '/api/1/photo': [0.1, 0.1, 0.1, 0.1],
            }
            self.assertEqual(
                self.analyzer.requests_count,
                expect_requests_count
            )
            self.assertLess(
                abs(self.analyzer.requests_time_sum - expect_requests_time_sum),
                self.epsilon
            )
            self.assertDictEqual(
                self.analyzer.request_times,
                expect_request_times
            )
            self.assertEqual(
                self.analyzer.parsing_errors,
                expect_parsing_errors
            )

    def test_compute_stats(self):
        self.analyzer.requests_count = 7
        self.analyzer.requests_time_sum = 1.6
        self.analyzer.request_times = {
            '/api/v2/banner': [0.3, 0.4, 0.5],
            '/api/1/photo': [0.1, 0.1, 0.1, 0.1],
        }
        self.analyzer._compute_stats()
        expect_urls_stats = [
            {
                'url': '/api/v2/banner',
                'count': 3,
                'count_perc': round(3*100/7, 2),
                'time_sum': round(1.2, 2),
                'time_perc': round(1.2/1.6, 2),
                'time_avg': round(1.2/3, 2),
                'time_max': 0.5,
                'time_med': 0.4,
            },
            {
                'url': '/api/1/photo',
                'count': 4,
                'count_perc': round(4*100/7, 2),
                'time_sum': round(0.4, 2),
                'time_perc': round(0.4/1.6, 2),
                'time_avg': round(0.4/4, 2),
                'time_max': 0.1,
                'time_med': 0.1,
            },
        ]
        self.assertEqual(
            self.analyzer.urls_stats,
            expect_urls_stats
        )

    def test_open_with_plain(self):
        filename = 'test.log'
        expect = 'test'
        with mock.patch('builtins.open', mock_open(read_data='test')) as m:
            analyzer = LogAnalyzer(self.test_config, filename)
            analyzer.open()
            result = analyzer.logfile_for_analyze.read()
            self.assertEqual(result, expect)

    def test_open_with_gzip(self):
        filename_gz = 'test.log.gz'
        expect = 'test'
        with mock.patch('gzip.open', mock_open(read_data='test')) as m:
            analyzer = LogAnalyzer(self.test_config, filename_gz)
            analyzer.open()
            result = analyzer.logfile_for_analyze.read()
            self.assertEqual(result, expect)

    def test_save(self):
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

        self.analyzer.report_size = 2
        self.analyzer.urls_stats = [
            {'time_sum': 1},
            {'time_sum': 5},
            {'time_sum': 2},
            {'time_sum': 3},
            {'time_sum': 0.1},
        ]

        with mock.patch('builtins.open', mock_open(read_data=template)) as m:
            self.analyzer.save('template.html', report_name='report01.html')
            m.assert_called_with('report01.html', 'w')
            handle = m()
            handle.write.assert_called_once_with(expect)

    def test_save_with_right_report_name(self):
        with mock.patch('builtins.open') as m:
            self.analyzer.logname_for_analyze = 'sample.log-20170630'
            self.analyzer.save('template.html')
            m.assert_called_with('./reports/report-2017.06.30.html', 'w')

    def test_save_with_custom_report_name(self):
        with mock.patch('builtins.open') as m:
            self.analyzer.save('template.html', report_name='report01')
            m.assert_called_with('report01', 'w')

    def test_construct_report_name(self):
        cases = (
            ('sample.log-20170630', 'report-2017.06.30.html'),
            ('sample_01.log', 'report_for_sample_01.log.html')
        )
        for logname, expect in cases:
            with self.subTest(logname=logname):
                result = self.analyzer._construct_report_name(logname)
                self.assertEqual(expect, result)


if __name__ == '__main__':
    unittest.main()
