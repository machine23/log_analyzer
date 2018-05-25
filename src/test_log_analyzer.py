import unittest
from datetime import datetime
from unittest import mock

from .log_analyzer import LogAnalyzer


class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        config = {
            'REPORT_SIZE': 1000,
            'REPORT_DIR': './reports',
            'LOG_DIR': './log',
            'LOG_PREFIX': 'nginx-access-ui',
        }
        self.analyzer = LogAnalyzer(config)

    def test_date_in_logname(self):
        logname = 'nginx-access-ui.log-20170630.gz'
        expected = datetime(2017, 6, 30)
        result = self.analyzer.date_in_logname(logname)
        self.assertEqual(expected, result)

    def test_date_in_logname_without_date(self):
        logname = 'nginx-access-ui.log'
        self.assertIsNone(self.analyzer.date_in_logname(logname))

    def test_get_last_log(self):
        with mock.patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = [
                'nginx-access-ui.log-20170630.gz',
                'nginx-access-ui.log-20170712.gz',
                'nginx-access-ui.log-20170930',
                'nginx-access-ui.log',
                'nginx-any.log-20170630.gz'
            ]
            self.assertEqual(self.analyzer.get_last_log(),
                             './log/nginx-access-ui.log-20170930')

    def test_get_last_log_without_right_log(self):
        with mock.patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = [
                'nginx-access-ui.log',
                'something-else.log',
                'may_be_any',
            ]
            self.assertIsNone(self.analyzer.get_last_log())


if __name__ == '__main__':
    unittest.main()
