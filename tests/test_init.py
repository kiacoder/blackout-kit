import unittest
from unittest.mock import patch

from blackoutkit import get_version, check_version

class TestInitVersions(unittest.TestCase):

    @patch('blackoutkit.__version__', '1.1.0')
    def test_get_version_standard(self):
        self.assertEqual(get_version(), (1, 1, 0))

    @patch('blackoutkit.__version__', '2.0')
    def test_get_version_short(self):
        self.assertEqual(get_version(), (2, 0))

    @patch('blackoutkit.__version__', '1.2.3.4')
    def test_get_version_long(self):
        self.assertEqual(get_version(), (1, 2, 3))

    @patch('blackoutkit.__version__', 'invalid.version')
    def test_get_version_invalid(self):
        self.assertEqual(get_version(), (0, 0, 0))

    @patch('blackoutkit.__version__', '1.2.0')
    def test_check_version_older(self):
        self.assertTrue(check_version('1.0.0'))
        self.assertTrue(check_version('1.1.9'))

    @patch('blackoutkit.__version__', '1.2.0')
    def test_check_version_equal(self):
        self.assertTrue(check_version('1.2.0'))
        self.assertTrue(check_version('1.2'))

    @patch('blackoutkit.__version__', '1.2.0')
    def test_check_version_newer(self):
        self.assertFalse(check_version('1.3.0'))
        self.assertFalse(check_version('2.0.0'))

if __name__ == '__main__':
    unittest.main()
