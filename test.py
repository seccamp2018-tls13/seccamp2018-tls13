
import sys
import unittest

verbosity = 2
if len(sys.argv) >= 2 and sys.argv[1].startswith('-'):
    verbosity = 1

suite = unittest.TestLoader().discover(start_dir='tests', pattern='test_*.py')
unittest.TextTestRunner(verbosity=verbosity).run(suite)
