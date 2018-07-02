
import unittest

suite = unittest.TestLoader().discover(start_dir='tests', pattern='test_*.py')
unittest.TextTestRunner(verbosity=2).run(suite)
