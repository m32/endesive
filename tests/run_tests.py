#!/usr/bin/env vpython3
import unittest

if __name__ == '__main__':

    # use the default shared TestLoader instance
    test_loader = unittest.defaultTestLoader

    # use the basic test runner that outputs to sys.stderr
    test_runner = unittest.TextTestRunner()

    # automatically discover all tests in the current dir of the form test*.py
    # NOTE: only works for python 2.7 and later
    test_suite = test_loader.discover('.')

    # run the test suite
    test_runner.run(test_suite)
