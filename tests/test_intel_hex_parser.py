from contextlib import contextmanager
import imp
import os
import random
from StringIO import StringIO
import sys
import tempfile
import unittest

intel_hex_parser = imp.load_source("intel_hex_parser",
                                   "../intel_hex_parser.py")

@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestL5x(unittest.TestCase):

    def test_I16(self):
        # tests that the file can be written to I32 format and recovered
        self._test_file("data/full_I16.hex", "I16", "I32")

    def test_I32(self):
        self._test_file("data/subset_I32.hex", "I32", "I16")

    def _test_file(self, orig_filename, orig_format, target_format):
        with open(orig_filename, "r") as in_file:
            hex_obj_in, d_form_in = intel_hex_parser.IntelHex.read_from_file(in_file)

        self.assertEqual(d_form_in, orig_format)

        fd, test_file_path = tempfile.mkstemp()
        fd2, revert_test_path = tempfile.mkstemp()
        try:
            with open(test_file_path, "r+") as out_file:
                hex_obj_in.write(out_file, hex_format=target_format)
                out_file.seek(0)
                # convert back and check that it's equivalent
                hex_obj_32, d_form_out = intel_hex_parser.IntelHex.read_from_file(
                    out_file)
                self.assertEqual(d_form_out, target_format)

            # write back to I16 format
            with open(revert_test_path, "r+") as reverted_file:
                hex_obj_32.write(reverted_file, hex_format=orig_format)
                reverted_file.seek(0)
                hex_obj_revert, d_form_rev = intel_hex_parser.IntelHex.read_from_file(
                    reverted_file)
                self.assertEqual(d_form_rev, orig_format)
                self.assertEqual(
                    hex_obj_in, hex_obj_revert)

        finally:
            os.close(fd)
            os.close(fd2)

    def test_strict(self):
        # tests that the file with the invalid duplicate entry points raises an
        # exception in strict mode
        with self.assertRaises(IOError) as cm:
            with open("data/full_I16.hex", "r") as in_file:
                hex_obj_in, d_form_in = intel_hex_parser.IntelHex.read_from_file(
                    in_file, strict=True)

    def test_sorted_dict(self):
        source_data = ((1, 200),
                       (200, 133),
                       (-298, 87),
                       (0.9827, "hello"),
                       (0x8765, 0x9be))
        d = intel_hex_parser.SortedDict(source_data)
        # check that the keys are sorted
        self.assertEqual(d.keys(), sorted([el[0] for el in source_data]))
        self.assertEqual(d.items(), sorted(source_data, key=lambda el: el[0]))

        # add some more data to check that sorted property remains valid
        for i in range(100):
            d[random.randint(0, 1000)] = random.random()

        keys = d.keys()
        self.assertTrue(
            all(keys[i] <= keys[i + 1] for i in xrange(len(keys) - 1)))

    def test_gt(self):
        def find_prev(l, num):
            last = None
            for el in l:
                if el < num:
                    last = el
                else:
                    break
            return last

        def find_next(l, num):
            for el in l:
                if el > num:
                    return el
            return None

        test_list = sorted([random.randint(-100, 100) for i in range(30)])

        for i in range(-100, 100):
            print i
            self.assertEqual(intel_hex_parser.find_lt(test_list, i),
                             find_prev(test_list, i))
            self.assertEqual(intel_hex_parser.find_gt(test_list, i),
                             find_next(test_list, i))

    def test_cli_noargs(self):
        # check main with no args
        with captured_output() as (out, err):
            with self.assertRaises(SystemExit) as cm:
                intel_hex_parser.main([])

        self.assertEqual(cm.exception.code, 2)
        self.assertIn("too few arguments", err.getvalue().strip())

    def test_cli_same_format(self):
        # try writing to same format
        test_input = os.path.abspath(
            os.path.join("data", "full_I16.hex"))
        fd, test_out_path = tempfile.mkstemp()

        with captured_output() as (out, err):
            with self.assertRaises(SystemExit) as cm:
                intel_hex_parser.main(
                    [test_input, "-o", test_out_path, "-t", "I16"])

        self.assertEqual(cm.exception.code, 1)
        self.assertIn("is already in the requested format",
                      out.getvalue().strip())

    def test_cli_correct(self):
        # try writing to same format
        test_input = os.path.abspath(
            os.path.join("data", "full_I16.hex"))
        fd, test_out_path = tempfile.mkstemp()

        with captured_output() as (out, err):
            intel_hex_parser.main(
                [test_input, "-o", test_out_path, "-t", "I32"])

        self.assertIn("Writing", out.getvalue().strip())

