import argparse
import bisect
import os
import sys


class IntelHex(object):
    """
    One data representation for any subset of the Intel HEX format
    """

    def __init__(self, data, entry_point):
        """
        :param data: dict of contiguous data, keyed by start address
        :param entry_point: entry point of program (EIP)
        """
        self.data = data
        self.entry_point = entry_point

    def __repr__(self):
        return "{}\n\t".format(self.entry_point) + "\n\t".join(
            self.data.items())

    def __eq__(self, other):
        return ((self.entry_point == other.entry_point) and
                (self.data == other.data))

    def write(self, file_pointer, hex_format="I32", line_length=0x10):
        """
        Writes the data to file using the appropriate format

        :param file_pointer: file objec opened by client code
        :param hex_format: either "I32" (rec_types 0,1,4,5)
            or "I16" (rec_types 0,1,2,3)
        :param line_length: max length of data record data fields in bytes
        """
        offset = 0
        for start_address in self.data.keys():
            # get chunk records
            for record, applied_offset in IntelHex.generate_data_records(
                    start_address, self.data[start_address],
                    initial_offset=offset, hex_format=hex_format,
                    line_length=line_length):
                file_pointer.write(record + "\n")
                offset = applied_offset
        if self.entry_point is not None:
            # write entry_point record if exists
            if hex_format == "I32":
                entry_record = ":04000005{:08X}".format(self.entry_point)
            elif hex_format == "I16":
                segment = (self.entry_point >> 16)
                if segment > 0xF:
                    raise IOError("Entry point of 0x{:X} can't"
                                  "be written to I16 format".format(
                                      self.entry_point))
                segment = segment << 12
                offset = self.entry_point & 0xFFFF
                word = (segment << 16) | offset
                entry_record = ":04000003{:08X}".format(word)
            else:
                raise IOError("Unknown format {}".format(hex_format))
            # add checksum
            entry_record += "{:02X}".format(
                IntelHex.generate_checksum(entry_record[1:]))
            # write
            file_pointer.write(entry_record + "\n")
        # write EOF record
        file_pointer.write(":00000001FF\n")

    @staticmethod
    def generate_data_records(start_address, chunk, initial_offset=0,
                              hex_format="I32", line_length=0x10):
        """
        Takes a contiguous data chunk and generates data / offset records of
        the length and type requested

        :param start_address: start address for chunk
        :param chunk: list of data, one elem per byte
        :param initial_offset: any offset previously written to file (absolute)
        :param hex_format: either "I32" (rec_types 0,1,4,5)
            or "I16" (rec_types 0,1,2,3)
        :param line_length: max length of data record data fields in bytes
        :yields: record, applied_offset (to be fed back into subsequent call
            as initial_offset)
        """
        # determine if start address is outside current extended address space
        if start_address > (initial_offset + 0xFFFF):
            # round extra_offset to nearest 0x10000
            extra_offset = ((start_address - initial_offset) / 0xFFFF) << 0x10
            initial_offset += extra_offset
            yield IntelHex.extended_address_record(
                initial_offset, hex_format), initial_offset

        index = 0
        applied_offset = initial_offset
        chunk_length = len(chunk)

        # build records by consuming data chunk
        while index < chunk_length:
            # determine data record length
            rec_length = min(chunk_length - index, line_length)
            # determine extent of record in extended memory space
            rec_extent = start_address + index + rec_length - applied_offset
            # check if it's passing the local extended memory space limit
            if rec_extent > 0x10000:
                # cut off rec_length earlier
                rec_length = max(0, rec_length - (rec_extent - 0xFFFF))
            # build record string
            byte_count = "{:02X}".format(rec_length)
            if start_address + index - applied_offset < 0:
                raise Exception("{:X} + {:X} - {:X} = {:X}".format(
                    start_address, index, applied_offset,
                    start_address + index - applied_offset))
            address_str = "{:04X}".format(
                start_address + index - applied_offset)
            data_str = "".join(["{:02X}".format(el)
                                for el in chunk[index:index + rec_length]])

            if rec_length > 0:
                # increment list index
                index += rec_length

                record = ":" + byte_count + address_str + "00" + data_str
                record += "{:02X}".format(
                    IntelHex.generate_checksum(record[1:]))
                yield record, applied_offset

            if rec_extent > 0x10000:
                # we're due an extension - write address extension record
                applied_offset += 0x10000
                yield IntelHex.extended_address_record(
                    applied_offset, hex_format), applied_offset

    @staticmethod
    def extended_address_record(abs_offset, hex_format):
        """
        Produces an extended address record depending on `hex_format`

        :param abs_offset: offset to write
        :param hex_format: either "I32" or "I16"
        :returns: record string
        """
        if hex_format == "I32":
            shift = 16
            type_str = "04"
        elif hex_format == "I16":
            shift = 4
            type_str = "02"
        # check for overflow
        if abs_offset > (0xFFFF << 16):
            raise ValueError(
                "Offset 0x{:0x} outside allowed space for hex type {}".format(
                    abs_offset, hex_format))

        record = ":020000{}{:04X}".format(type_str, abs_offset >> shift)

        return record + "{:02X}".format(IntelHex.generate_checksum(record[1:]))

    @classmethod
    def read_from_file(cls, file_pointer, hex_format="auto", strict=False):
        """
        Create IntelHex from file

        :param file_pointer: file object opened by client code
        :param hex_format: either "I32" (rec_types 0,1,4,5)
            or "I16" (rec_types 0,1,2,3) or "auto"
        :param strict: determines whether conflicting file types cause program
            termination
        :returns: instance of IntelHex class
        """
        # parse file
        data, entry_point, detected_format = cls.parse_file(
            file_pointer, hex_format, strict)
        # create and return IntelHex
        return cls(data, entry_point), detected_format

    @staticmethod
    def parse_file(file_pointer, hex_format, strict):
        """
        Reads file and builds a data dict and an abstract entry point record

        :param file_pointer: file object opened by client code
        :param hex_format: either "I32" (rec_types 0,1,4,5)
            or "I16" (rec_types 0,1,2,3) or "auto"
        :param strict: determines whether conflicting file types cause program
            termination
        :returns: data, entry_point, hex_format (may have been auto detected)
        """
        illegal_rec_types = {"I32": (0x02, 0x03),
                             "I16": (0x04, 0x05)}
        # record types 0x00 (DATA)
        data = SortedDict()
        # record types 0x01 (EOF)
        encountered_eof = False
        # record types 0x02 or 0x04 (Extended Addresses)
        address_offset = 0
        # record types 0x03 or 0x05 (Start / Entry Points)
        entry_point = None

        for i, record in enumerate(file_pointer.readlines()):
            # remove whitespace
            record = "".join(record.split())
            if encountered_eof:
                raise IOError(("Reached EOF record before"
                               " record {}:\n{}").format(
                                   i, record))
            # simple check that this is a valid Intel HEX file
            if record[0] != ':':
                raise IOError(("This doesn't seem to be a valid Intel"
                               "HEX file, see line {}:\n{}").format(
                                   i, record))
            # check checksum
            if int(record[-2:], 16) != IntelHex.generate_checksum(record[1:-2]):
                raise IOError("Failed checksum for line {}, {} != {}".format(
                    i, record[-2:], IntelHex.generate_checksum(record[1:-2])))
            # extract info
            byte_count = int(record[1:3], 16)
            rec_address = int(record[3:7], 16)
            rec_type = int(record[7:9], 16)
            # check for illegal record types:
            if rec_type in range(2, 6):
                if hex_format == "auto":
                    # detect file type
                    hex_format = filter(
                        lambda el: rec_type not in illegal_rec_types[el],
                        illegal_rec_types)[0]
                    display_message("Detected file type {}".format(hex_format))
                if rec_type in illegal_rec_types[hex_format]:
                    msg = ("Illegal record type 0x{:02X} for"
                           "format {}").format(rec_type, hex_format)
                    if strict:
                        raise IOError(msg)
                    else:
                        display_message(msg, mode="warning")
            # get data string
            rec_data = record[9:(9 + (2 * byte_count))]
            if rec_type <= 0x01:
                rec_data = [int(el, 16) for el in split_string(rec_data, 2)]
            else:
                rec_data = int(rec_data, 16)
            # process info
            if rec_type == 0x00:
                # Data type
                new_entry = (address_offset + rec_address, rec_data)
                IntelHex.merge_data(data, new_entry)
            elif rec_type == 0x01:
                # EOF type
                encountered_eof = True
            elif rec_type == 0x02:
                # Extended Address I16HEX style
                address_offset = rec_data << 4
            elif rec_type == 0x03:
                # Entry Point I16HEX style
                # check that we don't already have one
                if entry_point is not None:
                    msg = "File has two start point records {}, {}".format(
                        i, record)
                    if strict:
                        raise IOError(msg)
                    else:
                        display_message(msg, mode="warning")
                segment = rec_data >> 16
                seg_offset = rec_data & 0xFFFF
                entry_point = (segment << 4) + seg_offset
            elif rec_type == 0x04:
                # Extended Address I32HEX style
                address_offset = rec_data << 0x10
            elif rec_type == 0x05:
                # Entry Point I32HEX style
                # check that we don't already have one
                if entry_point is not None:
                    msg = "File has two start point records {}, {}".format(
                        i, record)
                    if strict:
                        raise IOError(msg)
                    else:
                        display_message(msg, mode="warning")
                entry_point = rec_data
            else:
                raise IOError("Unknown record type 0x{:X}".format(rec_type))

        return data, entry_point, hex_format

    @staticmethod
    def generate_checksum(semi_record):
        """
        Generates a checksum in accordance with Intel HEX spec
        (two's complement of LSB of sum of all bytes)

        :param semi_record: Intel HEX record string w/o ':' or checksum
        :returns: checksum
        """
        data = [int(el, 16) for el in split_string(semi_record, 2)]
        data_sum_lsb = sum(data) & 0xFF
        return ((data_sum_lsb ^ 0xFF) + 1) & 0xFF

    @staticmethod
    def merge_data(data, new_entry):
        """
        Looks through the ordered data dict and either creates a new entry or
        appends / merges with an existing one

        :param data: data SortedDict of contiguous addresses *mutated*
        :param new_entry: tuple (start_addr, data_list) to be inserted / merged
            into data
        """
        if len(data) == 0:
            data[new_entry[0]] = new_entry[1]
            return

        if new_entry[0] in data:
            raise ValueError(
                "Duplicate start address found with {}".format(new_entry))

        # check for conflicts / merge opportunities with existing data
        # look for the closest addresses in data
        addresses = data.keys()
        prev_address = find_lt(addresses, new_entry[0])
        next_address = find_gt(addresses, new_entry[0])

        # deal with no next / prev address cases:
        if prev_address is None:
            prev_extent = float("-inf")
        else:
            prev_extent = prev_address + len(data[prev_address])
        if next_address is None:
            next_address = float("inf")

        # check for actual overlap - illegal (TODO - check it *is* illegal)
        new_extent = new_entry[0] + len(new_entry[1])
        if (prev_extent > new_entry[0]) or (new_extent > next_address):
            raise ValueError("Data overlap found in 0x{:X} {}".format(
                new_entry[0], map(hex, new_entry[1])))

        add_to_address = new_entry[0]
        # detect if touching previous
        if prev_extent == new_entry[0]:
            data[prev_address] = data[prev_address] + new_entry[1]
            add_to_address = prev_address
        # detect if touching next
        if new_extent == next_address:
            # remove next and add into new address or prev address post merge
            data[add_to_address] = new_entry[1] + data.pop(next_address)
        # no conflicts, just add
        if add_to_address not in data:
            data[add_to_address] = new_entry[1]


class SortedDict(dict):
    """Implements a dict and caches the keys list as a sorted array"""
    def __init__(self, *args):
        super(SortedDict, self).__init__(*args)
        # perform initial sort
        self._keys = sorted(super(SortedDict, self).keys())

    def keys(self):
        return self._keys

    def items(self):
        return [(k, super(SortedDict, self).__getitem__(k))
                for k in self._keys]

    def values(self):
        return map(lambda x: x[1], self.items())

    def __setitem__(self, key, val):
        # take advantage of timsort in python (fast on already sorted lists)
        if key not in super(SortedDict, self).keys():
            self._keys = sorted(self._keys + [key])
        super(SortedDict, self).__setitem__(key, val)

    def __delitem__(self, key):
        if key in self._keys:
            self._keys.remove(key)
        super(SortedDict, self).__delitem__(key)


def find_lt(l, x):
    """
    For a sorted list `l` finds rightmost value less than `x`

    :param l: sorted list
    :param x: search term

    :returns: value found, or None if none found
    """
    i = bisect.bisect_left(l, x)
    if i:
        return l[i-1]
    return None


def find_gt(l, x):
    """
    For a sorted list `l` finds leftmost value greater than `x`

    :param l: sorted list
    :param x: search term

    :returns: value found, or None if none found
    """
    i = bisect.bisect_right(l, x)
    if i != len(l):
        return l[i]
    return None


def split_string(text, n):
    """
    Splits a string up into n sized chunks

    :param text: input string
    :param n: chunk size
    """
    return [text[i:i + n] for i in range(0, len(text), n)]


def parse_args(args):
    """
    Setup argparsing for standalone use
    """
    parser = argparse.ArgumentParser(
        description="Intel HEX file parser / writer")
    parser.add_argument("input", help="file to read")
    parser.add_argument("--output", "-o",
                        help="output to file specified")
    parser.add_argument("--type-output", "-t",
                        choices=("I16", "I32"),
                        help="type of hex format for output file (I16 or I32)")

    return parser.parse_args(args)


def display_message(string, mode="action"):
    """
    Prints the string in a predetermined format

    :param string: info string to print
    """
    if mode == "action":
        print " - {}".format(string)
    elif mode == "warning":
        print "!! {}".format(string)
    elif mode == "error":
        print "?? {}".format(string)


def main(args):
    args = parse_args(args)

    input_file = args.input
    output_file = args.output
    output_type = args.type_output

    if not os.path.isfile(input_file):
        display_message("{} is not a valid filepath".format(input_file),
                        mode="error")
        sys.exit(1)

    if not os.path.isdir(os.path.dirname(output_file)):
        display_message("{} isn't a valid directory path".format(
            os.path.dirname(output_file)), mode="error")
        sys.exit(1)

    with open(input_file, "r") as fp:
        hex_obj, detected_format = IntelHex.read_from_file(fp)

    display_message("File parsed successfully: {}".format(input_file))

    if detected_format == output_type:
        display_message("{} is already in the requested format ({})".format(
            input_file, output_type), mode="error")
        sys.exit(1)

    display_message("Writing {} -> {} (format {})".format(
        input_file, output_file, output_type))

    with open(output_file, "w") as fp:
        hex_obj.write(fp, hex_format=output_type)

    display_message("File written successfully: {}".format(output_file))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
