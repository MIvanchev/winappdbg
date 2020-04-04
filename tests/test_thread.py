from mock import patch

import unittest
import winappdbg
import winappdbg.win32

DataReadOnly                        = 0
DataReadOnlyAccessed                = 1
DataReadWrite                       = 2
DataReadWriteAccessed               = 3
DataReadOnlyExpandDown              = 4
DataReadOnlyExpandDownAccessed      = 5
DataReadWriteExpandDown             = 6
DataReadWriteExpandDownAccessed     = 7
CodeExecuteOnly                     = 8
CodeExecuteOnlyAccessed             = 9
CodeExecuteRead                     = 10
CodeExecuteReadAccessed             = 11
CodeExecuteOnlyConforming           = 12
CodeExecuteOnlyConformingAccessed   = 13
CodeExecuteReadConforming           = 14
CodeExecuteReadConformingAccessed   = 15

class Segment(object):

    ldt = winappdbg.win32.LDT_ENTRY()

    def __init__(self, type):
        self.ldt.LimitLow                   = 0
        self.ldt.BaseLow                    = 0
        self.ldt.HighWord.BaseMid           = 0
        self.ldt.HighWord.Flags1            = 0
        self.ldt.HighWord.Flags2            = 0
        self.ldt.HighWord.BaseHi            = 0
        self.ldt.HighWord.Bits.BaseMid      = 0
        self.ldt.HighWord.Bits.Type         = (1 << 4) | type
        self.ldt.HighWord.Bits.Dpl          = 0
        self.ldt.HighWord.Bits.Pres         = 0
        self.ldt.HighWord.Bits.LimitHi      = 0
        self.ldt.HighWord.Bits.Sys          = 0
        self.ldt.HighWord.Bits.Reserved_0   = 0
        self.ldt.HighWord.Bits.Default_Big  = 0
        self.ldt.HighWord.Bits.Granularity  = 0

    def with_base_address(self, address):
        self.ldt.BaseLow = address & 0xFFFF
        self.ldt.HighWord.Bytes.BaseMid = (address >> 16) & 0xFF
        self.ldt.HighWord.Bytes.BaseHi = address >> 24
        return self

    def and_with_limit_in_bytes(self, limit):
        self.ldt.LimitLow = limit & 0xFFFF
        self.ldt.HighWord.Bits.LimitHi = limit >> 16
        self.ldt.HighWord.Bits.Granularity = 0
        return self

    def and_with_limit_in_pages(self, limit):
        self.ldt.LimitLow = limit & 0xFFFF
        self.ldt.HighWord.Bits.LimitHi = limit >> 16
        self.ldt.HighWord.Bits.Granularity = 1
        return self

    def and_with_max_offset_0xFFFF(self):
        self.ldt.HighWord.Bits.Default_Big = 0
        return self

    def and_with_max_offset_0xFFFFFFFF(self):
        self.ldt.HighWord.Bits.Default_Big = 1
        return self

    @property
    def descriptor(self):
        return self.ldt

def system_descriptor():
    ldt = winappdbg.win32.LDT_ENTRY()
    ldt.HighWord.Bits.Type = 1 << 5
    return ldt

def descriptor_for_a(segment):
    return segment.descriptor

def segment_of_type(type):
    return Segment(type)

def get_register_mock(reg):
    return patch.object(winappdbg.Thread, 'get_register', return_value=reg)

class ThreadTests(unittest.TestCase):

    @patch('winappdbg.win32.GetThreadSelectorEntry')
    @patch('winappdbg.Thread.get_handle')
    @patch('winappdbg.Thread.get_bits', return_value = 32)
    def test_get_linear_address(
            self, mock_get_bits, mock_get_handle, mock_GetThreadSelectorEntry):

        # Test system descriptor

        mock_GetThreadSelectorEntry.return_value = system_descriptor();

        with get_register_mock(50), self.assertRaises(ValueError) as cm:
            winappdbg.Thread(4096).get_linear_address('SegCs', 0xFF002700)

        self.assertEqual(
            cm.exception.message,
            "Selector 50 (register CS) identifies a system descriptor.")

        # Test expand down data segment, offset below limit

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(DataReadOnlyExpandDown)
                .with_base_address(0x100)
                .and_with_limit_in_bytes(0x2FF)
                .and_with_max_offset_0xFFFF()))

        with self.assertRaises(ValueError) as cm:
            winappdbg.Thread(70944).get_linear_address(24, 0x200)

        self.assertEqual(
            cm.exception.message,
            "Offset 00000200 is invalid for the segment with selector 24. The "
            "segment spans the bytes from offset 00000300 through 0000FFFF.")

        # Test expand down data segment, offset above maximum 0xFFFF

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(DataReadOnlyExpandDownAccessed)
                .with_base_address(0)
                .and_with_limit_in_pages(4)
                .and_with_max_offset_0xFFFF()))

        with get_register_mock(4), self.assertRaises(ValueError) as cm:
            winappdbg.Thread(14031).get_linear_address('SegSs', 0x10004)

        self.assertEqual(
            cm.exception.message,
            "Offset 00010004 is invalid for the segment with selector 4 "
            "(register SS). The segment spans the bytes from offset 00005000 "
            "through 0000FFFF.")

        # Test expand down data segment; offset below maximum 0xFFFFFFFF, but
        # above 0xFFFF

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(DataReadWriteExpandDownAccessed)
                .with_base_address(0x84F4)
                .and_with_limit_in_bytes(0x9007F530)
                .and_with_max_offset_0xFFFFFFFF()))

        self.assertEqual(
            winappdbg.Thread(4933).get_linear_address(91, 0x321149A),
            0x84F4 + 0x321149A)

        # Test expand down data segment, valid offset

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(DataReadOnlyExpandDownAccessed)
                .with_base_address(0x10)
                .and_with_limit_in_pages(9)
                .and_with_max_offset_0xFFFF()))

        self.assertEqual(
            winappdbg.Thread(99407).get_linear_address(17, 0xABCD),
            0x10 + 0xABCD)

        # Test code segment, offset above limit

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(CodeExecuteOnly)
                .with_base_address(0)
                .and_with_limit_in_bytes(0x7FFF)))

        with self.assertRaises(ValueError) as cm:
            winappdbg.Thread(77530).get_linear_address(40, 0x8000)

        self.assertEqual(
            cm.exception.message,
            "Offset 00008000 is invalid for the segment with selector 40. The "
            "segment spans the bytes from offset 00000000 through 00007FFF.")

        # Test code segment, max offset has no effect

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(CodeExecuteReadAccessed)
                .with_base_address(0)
                .and_with_limit_in_bytes(0x7FFFA)
                .and_with_max_offset_0xFFFF()))

        with get_register_mock(50):
            self.assertEqual(
                winappdbg.Thread(83120).get_linear_address('SegDs', 0x43097),
                0x43097)

        # Test code segment, conforming not misinterpreted for expand down

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(CodeExecuteOnlyConforming)
                .with_base_address(0x140)
                .and_with_limit_in_pages(0xE4)))

        self.assertEqual(
            winappdbg.Thread(1725509).get_linear_address(99, 0xF031),
            0x140 + 0xF031)

         # Test empty segment

        mock_GetThreadSelectorEntry.return_value = (
            descriptor_for_a(
                segment_of_type(DataReadOnlyExpandDown)
                .with_base_address(0)
                .and_with_limit_in_bytes(0xFFFF)))

        with get_register_mock(127), self.assertRaises(ValueError) as cm:
            winappdbg.Thread(430051).get_linear_address('SegSs', 0x1000)

        self.assertEqual(
            cm.exception.message,
            "Offset 00001000 is invalid for the segment with selector 127 "
            "(register SS). The segment does not span any memory locations.")
