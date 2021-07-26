"""
This is a pytest script used to test some parts of nocart.py.

It can be run with `pytest -vv test_nocart.py`.
"""

import logging

import pytest

import nocart


def test_CprFile(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    target = tmp_path / "plop.cpr"
    cpr_file = nocart.CprFile()
    for rom_idx in range(4):
        rompath = tmp_path / f"rom_{rom_idx}"
        rompath.write_bytes(f"ROM_{rom_idx}_CONTENT".encode() + 16371 * b"\0")
        cpr_file.add_rom(rompath)
    smallrompath = tmp_path / f"rom_4"
    smallrompath.write_bytes(f"ROM_PADDED_CONTENT".encode())
    cpr_file.add_rom(smallrompath)
    cpr_file.write(target)
    nocart.check_cpr(target)
    assert caplog.record_tuples[0] == ('root', 30, "Padding chunk b'cb04' by adding 16366 * '0xff'.")
    assert caplog.record_tuples[1][2].startswith("Checking file")
    assert caplog.record_tuples[1][2].endswith("plop.cpr")
    assert caplog.record_tuples[2:] == [
        ('root', 20, 'File tag: RIFF, size 81964, type AMS!'),
        ('root', 20, 'Chunk 00 @ 0xC: cb00. Size: 0x4000'),
        ('root', 20, 'Chunk 01 @ 0x4014: cb01. Size: 0x4000'),
        ('root', 20, 'Chunk 02 @ 0x801C: cb02. Size: 0x4000'),
        ('root', 20, 'Chunk 03 @ 0xC024: cb03. Size: 0x4000'),
        ('root', 20, 'Chunk 04 @ 0x1002C: cb04. Size: 0x4000'),
        ('root', 20, 'File seems OK and contains 5 chunks!'),
    ]
    content = target.read_bytes()
    assert content[20:33] == b"ROM_0_CONTENT"
    assert content[20 + 0x4008:33 + 0x4008] == b"ROM_1_CONTENT"
    assert content[20 + 0x8010:33 + 0x8010] == b"ROM_2_CONTENT"
    assert content[20 + 0xC018:33 + 0xC018] == b"ROM_3_CONTENT"
    assert content[20 + 0x10020:38 + 0x10020] == b"ROM_PADDED_CONTENT"

@pytest.mark.parametrize(("content", "error_message"), [
    (b"xxxx", "Cannot read file header"),
    (b"FIRR\x00\x00\x00\x00plop", "Not a RIFF file"),
    (b"RIFF\x00\x00\x00\x00plop", "Not a CPR file"),
    (b"RIFF\x00\x00\x00\x00AMS!", "File size 12 doesn't match size in header 0 + 8"),
    (b"RIFF\x0C\x00\x00\x00AMS!pwetpwet", "Chunk tag b'pwet' not matching pattern cb00"),
    (b"RIFF\x08\x00\x00\x00AMS!pwet", "Cannot read chunk header number 0 @ 0xC"),
    (b"RIFF\x08\x00\x00\x00AMS!cb00", "Cannot read chunk header number 0 @ 0xC"),
    (b"RIFF\x12\x00\x00\x00AMS!cb00\x10\x00\x00\x00abcdef", "Chunk 00 @ 0xC seems truncated. Read 6 of 16."),
])
def test_check_cpr_errors(tmp_path, content, error_message):
    target = tmp_path / "plop.cpr"
    target.write_bytes(content)
    with pytest.raises(expected_exception=nocart.NoCartException) as exc_wrapper:
        nocart.check_cpr(target)
    assert str(exc_wrapper.value) == error_message


def test_check_cpr(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    target = tmp_path / "plop.cpr"
    target.write_bytes(b"RIFF\x22\x00\x00\x00AMS!cb00\x06\x00\x00\x00abcdefcb01\x08\x00\x00\x00abcdefgh")
    nocart.check_cpr(target)
    assert caplog.record_tuples[0][2].startswith("Checking file")
    assert caplog.record_tuples[0][2].endswith("plop.cpr")
    assert caplog.record_tuples[1:] == [
        ('root', 20, 'File tag: RIFF, size 34, type AMS!'),
        ('root', 20, 'Chunk 00 @ 0xC: cb00. Size: 0x0006'),
        ('root', 30, 'Chunk 00 size is not 0x4000, required for cpr files.'),
        ('root', 20, 'Chunk 01 @ 0x1A: cb01. Size: 0x0008'),
        ('root', 30, 'Chunk 01 size is not 0x4000, required for cpr files.'),
        ('root', 20, 'File seems OK and contains 2 chunks!'),
    ]


def test_check_cpr_empty(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    target = tmp_path / "plop.cpr"
    target.write_bytes(b"RIFF\x04\x00\x00\x00AMS!")
    nocart.check_cpr(target)
    assert caplog.record_tuples[0][2].startswith("Checking file")
    assert caplog.record_tuples[0][2].endswith("plop.cpr")
    assert caplog.record_tuples[1:] == [
        ('root', 20, 'File tag: RIFF, size 4, type AMS!'),
        ('root', 30, 'Files is correct but contains no chunks.'),
    ]
