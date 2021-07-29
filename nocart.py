#!/usr/bin/python3

# pylint: disable=logging-fstring-interpolation,missing-class-docstring

"""nocart_python v0.2.0
This program is a Python port of nocart.
http://www.cpcwiki.eu/index.php/Nocart

Action description:

create:
    create a .cpr file from a .dsk file, to be used on a GX-4000

dumpdsk:
    dump all content of .dsk file, as if it was written on a .cpr file.
    Can be used to patch directly the content before generating the .cpr.

check:
    check an existing .cpr file
"""

import argparse
import enum
import logging
import struct

from functools import partial
from itertools import (
    count,
    islice,
    product,
)
from pathlib import Path
from typing import (
    BinaryIO,
    Dict,
    Iterator,
    List,
    Optional,
)


MAX_NUM_CHUNKS = 32
CART_CHUNK_SIZE = 0x4000
SECTOR_SIZE = 512
BASIC_COMMAND_LENGTH = 16

DEFAULT_ROM_LOCATION = Path(__file__).absolute().parent.joinpath("patched_roms")
RIFF_HEADER_STRUCT = struct.Struct(b"<4sI4s")
CHUNK_HEADER_STRUCT = struct.Struct(b"<4sI")
RIFF_TAG = b"RIFF"
AMS_TAG = b"AMS!"


class NoCartException(Exception):
    pass


class DskFileException(NoCartException):
    pass


class DskSector:
    """
    Gives access to a sector informations and content
    """
    def __init__(self, raw_sector_header: bytes, file: BinaryIO, length: int):
        self.file = file
        self.offset = file.tell()

        self.track = raw_sector_header[0x00]
        self.side = raw_sector_header[0x01]
        self.identifier = raw_sector_header[0x02]
        self.size = 0x80 << raw_sector_header[0x03]
        self.length = raw_sector_header[0x06] + raw_sector_header[0x07] * 0x100

        self.file.seek(length, 1)

        if (self.length and self.length != length) or self.size != length:
            raise DskFileException(
                "Sector length found does not match sector length declared in track."
            )

    def content(self) -> bytes:
        self.file.seek(self.offset)
        return self.file.read(self.size)


class DskTrack:
    """
    Accessor helper for track information
    """
    def __init__(self, file: BinaryIO):
        self.file = file
        self.offset = file.tell()

        track_header = self.file.read(0x100)
        if track_header[0x00:0x0A] != b"Track-Info":
            raise DskFileException("Invalid track (no Track-Info).")

        self.number = track_header[0x10]
        self.side = track_header[0x11]
        self.sectors_size = 0x80 << track_header[0x14]
        self.sectors_number = track_header[0x15]
        self.sectors: Dict[int, DskSector] = {}

        for idx in range(self.sectors_number):
            start = 8 * idx + 0x18
            sector = DskSector(track_header[start:start + 8], self.file, self.sectors_size)
            self.sectors[sector.identifier] = sector

    def generate_sorted_sectors(self) -> Iterator[DskSector]:
        for sector_id in sorted(self.sectors):
            yield self.sectors[sector_id]


class DskFile:
    """
    This class maps access to a .dsk file.
    """
    def __init__(self, filepath: Path):
        self.file = filepath.open("rb")
        self.is_read_only = True

        self.format: bytes = self.file.read(34)
        self.creator: bytes = self.file.read(14)
        self.tracks_nb: int = ord(self.file.read(1))
        self.sides_nb: int = ord(self.file.read(1))
        track_size: int = int.from_bytes(self.file.read(2), byteorder="little", signed=False)

        self.extended = True
        if self.format[0:8] == b"MV - CPC":
            self.extended = False
        elif self.format[0:3] != b"EXT":
            raise DskFileException(
                "Only MV - CPCEMU or Extended DSK are supported.")

        if self.extended:
            self.tracks_sizes = [
                sz * 0x100
                for sz in self.file.read(self.tracks_nb * self.sides_nb)
            ]
        else:
            self.tracks_sizes = [
                track_size for _ in range(self.tracks_nb * self.sides_nb)
            ]

        if not self.tracks_sizes:
            raise DskFileException("Tracks sizes problem.")

        self.tracks: List[DskTrack] = []
        self._read_tracks()

    def _read_tracks(self) -> None:
        # Reading Tracks.
        self.file.seek(0x100)
        for track_idx, (track_id, side_id) in enumerate(product(range(self.tracks_nb), range(self.sides_nb))):
            declared_track_size = self.tracks_sizes[track_idx]
            if declared_track_size:
                track = DskTrack(self.file)
                actual_size = self.file.tell() - track.offset
                if actual_size != declared_track_size:
                    raise DskFileException(
                        f"Track number {track_idx} has size {actual_size}, doesn't match declared {declared_track_size}"
                    )
                if track.side != side_id or track.number != track_id:
                    raise DskFileException(
                        f"Found track number {track_idx} at offset {track.offset} "
                        f"with side id {track.side} and track id {track.number} "
                        f"when {side_id} and {track_id} are expected."
                    )
                self.tracks.append(track)

    def __str__(self) -> str:
        return "{1} sided {2} disk image containing {0.tracks_nb} " \
            "tracks per side ({3} tracks actually present)".format(
                self,
                {
                    1: "One",
                    2: "Two"
                }[self.sides_nb],
                {
                    True: "Extended",
                    False: "CPCEMU"
                }[self.extended],
                len(self.tracks)
            )

    def get_min_sector_id(self) -> int:
        return min(self.tracks[0].sectors.keys())

    def generate_sectors_content(self):
        for idx, track in enumerate(self.tracks):
            for sector in track.generate_sorted_sectors():
                logging.debug(f"Reading sector &{sector.identifier:02X} from track {idx}")
                yield sector.content()


class CprFile:
    def __init__(self):
        self.chunks: List[bytes] = []
        self.chunk_size = CART_CHUNK_SIZE

    def add_rom(self, rom_path: Path) -> None:
        content = rom_path.read_bytes()
        if len(content) > self.chunk_size:
            raise NoCartException(f"File {rom_path} is larger than 0x{self.chunk_size:04x}")
        self.chunks.append(content)

    def write(self, target: Path) -> None:
        if len(self.chunks) > MAX_NUM_CHUNKS:
            raise NoCartException(f"Too many chunks ({len(self.chunks)}) for a CPR file.")
        with target.open("wb") as cpr_file:
            riff_size = len(AMS_TAG) + (self.chunk_size + CHUNK_HEADER_STRUCT.size) * len(self.chunks)
            cpr_file.write(RIFF_HEADER_STRUCT.pack(RIFF_TAG, riff_size, AMS_TAG))
            for idx, chunk in enumerate(self.chunks):
                ckid = f"cb{idx:02}".encode()
                cpr_file.write(CHUNK_HEADER_STRUCT.pack(ckid, self.chunk_size))
                cpr_file.write(chunk)
                if len(chunk) < self.chunk_size:
                    padding_size = self.chunk_size - len(chunk)
                    logging.info(f"Padding chunk {ckid!r} by adding {padding_size} * '0xff'.")
                    cpr_file.write(padding_size * b"\xff")


class NoCartFile(CprFile):
    def __init__(self, input_dsk: DskFile, command: Optional[str], rom_path: Path):
        super().__init__()
        self.command = command
        self.rom_path = rom_path
        self.input_dsk = input_dsk

    def _add_amsdos_chunk(self) -> None:
        amsdos_content = bytearray((self.rom_path / "amsdos.rom").read_bytes())
        if self.command:
            bytes_patch = self.command.encode()
            bytes_patch += (BASIC_COMMAND_LENGTH - len(bytes_patch)) * b"\x00"
            amsdos_content[0X1C04:0X1C04 + BASIC_COMMAND_LENGTH] = bytes_patch
        else:
            amsdos_content[0x1C03] = 0

        if self.input_dsk.extended:
            logging.info("Patching rom for extended disk format")
            patch = bytes([
                0x24, 0x00, 0x03, 0x07, 0x00, 0xfe, 0x00, 0x3f, 0x00, 0xc0, 0x00,
                0x10, 0x00, 0x00, 0x00, 0xc1, 0x09, 0x2a, 0x52, 0xe5, 0x02, 0x04
            ])
            amsdos_content[0x0A43:0x0A43 + len(patch)] = patch
            amsdos_content[0x056d] = 0x41
        else:
            min_sector_id = self.input_dsk.get_min_sector_id()
            logging.info(f"CPC MV format. Min sector id is &{min_sector_id:02X}")
            amsdos_content[0x056d] = min_sector_id
        self.chunks.append(amsdos_content)

    def generate_chunks(self):
        assert CART_CHUNK_SIZE // SECTOR_SIZE * SECTOR_SIZE == CART_CHUNK_SIZE
        generator = self.input_dsk.generate_sectors_content()
        while chunk_pieces := list(islice(generator, CART_CHUNK_SIZE // SECTOR_SIZE)):
            yield b"".join(chunk_pieces)

    def write(self, target: Path) -> None:
        self.add_rom(self.rom_path / "os.rom")
        self.add_rom(self.rom_path / "basic.rom")
        self._add_amsdos_chunk()
        for chunk in self.generate_chunks():
            self.chunks.append(chunk)
        super().write(target)


def check_cpr(args: argparse.Namespace) -> None:
    cpr_path = args.source_file
    logging.info(f"Checking file {cpr_path}")
    with cpr_path.open("rb") as cpr_file:
        raw_size = cpr_path.stat().st_size
        try:
            riff_tag, riff_size, ams_tag = RIFF_HEADER_STRUCT.unpack_from(cpr_file.read(RIFF_HEADER_STRUCT.size))
        except struct.error as exc:
            raise NoCartException("Cannot read file header") from exc
        logging.info(f"File tag: {riff_tag.decode()}, size {riff_size}, type {ams_tag.decode()}")
        if riff_tag != RIFF_TAG:
            raise NoCartException("Not a RIFF file")
        if ams_tag != AMS_TAG:
            raise NoCartException("Not a CPR file")
        if raw_size != riff_size + 8:
            raise NoCartException(f"File size {raw_size} doesn't match size in header {riff_size} + 8")
        some_chunks_found = False

        for chunk_idx in count():
            if cpr_file.tell() >= riff_size + 8:
                break
            some_chunks_found = True
            _check_chunk(cpr_file, chunk_idx)
    if some_chunks_found:
        logging.info(f"File seems OK and contains {chunk_idx} chunks!")
    else:
        logging.warning("Files is correct but contains no chunks.")


def _check_chunk(cpr_file: BinaryIO, chunk_idx: int):
    header_location = cpr_file.tell()
    header = cpr_file.read(CHUNK_HEADER_STRUCT.size)
    try:
        chunk_tag, chunk_size = CHUNK_HEADER_STRUCT.unpack_from(header)
    except struct.error as exc:
        raise NoCartException(f"Cannot read chunk header number {chunk_idx} @ 0x{header_location:X}") from exc

    logging.info(f"Chunk {chunk_idx:02} @ 0x{header_location:X}: {chunk_tag.decode()}. Size: 0x{chunk_size:04x}")
    if chunk_size != CART_CHUNK_SIZE:
        logging.warning(f"Chunk {chunk_idx:02} size is not 0x{CART_CHUNK_SIZE:X}, required for cpr files.")
    expected_tag = f"cb{chunk_idx:02}"
    if chunk_tag != expected_tag.encode():
        raise NoCartException(f"Chunk tag {chunk_tag} not matching pattern {expected_tag}")

    read_count = len(cpr_file.read(chunk_size))
    if read_count != chunk_size:
        raise NoCartException(
            f"Chunk {chunk_idx:02} @ 0x{header_location:X} seems truncated. "
            f"Read {read_count} of {chunk_size}."
        )


def dump_dsk(args: argparse.Namespace) -> None:
    dsk_file = DskFile(args.input_file)
    logging.info(f"Dumping dsk file {args.input_file} into {args.output_file}")
    sector_data = b"".join(dsk_file.generate_sectors_content())
    args.output_file.write_bytes(sector_data)


def create_cpr(args: argparse.Namespace) -> None:
    if args.command and len(args.command) > BASIC_COMMAND_LENGTH:
        logging.error(f"Basic command must be shorter than {BASIC_COMMAND_LENGTH} chars")
    dsk_file = DskFile(args.input_file)
    logging.info(f"Reading dsk file {args.input_file}")
    logging.info(str(dsk_file))
    no_cart = NoCartFile(dsk_file, args.command, args.rompath)
    no_cart.write(args.output_file)


class Actions(enum.Enum):
    check = partial(check_cpr)
    create = partial(create_cpr)
    dumpdsk = partial(dump_dsk)

    def __call__(self, args: argparse.Namespace):
        self.value(args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=[action.name for action in Actions], help="action")
    parser.add_argument("input_file", type=Path, help="Input file")
    parser.add_argument("output_file", nargs="?", type=Path, help="Target file")
    parser.add_argument("-v", "--verbose", action="store_true", help='Print debug logs.')
    parser.add_argument("-c", "--command", help='Command to start game, eg: |cpm or run"disc"')
    parser.add_argument("--rompath", type=Path, default=DEFAULT_ROM_LOCATION,
                        help='Path where the CPC ROM file are stored. Default: %(default)s')
    return parser.parse_args()


def main():
    args = parse_args()
    loglevel = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=loglevel, format="%(levelname)s:%(message)s")

    try:
        Actions[args.action](args)
    except NoCartException as exc:
        logging.error(exc)


if __name__ == "__main__":
    main()
