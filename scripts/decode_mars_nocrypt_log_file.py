#!/usr/bin/env python3
# DESCRIPTION: Mars 未加密 xlog：只做压缩解压（zlib / zstd）
# Python 3 port of Tencent Mars decode_mars_nocrypt_log_file.py (CLI compatible)

import glob
import os
import struct
import sys
import traceback
import zlib

import zstandard as zstd

MAGIC_NO_COMPRESS_START = 0x03
MAGIC_NO_COMPRESS_START1 = 0x06
MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08
MAGIC_COMPRESS_START = 0x04
MAGIC_COMPRESS_START1 = 0x05
MAGIC_COMPRESS_START2 = 0x07
MAGIC_COMPRESS_NO_CRYPT_START = 0x09

MAGIC_SYNC_ZSTD_START = 0x0A
MAGIC_SYNC_NO_CRYPT_ZSTD_START = 0x0B
MAGIC_ASYNC_ZSTD_START = 0x0C
MAGIC_ASYNC_NO_CRYPT_ZSTD_START = 0x0D

MAGIC_END = 0x00

lastseq = 0


def _mv(buf, offset, size):
    return memoryview(buf)[offset : offset + size]


def _ext_text(out, text):
    out.extend(text.encode("utf-8", errors="replace"))


class ZstdDecompressReader:
    def __init__(self, data):
        self.buffer = bytes(data)

    def read(self, size):
        return self.buffer


def IsGoodLogBuffer(_buffer, _offset, count):
    if _offset == len(_buffer):
        return (True, "")

    magic_start = _buffer[_offset]
    if magic_start in (MAGIC_NO_COMPRESS_START, MAGIC_COMPRESS_START, MAGIC_COMPRESS_START1):
        crypt_key_len = 4
    elif magic_start in (
        MAGIC_COMPRESS_START2,
        MAGIC_NO_COMPRESS_START1,
        MAGIC_NO_COMPRESS_NO_CRYPT_START,
        MAGIC_COMPRESS_NO_CRYPT_START,
        MAGIC_SYNC_ZSTD_START,
        MAGIC_SYNC_NO_CRYPT_ZSTD_START,
        MAGIC_ASYNC_ZSTD_START,
        MAGIC_ASYNC_NO_CRYPT_ZSTD_START,
    ):
        crypt_key_len = 64
    else:
        return (False, "_buffer[%d]:%d != MAGIC_NUM_START" % (_offset, _buffer[_offset]))

    header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len
    if _offset + header_len + 1 + 1 > len(_buffer):
        return (False, "offset:%d > len(buffer):%d" % (_offset, len(_buffer)))
    length = struct.unpack_from("I", _mv(_buffer, _offset + header_len - 4 - crypt_key_len, 4))[0]
    if _offset + header_len + length + 1 > len(_buffer):
        return (
            False,
            "log length:%d, end pos %d > len(buffer):%d"
            % (length, _offset + header_len + length + 1, len(_buffer)),
        )
    if MAGIC_END != _buffer[_offset + header_len + length]:
        return (
            False,
            "log length:%d, buffer[%d]:%d != MAGIC_END"
            % (length, _offset + header_len + length, _buffer[_offset + header_len + length]),
        )

    if 1 >= count:
        return (True, "")
    return IsGoodLogBuffer(_buffer, _offset + header_len + length + 1, count - 1)


def GetLogStartPos(_buffer, _count):
    offset = 0
    while offset < len(_buffer):
        if _buffer[offset] in (
            MAGIC_NO_COMPRESS_START,
            MAGIC_NO_COMPRESS_START1,
            MAGIC_COMPRESS_START,
            MAGIC_COMPRESS_START1,
            MAGIC_COMPRESS_START2,
            MAGIC_COMPRESS_NO_CRYPT_START,
            MAGIC_NO_COMPRESS_NO_CRYPT_START,
            MAGIC_SYNC_ZSTD_START,
            MAGIC_SYNC_NO_CRYPT_ZSTD_START,
            MAGIC_ASYNC_ZSTD_START,
            MAGIC_ASYNC_NO_CRYPT_ZSTD_START,
        ):
            if IsGoodLogBuffer(_buffer, offset, _count)[0]:
                return offset
        offset += 1
    return -1


def DecodeBuffer(_buffer, _offset, _outbuffer):
    global lastseq

    if _offset >= len(_buffer):
        return -1

    ret = IsGoodLogBuffer(_buffer, _offset, 1)
    if not ret[0]:
        fixpos = GetLogStartPos(_buffer[_offset:], 1)
        if fixpos == -1:
            return -1
        _ext_text(_outbuffer, "[F]decode_log_file.py decode error len=%d, result:%s \n" % (fixpos, ret[1]))
        _offset += fixpos

    magic_start = _buffer[_offset]
    if magic_start in (MAGIC_NO_COMPRESS_START, MAGIC_COMPRESS_START, MAGIC_COMPRESS_START1):
        crypt_key_len = 4
    elif magic_start in (
        MAGIC_COMPRESS_START2,
        MAGIC_NO_COMPRESS_START1,
        MAGIC_NO_COMPRESS_NO_CRYPT_START,
        MAGIC_COMPRESS_NO_CRYPT_START,
        MAGIC_SYNC_ZSTD_START,
        MAGIC_SYNC_NO_CRYPT_ZSTD_START,
        MAGIC_ASYNC_ZSTD_START,
        MAGIC_ASYNC_NO_CRYPT_ZSTD_START,
    ):
        crypt_key_len = 64
    else:
        _ext_text(_outbuffer, "in DecodeBuffer _buffer[%d]:%d != MAGIC_NUM_START" % (_offset, magic_start))
        return -1

    header_len = 1 + 2 + 1 + 1 + 4 + crypt_key_len
    length = struct.unpack_from("I", _mv(_buffer, _offset + header_len - 4 - crypt_key_len, 4))[0]
    tmpbuffer = bytearray(length)

    seq = struct.unpack_from("H", _mv(_buffer, _offset + header_len - 4 - crypt_key_len - 2 - 2, 2))[0]

    if seq != 0 and seq != 1 and lastseq != 0 and seq != (lastseq + 1):
        _ext_text(_outbuffer, "[F]decode_log_file.py log seq:%d-%d is missing\n" % (lastseq + 1, seq - 1))

    if seq != 0:
        lastseq = seq

    tmpbuffer[:] = _buffer[_offset + header_len : _offset + header_len + length]

    try:
        magic = _buffer[_offset]
        if magic in (MAGIC_NO_COMPRESS_START1, MAGIC_COMPRESS_START2, MAGIC_SYNC_ZSTD_START, MAGIC_ASYNC_ZSTD_START):
            print("use wrong decode script")
            _ext_text(_outbuffer, "[F]use wrong decode script (need Mars crypt decoder)\n")
        elif magic == MAGIC_ASYNC_NO_CRYPT_ZSTD_START or magic == MAGIC_SYNC_NO_CRYPT_ZSTD_START:
            decompressor = zstd.ZstdDecompressor()
            tmpbuffer = bytearray(decompressor.decompress(bytes(tmpbuffer)))
        elif magic in (MAGIC_COMPRESS_START, MAGIC_COMPRESS_NO_CRYPT_START):
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = bytearray(decompressor.decompress(bytes(tmpbuffer)))
        elif magic == MAGIC_COMPRESS_START1:
            decompress_data = bytearray()
            while len(tmpbuffer) > 0:
                single_log_len = struct.unpack_from("H", _mv(tmpbuffer, 0, 2))[0]
                decompress_data.extend(tmpbuffer[2 : single_log_len + 2])
                tmpbuffer[:] = tmpbuffer[single_log_len + 2 :]
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            tmpbuffer = bytearray(decompressor.decompress(bytes(decompress_data)))
        else:
            pass
    except Exception as e:
        traceback.print_exc()
        _ext_text(_outbuffer, "[F]decode_log_file.py decompress err, " + str(e) + "\n")
        return _offset + header_len + length + 1

    _outbuffer.extend(tmpbuffer)
    return _offset + header_len + length + 1


def ParseFile(_file, _outfile):
    with open(_file, "rb") as fp:
        _buffer = bytearray(os.path.getsize(_file))
        fp.readinto(_buffer)

    startpos = GetLogStartPos(_buffer, 2)
    if startpos == -1:
        return

    outbuffer = bytearray()
    while True:
        startpos = DecodeBuffer(_buffer, startpos, outbuffer)
        if startpos == -1:
            break

    if len(outbuffer) == 0:
        return

    with open(_outfile, "wb") as fpout:
        fpout.write(outbuffer)


def main(args):
    global lastseq

    if len(args) == 1:
        if os.path.isdir(args[0]):
            for filepath in glob.glob(args[0] + "/*.xlog"):
                lastseq = 0
                ParseFile(filepath, filepath + ".log")
        else:
            ParseFile(args[0], args[0] + ".log")
    elif len(args) == 2:
        ParseFile(args[0], args[1])
    else:
        for filepath in glob.glob("*.xlog"):
            lastseq = 0
            ParseFile(filepath, filepath + ".log")


if __name__ == "__main__":
    main(sys.argv[1:])
