import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

Uint8List sha1Digest(Uint8List data) {
  final lengthBits = data.length * 8;
  final paddingLength = ((56 - ((data.length + 1) % 64)) % 64 + 64) % 64;
  final padded = Uint8List(data.length + 1 + paddingLength + 8);
  padded.setRange(0, data.length, data);
  padded[data.length] = 0x80;
  final paddedData = ByteData.sublistView(padded);
  paddedData.setUint32(padded.length - 4, lengthBits & 0xffffffff, Endian.big);
  paddedData.setUint32(
    padded.length - 8,
    (lengthBits ~/ 0x100000000) & 0xffffffff,
    Endian.big,
  );

  var h0 = 0x67452301;
  var h1 = 0xefcdab89;
  var h2 = 0x98badcfe;
  var h3 = 0x10325476;
  var h4 = 0xc3d2e1f0;

  final words = Uint32List(80);
  for (var offset = 0; offset < padded.length; offset += 64) {
    final blockView = ByteData.sublistView(padded, offset, offset + 64);
    for (var index = 0; index < 16; index++) {
      words[index] = blockView.getUint32(index * 4, Endian.big);
    }
    for (var index = 16; index < 80; index++) {
      words[index] = _rotl32(
        words[index - 3] ^
            words[index - 8] ^
            words[index - 14] ^
            words[index - 16],
        1,
      );
    }

    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;

    for (var index = 0; index < 80; index++) {
      late int f;
      late int k;
      if (index < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5a827999;
      } else if (index < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (index < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      final temp = (_rotl32(a, 5) + f + e + k + words[index]) & 0xffffffff;
      e = d;
      d = c;
      c = _rotl32(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) & 0xffffffff;
    h1 = (h1 + b) & 0xffffffff;
    h2 = (h2 + c) & 0xffffffff;
    h3 = (h3 + d) & 0xffffffff;
    h4 = (h4 + e) & 0xffffffff;
  }

  final digest = ByteData(20);
  digest.setUint32(0, h0, Endian.big);
  digest.setUint32(4, h1, Endian.big);
  digest.setUint32(8, h2, Endian.big);
  digest.setUint32(12, h3, Endian.big);
  digest.setUint32(16, h4, Endian.big);
  return digest.buffer.asUint8List();
}

Uint8List hmacSha1(Uint8List key, Uint8List data) {
  var normalizedKey = Uint8List.fromList(key);
  if (normalizedKey.length > 64) {
    normalizedKey = sha1Digest(normalizedKey);
  }
  if (normalizedKey.length < 64) {
    final padded = Uint8List(64);
    padded.setRange(0, normalizedKey.length, normalizedKey);
    normalizedKey = padded;
  }
  final innerPad = Uint8List(64);
  final outerPad = Uint8List(64);
  for (var index = 0; index < 64; index++) {
    innerPad[index] = normalizedKey[index] ^ 0x36;
    outerPad[index] = normalizedKey[index] ^ 0x5c;
  }

  final inner = BytesBuilder(copy: false)
    ..add(innerPad)
    ..add(data);
  final outer = BytesBuilder(copy: false)
    ..add(outerPad)
    ..add(sha1Digest(inner.takeBytes()));
  return sha1Digest(outer.takeBytes());
}

Uint8List md5Digest(Uint8List data) {
  final lengthBits = data.length * 8;
  final paddingLength = ((56 - ((data.length + 1) % 64)) % 64 + 64) % 64;
  final padded = Uint8List(data.length + 1 + paddingLength + 8);
  padded.setRange(0, data.length, data);
  padded[data.length] = 0x80;
  final paddedView = ByteData.sublistView(padded);
  paddedView.setUint32(
    padded.length - 8,
    lengthBits & 0xffffffff,
    Endian.little,
  );
  paddedView.setUint32(
    padded.length - 4,
    (lengthBits ~/ 0x100000000) & 0xffffffff,
    Endian.little,
  );

  var a0 = 0x67452301;
  var b0 = 0xefcdab89;
  var c0 = 0x98badcfe;
  var d0 = 0x10325476;

  final shifts = <int>[
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
  ];

  final constants = Uint32List(64);
  for (var index = 0; index < 64; index++) {
    constants[index] = (pow(2, 32) * sin(index + 1).abs()).floor() & 0xffffffff;
  }

  final chunk = Uint32List(16);
  for (var offset = 0; offset < padded.length; offset += 64) {
    final chunkView = ByteData.sublistView(padded, offset, offset + 64);
    for (var index = 0; index < 16; index++) {
      chunk[index] = chunkView.getUint32(index * 4, Endian.little);
    }

    var a = a0;
    var b = b0;
    var c = c0;
    var d = d0;

    for (var index = 0; index < 64; index++) {
      late int f;
      late int g;
      if (index < 16) {
        f = (b & c) | ((~b) & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * index) % 16;
      }

      final temp = d;
      d = c;
      c = b;
      b = (b +
              _rotl32(
                (a + f + constants[index] + chunk[g]) & 0xffffffff,
                shifts[index],
              )) &
          0xffffffff;
      a = temp;
    }

    a0 = (a0 + a) & 0xffffffff;
    b0 = (b0 + b) & 0xffffffff;
    c0 = (c0 + c) & 0xffffffff;
    d0 = (d0 + d) & 0xffffffff;
  }

  final digest = ByteData(16);
  digest.setUint32(0, a0, Endian.little);
  digest.setUint32(4, b0, Endian.little);
  digest.setUint32(8, c0, Endian.little);
  digest.setUint32(12, d0, Endian.little);
  return digest.buffer.asUint8List();
}

int crc32(Uint8List data) {
  var crc = 0xffffffff;
  for (final byte in data) {
    crc = _crc32Table[(crc ^ byte) & 0xff] ^ ((crc >> 8) & 0x00ffffff);
  }
  return (crc ^ 0xffffffff) & 0xffffffff;
}

Uint8List md5String(String value) {
  return md5Digest(Uint8List.fromList(utf8.encode(value)));
}

int _rotl32(int value, int shift) {
  return ((value << shift) | ((value & 0xffffffff) >> (32 - shift))) &
      0xffffffff;
}

final Uint32List _crc32Table = Uint32List.fromList(
  List<int>.generate(256, (index) {
    var value = index;
    for (var bit = 0; bit < 8; bit++) {
      if ((value & 1) == 1) {
        value = 0xedb88320 ^ (value >> 1);
      } else {
        value >>= 1;
      }
    }
    return value & 0xffffffff;
  }),
);
