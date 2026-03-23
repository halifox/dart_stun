import 'dart:math';
import 'dart:typed_data';

int readUint16(Uint8List bytes, int offset) {
  return ByteData.sublistView(bytes, offset, offset + 2)
      .getUint16(0, Endian.big);
}

int readUint32(Uint8List bytes, int offset) {
  return ByteData.sublistView(bytes, offset, offset + 4)
      .getUint32(0, Endian.big);
}

void writeUint16(BytesBuilder builder, int value) {
  final data = ByteData(2)..setUint16(0, value, Endian.big);
  builder.add(data.buffer.asUint8List());
}

void writeUint32(BytesBuilder builder, int value) {
  final data = ByteData(4)..setUint32(0, value, Endian.big);
  builder.add(data.buffer.asUint8List());
}

void writeUint16Into(Uint8List bytes, int offset, int value) {
  ByteData.sublistView(bytes, offset, offset + 2)
      .setUint16(0, value, Endian.big);
}

void writeUint32Into(Uint8List bytes, int offset, int value) {
  ByteData.sublistView(bytes, offset, offset + 4)
      .setUint32(0, value, Endian.big);
}

Uint8List uint16ListToBytes(Iterable<int> values) {
  final builder = BytesBuilder(copy: false);
  for (final value in values) {
    writeUint16(builder, value);
  }
  return builder.takeBytes();
}

int paddingLength(int valueLength) {
  return (4 - (valueLength % 4)) % 4;
}

Uint8List addPadding(Uint8List value) {
  final padding = paddingLength(value.length);
  if (padding == 0) {
    return Uint8List.fromList(value);
  }
  return Uint8List(value.length + padding)..setRange(0, value.length, value);
}

bool bytesEqual(Uint8List left, Uint8List right) {
  if (identical(left, right)) {
    return true;
  }
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

String hexEncode(Uint8List value) {
  final buffer = StringBuffer();
  for (final byte in value) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

Uint8List randomBytes(int length, {Random? random}) {
  final source = random ?? _secureRandom();
  final bytes = Uint8List(length);
  for (var index = 0; index < length; index++) {
    bytes[index] = source.nextInt(256);
  }
  return bytes;
}

Random _secureRandom() {
  try {
    return Random.secure();
  } on UnsupportedError {
    return Random();
  }
}
