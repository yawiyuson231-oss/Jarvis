import 'dart:typed_data';

/// Minimal, bounds-checked DNS wire codec for A/AAAA queries over RFC 8484.
/// No UDP, EDNS Client Subnet, compression in queries, or plaintext fallback.
class DnsProtocolException implements Exception {
  final String message;
  final int? resultCode;
  const DnsProtocolException(this.message, {this.resultCode});
  @override
  String toString() => message;
}

class DnsQuestion {
  final String name;
  final int type;
  final int id;
  const DnsQuestion({required this.name, required this.type, required this.id});

  void validate() {
    if (type != 1 && type != 28) {
      throw const DnsProtocolException('Only A and AAAA queries are supported.');
    }
    if (id < 0 || id > 0xffff || name.isEmpty || name.length > 253 ||
        !RegExp(r'^[a-z0-9._-]+$').hasMatch(name)) {
      throw const DnsProtocolException('Invalid DNS question.');
    }
    if (name.split('.').any((s) => s.isEmpty || s.length > 63 ||
        s.startsWith('-') || s.endsWith('-'))) {
      throw const DnsProtocolException('Invalid DNS label.');
    }
  }
}

class DnsReply {
  final String name;
  final int type;
  final List<Uint8List> addresses;
  final int ttlSeconds;
  final int resultCode;
  final bool authenticatedData;

  const DnsReply({
    required this.name,
    required this.type,
    required this.addresses,
    required this.ttlSeconds,
    required this.resultCode,
    required this.authenticatedData,
  });

  bool get isNegative => resultCode == 3;
  bool get isSinkholed => addresses.isNotEmpty && addresses.every((bytes) =>
      bytes.every((byte) => byte == 0));
}

abstract final class DnsMessage {
  static const maxResponseBytes = 65535;
  static const _maxRecordsPerSection = 256;

  static Uint8List encodeQuery(DnsQuestion question) {
    question.validate();
    final builder = BytesBuilder(copy: false);
    builder.add([question.id >> 8, question.id & 0xff, 0x01, 0x00,
      0, 1, 0, 0, 0, 0, 0, 0]);
    for (final label in question.name.split('.')) {
      builder.addByte(label.length);
      builder.add(label.codeUnits);
    }
    builder.add([0, 0, question.type, 0, 1]);
    return builder.takeBytes();
  }

  static DnsReply decodeReply(Uint8List bytes, DnsQuestion question) {
    question.validate();
    final data = ByteData.sublistView(bytes);
    void requireBytes(int offset, int count) {
      if (offset < 0 || count < 0 || offset > bytes.length ||
          count > bytes.length - offset) {
        throw const DnsProtocolException('Truncated DNS response.');
      }
    }

    requireBytes(0, 12);
    if (bytes.length > maxResponseBytes) {
      throw const DnsProtocolException('Oversized DNS response.');
    }
    final id = data.getUint16(0);
    final flags = data.getUint16(2);
    final counts = [data.getUint16(4), data.getUint16(6), data.getUint16(8), data.getUint16(10)];
    if (id != question.id || flags & 0x8000 == 0 || flags & 0x7800 != 0) {
      throw const DnsProtocolException('DNS response did not match the query.');
    }
    if (flags & 0x0200 != 0) {
      throw const DnsProtocolException('Truncated DNS answer; refusing an incomplete result.');
    }
    if (counts[0] != 1 || counts.any((n) => n > _maxRecordsPerSection)) {
      throw const DnsProtocolException('Invalid DNS section counts.');
    }
    final rcode = flags & 0x000f;
    if (rcode != 0 && rcode != 3) {
      throw DnsProtocolException('Resolver returned DNS error $rcode.', resultCode: rcode);
    }

    var offset = 12;
    final questionName = _readName(bytes, data, offset);
    offset = questionName.nextOffset;
    requireBytes(offset, 4);
    if (questionName.name != question.name || data.getUint16(offset) != question.type ||
        data.getUint16(offset + 2) != 1) {
      throw const DnsProtocolException('Resolver changed the DNS question.');
    }
    offset += 4;

    final aliases = <String, String>{};
    final addressRecords = <({String owner, Uint8List bytes, int ttl})>[];
    for (var i = 0; i < counts[1]; i++) {
      final owner = _readName(bytes, data, offset, allowRoot: true);
      offset = owner.nextOffset;
      requireBytes(offset, 10);
      final type = data.getUint16(offset);
      final klass = data.getUint16(offset + 2);
      final recordTtl = data.getUint32(offset + 4);
      final length = data.getUint16(offset + 8);
      offset += 10;
      requireBytes(offset, length);
      final recordEnd = offset + length;
      if (klass == 1) {
        if (type == 5) {
          final target = _readName(bytes, data, offset);
          if (target.nextOffset != recordEnd || aliases.containsKey(owner.name) ||
              target.name == owner.name) {
            throw const DnsProtocolException('Malformed or conflicting CNAME.');
          }
          aliases[owner.name] = target.name;
        } else if (type == question.type) {
          final expectedLength = type == 1 ? 4 : 16;
          if (length != expectedLength) {
            throw const DnsProtocolException('Invalid address record length.');
          }
          addressRecords.add((
            owner: owner.name,
            bytes: Uint8List.fromList(bytes.sublist(offset, recordEnd)),
            ttl: recordTtl,
          ));
        }
      }
      offset = recordEnd;
    }
    // Answer-section order is not guaranteed; follow the completed alias graph.
    final canonical = _canonicalTarget(question.name, aliases);
    final addresses = <Uint8List>[];
    var ttl = 0xffffffff;
    for (final record in addressRecords) {
      if (record.owner != canonical) continue;
      addresses.add(record.bytes);
      if (record.ttl < ttl) ttl = record.ttl;
    }
    // Validate all section boundaries, including records we do not interpret.
    for (final count in counts.skip(2)) {
      for (var i = 0; i < count; i++) {
        offset = _readName(bytes, data, offset, allowRoot: true).nextOffset;
        requireBytes(offset, 10);
        final length = data.getUint16(offset + 8);
        offset += 10;
        requireBytes(offset, length);
        offset += length;
      }
    }
    if (offset != bytes.length) {
      throw const DnsProtocolException('Unexpected trailing DNS data.');
    }
    return DnsReply(
      name: question.name,
      type: question.type,
      addresses: List.unmodifiable(addresses),
      ttlSeconds: addresses.isEmpty ? 30 : ttl.clamp(5, 3600).toInt(),
      resultCode: rcode,
      // This is the upstream resolver's assertion, NOT local DNSSEC validation.
      authenticatedData: flags & 0x0020 != 0,
    );
  }

  static String _canonicalTarget(String name, Map<String, String> aliases) {
    var current = name;
    final seen = <String>{};
    while (aliases.containsKey(current)) {
      if (!seen.add(current) || seen.length > 16) {
        throw const DnsProtocolException('CNAME loop or excessive alias chain.');
      }
      current = aliases[current]!;
    }
    return current;
  }

  static _DnsName _readName(Uint8List bytes, ByteData data, int start,
      {bool allowRoot = false}) {
    final labels = <String>[];
    var offset = start;
    int? end;
    var jumps = 0;
    var length = 0;
    while (true) {
      if (offset < 0 || offset >= bytes.length) {
        throw const DnsProtocolException('Truncated compressed DNS name.');
      }
      final size = bytes[offset++];
      if (size == 0) break;
      if (size & 0xc0 == 0xc0) {
        if (offset >= bytes.length || ++jumps > 64) {
          throw const DnsProtocolException('Invalid DNS compression pointer.');
        }
        final pointer = ((size & 0x3f) << 8) | bytes[offset++];
        // Pointers must move backwards: no forward references or cycles.
        if (pointer >= offset - 2) {
          throw const DnsProtocolException('Cyclic DNS compression pointer.');
        }
        end ??= offset;
        offset = pointer;
        continue;
      }
      if (size & 0xc0 != 0 || size > 63 || offset + size > bytes.length) {
        throw const DnsProtocolException('Invalid DNS label length.');
      }
      final labelBytes = bytes.sublist(offset, offset + size);
      if (labelBytes.any((b) =>
          !(b >= 97 && b <= 122) && !(b >= 65 && b <= 90) &&
          !(b >= 48 && b <= 57) && b != 45 && b != 95) ||
          labelBytes.first == 45 || labelBytes.last == 45) {
        throw const DnsProtocolException('Unsupported or invalid DNS label.');
      }
      final label = String.fromCharCodes(labelBytes).toLowerCase();
      length += label.length + 1;
      if (length > 254 || labels.length >= 127) {
        throw const DnsProtocolException('DNS name is too long.');
      }
      labels.add(label);
      offset += size;
    }
    end ??= offset;
    if (labels.isEmpty && !allowRoot) {
      throw const DnsProtocolException('Empty DNS owner name.');
    }
    return _DnsName(labels.join('.'), end);
  }
}

class _DnsName {
  final String name;
  final int nextOffset;
  const _DnsName(this.name, this.nextOffset);
}
