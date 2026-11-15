import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:private_agent/services/dns_message.dart';

import 'dns_test_support.dart';

Uint8List _encodeName(String name) {
  final b = BytesBuilder();
  for (final label in name.split('.')) {
    b.addByte(label.length);
    b.add(label.codeUnits);
  }
  b.addByte(0);
  return b.toBytes();
}

void main() {
  const question = DnsQuestion(name: 'example.com', type: 1, id: 0x1234);
  final query = DnsMessage.encodeQuery(question);

  test('encodes a recursive A question without EDNS client subnet', () {
    expect(query.sublist(0, 12), [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    expect(query.sublist(12), [7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1]);
  });

  test('parses A and AAAA records and clamps excessive TTL', () {
    final a = DnsMessage.decodeReply(dnsResponse(query, addresses: [[93, 184, 216, 34]], ttl: 999999, authenticated: true), question);
    expect(a.addresses.single, [93, 184, 216, 34]);
    expect(a.ttlSeconds, 3600);
    expect(a.authenticatedData, isTrue);
    const q6 = DnsQuestion(name: 'example.com', type: 28, id: 0x1234);
    final bytes = List<int>.filled(16, 0)..[0] = 0x26..[1] = 0x06..[15] = 1;
    final aaaa = DnsMessage.decodeReply(dnsResponse(DnsMessage.encodeQuery(q6), addresses: [bytes]), q6);
    expect(aaaa.addresses.single.length, 16);
    expect(aaaa.type, 28);
  });

  test('recognizes filtering sinkholes and negative answers', () {
    final blocked = DnsMessage.decodeReply(dnsResponse(query, addresses: [[0, 0, 0, 0]]), question);
    expect(blocked.isSinkholed, isTrue);
    final negative = DnsMessage.decodeReply(dnsResponse(query, rcode: 3), question);
    expect(negative.isNegative, isTrue);
    expect(negative.ttlSeconds, 30);
  });

  test('rejects mismatched IDs, questions, truncation and server failures', () {
    expect(() => DnsMessage.decodeReply(dnsResponse(query, overrideId: 1), question), throwsA(isA<DnsProtocolException>()));
    expect(() => DnsMessage.decodeReply(dnsResponse(query, truncated: true), question), throwsA(isA<DnsProtocolException>()));
    expect(() => DnsMessage.decodeReply(dnsResponse(query, rcode: 2), question), throwsA(isA<DnsProtocolException>()));
    final wrong = Uint8List.fromList(dnsResponse(query));
    wrong[13] = 88; // Corrupt the first label length/content boundary.
    expect(() => DnsMessage.decodeReply(wrong, question), throwsA(isA<DnsProtocolException>()));
  });

  test('rejects truncated packets and invalid address lengths', () {
    for (var n = 0; n < query.length; n++) {
      expect(() => DnsMessage.decodeReply(Uint8List.sublistView(query, 0, n), question), throwsA(isA<DnsProtocolException>()));
    }
    expect(() => DnsMessage.decodeReply(dnsResponse(query, addresses: [[1, 2, 3]]), question), throwsA(isA<DnsProtocolException>()));
  });

  test('rejects self-referential and forward compression pointers', () {
    final packet = Uint8List.fromList(query);
    ByteData.sublistView(packet).setUint16(6, 1);
    // Pointer to its own pointer field.
    final start = query.length;
    final bytes = Uint8List.fromList([...packet, 0xc0, 0]);
    bytes[start + 1] = start;
    expect(() => DnsMessage.decodeReply(bytes, question), throwsA(isA<DnsProtocolException>()));
    final forward = Uint8List.fromList([...query, 0xc0, query.length + 2]);
    expect(() => DnsMessage.decodeReply(forward, question), throwsA(isA<DnsProtocolException>()));
  });

  test('accepts compressed CNAME chains and ignores unrelated answers', () {
    // Answer 1: example.com CNAME target.example.com; answer 2: target A.
    final header = Uint8List.fromList(query.sublist(0, 12));
    ByteData.sublistView(header).setUint16(6, 3);
    final packet = BytesBuilder()..add(header)..add(query.sublist(12))
      ..add([0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
    final cname = <int>[6, 116, 97, 114, 103, 101, 116, 0xc0, 0x14]; // target -> .example.com
    final cnameStart = query.length + 12;
    packet.add([0, cname.length]);
    packet.add(cname);
    packet.add([0xc0, cnameStart, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
    // Unrelated answer under the original name after the CNAME is ignored.
    packet.add([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99]);
    final reply = DnsMessage.decodeReply(packet.takeBytes(), question);
    expect(reply.addresses.single, [203, 0, 113, 7]);
  });

  test('follows CNAMEs even when address records appear first', () {
    final answers = BytesBuilder();
    void record(String owner, int type, List<int> data) {
      answers.add(_encodeName(owner));
      final fixed = Uint8List(10);
      ByteData.sublistView(fixed)
        ..setUint16(0, type)
        ..setUint16(2, 1)
        ..setUint32(4, 60)
        ..setUint16(8, data.length);
      answers.add(fixed);
      answers.add(data);
    }
    record('target.example.com', 1, [203, 0, 113, 7]);
    record('example.com', 5, _encodeName('target.example.com'));
    final header = Uint8List.fromList(query.sublist(0, 12));
    ByteData.sublistView(header).setUint16(6, 2);
    final packet = BytesBuilder()..add(header)..add(query.sublist(12))..add(answers.toBytes());
    expect(DnsMessage.decodeReply(packet.takeBytes(), question).addresses.single, [203, 0, 113, 7]);
  });

  test('rejects a CNAME loop', () {
    final answers = BytesBuilder();
    for (final pair in [('example.com', 'target.example.com'), ('target.example.com', 'example.com')]) {
      answers.add(_encodeName(pair.$1));
      final data = _encodeName(pair.$2);
      final fixed = Uint8List(10);
      ByteData.sublistView(fixed)..setUint16(0, 5)..setUint16(2, 1)..setUint32(4, 60)..setUint16(8, data.length);
      answers.add(fixed);
      answers.add(data);
    }
    final header = Uint8List.fromList(query.sublist(0, 12));
    ByteData.sublistView(header).setUint16(6, 2);
    final packet = BytesBuilder()..add(header)..add(query.sublist(12))..add(answers.toBytes());
    expect(() => DnsMessage.decodeReply(packet.takeBytes(), question), throwsA(isA<DnsProtocolException>()));
  });

  test('accepts an OPT root name in the additional section', () {
    // Root name, OPT type 41, UDP size 1232, no options.
    final opt = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];
    final bytes = dnsResponse(query, addresses: [[1, 1, 1, 2]], extra: opt);
    final data = ByteData.sublistView(bytes)..setUint16(10, 1);
    expect(data.getUint16(10), 1);
    expect(DnsMessage.decodeReply(bytes, question).addresses.single, [1, 1, 1, 2]);
  });
}
