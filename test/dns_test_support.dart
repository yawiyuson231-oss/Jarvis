import 'dart:typed_data';

/// Build a small DNS response from the question section of an encoded query.
/// Kept independent of the production parser so parser tests exercise the wire.
Uint8List dnsResponse(
  Uint8List query, {
  List<List<int>> addresses = const [],
  int ttl = 60,
  int rcode = 0,
  bool truncated = false,
  bool authenticated = false,
  int? overrideId,
  List<int> extra = const [],
}) {
  var end = 12;
  while (query[end] != 0) { end += query[end] + 1; }
  end += 5;
  final type = query[end - 4];
  final header = Uint8List.fromList(query.sublist(0, end));
  final data = ByteData.sublistView(header);
  data.setUint16(0, overrideId ?? data.getUint16(0));
  data.setUint16(2, 0x8180 | rcode | (truncated ? 0x0200 : 0) | (authenticated ? 0x0020 : 0));
  data.setUint16(6, addresses.length);
  final b = BytesBuilder()..add(header);
  for (final address in addresses) {
    b.add([0xc0, 0x0c, 0, type, 0, 1]);
    final tail = Uint8List(8);
    ByteData.sublistView(tail)
      ..setUint32(0, ttl)
      ..setUint16(4, address.length);
    b.add(tail);
    b.add(address);
  }
  b.add(extra);
  return b.takeBytes();
}

const testProfileEndpoint = 'https://resolver.example/dns-query';
const testBootstrap = '192.0.2.1,192.0.2.2';
