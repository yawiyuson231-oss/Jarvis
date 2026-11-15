import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:private_agent/models/dns_security.dart';
import 'package:private_agent/services/dns_message.dart';
import 'package:private_agent/services/dns_resolver.dart';

import 'dns_test_support.dart';

void main() {
  const profile = DnsProviderProfile(
    id: 'test', label: 'Test', description: 'Deterministic test resolver',
    endpoint: testProfileEndpoint, bootstrapAddresses: ['192.0.2.1', '192.0.2.2'],
  );

  test('one network query serves concurrent callers and cache expires', () async {
    var now = DateTime(2026, 1, 1);
    var calls = 0;
    final gate = Completer<void>();
    final resolver = DnsResolver(profile: profile, now: () => now,
      transport: (p, q, t) async {
        calls++;
        await gate.future;
        return dnsResponse(q, addresses: [[93, 184, 216, 34]], ttl: 10);
      });
    final a = resolver.lookup('example.com', 1);
    final b = resolver.lookup('example.com', 1);
    gate.complete();
    await Future.wait([a, b]);
    expect(calls, 1);
    expect(resolver.stats.cacheHits, 1);
    await resolver.lookup('example.com', 1);
    expect(calls, 1);
    now = now.add(const Duration(seconds: 11));
    await resolver.lookup('example.com', 1);
    expect(calls, 2);
    resolver.dispose();
  });

  test('fails over only to another bootstrap IP of the same DoH profile', () async {
    final bootstraps = <String>[];
    var calls = 0;
    final resolver = DnsResolver(profile: profile, transport: (p, q, t) async {
      bootstraps.add(p.bootstrapAddresses.single);
      if (++calls == 1) throw const SocketException('simulated outage');
      return dnsResponse(q, addresses: [[93, 184, 216, 34]]);
    });
    final reply = await resolver.lookup('example.com', 1);
    expect(reply.addresses.single, [93, 184, 216, 34]);
    expect(bootstraps, ['192.0.2.1', '192.0.2.2']);
    expect(resolver.stats.failures, 1);
    resolver.dispose();
  });

  test('all resolver failures fail closed and are not cached', () async {
    var calls = 0;
    final resolver = DnsResolver(profile: profile, transport: (p, q, t) async {
      calls++;
      throw const SocketException('offline');
    });
    await expectLater(resolver.lookup('example.com', 1), throwsA(isA<DnsResolutionException>()));
    expect(calls, 2);
    expect(resolver.cachedRecords, 0);
    await expectLater(resolver.lookup('example.com', 1), throwsA(isA<DnsResolutionException>()));
    expect(calls, 4);
    resolver.dispose();
  });

  test('a stalled transport is bounded by the query deadline', () async {
    final resolver = DnsResolver(
      profile: profile,
      queryTimeout: const Duration(milliseconds: 20),
      transport: (p, q, t) => Completer<Uint8List>().future,
    );
    await expectLater(resolver.lookup('example.com', 1), throwsA(isA<DnsResolutionException>()));
    expect(resolver.stats.failures, 2);
    resolver.dispose();
  });

  test('IPv6 and IPv4 records are returned without a system lookup', () async {
    final types = <int>[];
    final resolver = DnsResolver(profile: profile, transport: (p, q, t) async {
      final type = q[q.length - 4];
      types.add(type);
      final ipv6 = List<int>.filled(16, 0);
      ipv6[0] = 0x26;
      ipv6[15] = 1;
      return dnsResponse(q, addresses: [type == 28 ? ipv6 : [93, 184, 216, 34]]);
    });
    final addresses = await resolver.resolveHost('example.com');
    expect(types.toSet(), {1, 28});
    expect(addresses.first.type, InternetAddressType.IPv6);
    expect(addresses.last.type, InternetAddressType.IPv4);
    resolver.dispose();
  });

  test('filtering responses are surfaced, not bypassed with another provider', () async {
    var calls = 0;
    final resolver = DnsResolver(profile: profile, transport: (p, q, t) async {
      calls++;
      return dnsResponse(q, addresses: [[0, 0, 0, 0]]);
    });
    final reply = await resolver.lookup('blocked.example', 1);
    expect(reply.isSinkholed, isTrue);
    await expectLater(resolver.resolveHost('blocked.example'), throwsA(isA<DnsResolutionException>()));
    expect(calls, 3); // cached A + AAAA lookup, no alternate-provider retry
    expect(resolver.stats.sinkholedReplies, 2);
    resolver.dispose();
  });
}
