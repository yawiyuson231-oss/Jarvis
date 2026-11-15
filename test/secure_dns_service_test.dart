import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:private_agent/models/dns_security.dart';
import 'package:private_agent/screens/settings/dns_security_screen.dart';
import 'package:private_agent/services/dns_resolver.dart';
import 'package:private_agent/services/secure_dns_service.dart';
import 'package:private_agent/services/settings_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'dns_test_support.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final settings = SettingsService.instance;
  final dns = SecureDnsService.instance;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    await settings.init();
    await settings.setDnsSettings(const DnsSettings(
      providerId: 'custom', customEndpoint: testProfileEndpoint,
      customBootstrapAddresses: testBootstrap,
    ));
    dns.install();
    dns.clearCache();
  });

  test('persists a complete DNS policy and rejects invalid active configs', () async {
    expect(settings.dnsSettings.mode, DnsSecurityMode.advanced);
    await settings.setDnsSettings(settings.dnsSettings.copyWith(
      mode: DnsSecurityMode.compatibility, allowPrivateLan: false));
    expect(settings.dnsSettings.mode, DnsSecurityMode.compatibility);
    expect(settings.dnsSettings.allowPrivateLan, isFalse);
    await expectLater(settings.setDnsSettings(settings.dnsSettings.copyWith(customEndpoint: 'http://bad.example')),
        throwsA(isA<DnsConfigurationException>()));
    expect(settings.dnsSettings.customEndpoint, testProfileEndpoint);
  });

  test('corrupt saved mode/provider fail closed rather than downgrading', () async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('dns_mode', 'corrupted');
    expect(settings.dnsSettings.mode, DnsSecurityMode.advanced);
    await prefs.setString('dns_provider', 'missing-provider');
    expect(dns.statusLabel, contains('Invalid DNS configuration'));
    final client = DnsHttpClient(dns);
    expect(() => client.openUrl('GET', Uri.https('example.com')),
        throwsA(isA<DnsConfigurationException>()));
    client.close();
  });

  test('HttpClient override uses DoH and fails closed on an empty answer', () async {
    var calls = 0;
    dns.setTransportForTesting((profile, query, timeout) async {
      calls++;
      expect(profile.endpoint, testProfileEndpoint);
      return dnsResponse(query); // Valid NOERROR with no A/AAAA records.
    });
    final client = http.Client();
    await expectLater(client.get(Uri.https('example.com', '/chat')),
        throwsA(isA<DnsResolutionException>()));
    expect(calls, 2); // A and AAAA, no plaintext resolver fallback.
    client.close();
  });

  test('Advanced blocks HTTP and WebSocket before any socket or DNS query', () async {
    var calls = 0;
    dns.setTransportForTesting((p, q, t) async { calls++; return dnsResponse(q); });
    final client = DnsHttpClient(dns);
    expect(() => client.openUrl('GET', Uri.parse('http://api.example.com')),
        throwsA(isA<DnsConfigurationException>()));
    await expectLater(() => WebSocket.connect('ws://api.example.com', customClient: client),
        throwsA(isA<DnsConfigurationException>()));
    expect(calls, 0);
    client.close();
  });

  test('a redirect from an allowed local URL cannot bypass Advanced HTTP policy', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serving = server.forEach((request) {
      request.response.statusCode = HttpStatus.found;
      request.response.headers.set(HttpHeaders.locationHeader, 'http://api.example.com/next');
      request.response.close();
    });
    final client = http.Client();
    try {
      await expectLater(client.get(Uri.parse('http://127.0.0.1:${server.port}/start')),
          throwsA(isA<DnsConfigurationException>()));
    } finally {
      client.close();
      await server.close(force: true);
      await serving;
    }
  });

  test('encrypted modes reject certificate bypasses and proxy overrides', () {
    final client = DnsHttpClient(dns);
    expect(() => client.badCertificateCallback = (_, __, ___) => true,
        throwsA(isA<DnsConfigurationException>()));
    expect(() => client.findProxy = (_) => 'PROXY attacker.example:8080',
        throwsA(isA<DnsConfigurationException>()));
    expect(() => client.keyLog = (_) {}, throwsA(isA<DnsConfigurationException>()));
    client.close();
  });

  test('loopback Ollama stays reachable in Advanced mode without public DNS', () async {
    var calls = 0;
    dns.setTransportForTesting((p, q, t) async { calls++; return dnsResponse(q); });
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final serving = server.forEach((request) {
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"ok":true}');
      request.response.close();
    });
    final client = http.Client();
    try {
      final response = await client.get(Uri.parse('http://127.0.0.1:${server.port}/v1/models'));
      expect(response.statusCode, 200);
      expect(response.body, '{"ok":true}');
      expect(calls, 0);
    } finally {
      client.close();
      await server.close(force: true);
      await serving;
    }
  });

  test('policy changes invalidate verification and DNS cache state', () async {
    dns.setTransportForTesting((p, q, t) async => dnsResponse(q, addresses: [[93, 184, 216, 34]]));
    final report = await dns.checkResolver();
    expect(report.transportVerified, isTrue);
    expect(dns.lastCheckSucceeded, isTrue);
    await settings.setDnsSettings(settings.dnsSettings.copyWith(mode: DnsSecurityMode.compatibility));
    expect(dns.lastCheckedAt, isNull);
    expect(dns.lastReport, isNull);
    expect(dns.cachedRecords, 0);
  });

  testWidgets('DNS screen exposes scope, modes and unverified status', (tester) async {
    dns.setTransportForTesting((p, q, t) async => dnsResponse(q));
    await tester.pumpWidget(const MaterialApp(home: DnsSecurityScreen()));
    await tester.pumpAndSettle();
    expect(find.text('DNS security'), findsOneWidget);
    expect(find.text(SecureDnsService.coverageNotice), findsOneWidget);
    expect(find.text('Configured · run a connection check'), findsOneWidget);
    await tester.scrollUntilVisible(find.text('Apply DNS settings'), 250);
    expect(find.text('Apply DNS settings'), findsOneWidget);
  });
}
