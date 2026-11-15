import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:private_agent/models/dns_security.dart';
import 'package:private_agent/services/ai_service.dart';

void main() {
  const policy = DnsTransportPolicy();
  const advanced = DnsSettings();

  test('defaults to Advanced DNS with Cloudflare malware filtering', () {
    expect(advanced.mode, DnsSecurityMode.advanced);
    expect(advanced.profile.id, 'cloudflare_security');
    expect(advanced.profile.filtersThreats, isTrue);
    advanced.profile.validate();
    for (final profile in DnsProviderProfile.presets) {
      profile.validate();
      expect(profile.uri.scheme, 'https');
      expect(profile.bootstrapAddresses.any((a) => a.contains(':')), isTrue);
    }
  });

  test('rejects insecure, credentialed, query-bearing and malformed DoH endpoints', () {
    for (final endpoint in [
      'http://resolver.example/dns-query',
      'https://user:secret@resolver.example/dns-query',
      'https://resolver.example/dns-query?token=secret',
      'https://resolver.example/dns-query#fragment',
      'https://bad_host.example/dns-query',
      'https://resolver.example:0/dns-query',
      '',
    ]) {
      expect(() => DnsProviderProfile.validateEndpoint(endpoint),
          throwsA(isA<DnsConfigurationException>()), reason: endpoint);
    }
  });

  test('bootstrap IPs must be literals, public-routable and bounded', () {
    expect(DnsProviderProfile.parseBootstrapAddresses('1.1.1.2, 2606:4700:4700::1112'),
        ['1.1.1.2', '2606:4700:4700::1112']);
    for (final value in ['resolver.example', '127.0.0.1', '0.0.0.0', '224.0.0.1', '169.254.1.1', '']) {
      expect(() => DnsProviderProfile.parseBootstrapAddresses(value), throwsA(isA<DnsConfigurationException>()));
    }
    expect(() => DnsProviderProfile.parseBootstrapAddresses(List.filled(9, '1.1.1.2').join(',')),
        throwsA(isA<DnsConfigurationException>()));
  });

  test('Advanced blocks remote HTTP and WS but permits explicit local exceptions', () {
    expect(() => policy.resolve(Uri.parse('http://api.example.com/v1'), advanced),
        throwsA(isA<DnsConfigurationException>()));
    expect(policy.resolve(Uri.parse('https://api.example.com/v1'), advanced), 'api.example.com');
    expect(policy.resolve(Uri.parse('http://127.0.0.1:11434/v1'), advanced), isNull);
    expect(policy.resolve(Uri.parse('http://localhost:11434/v1'), advanced), isNull);
    expect(policy.resolve(Uri.parse('http://192.168.1.20:8123/api/'), advanced), isNull);
    expect(() => policy.resolve(Uri.parse('http://192.168.1.20:8123'), advanced.copyWith(allowPrivateLan: false)),
        throwsA(isA<DnsConfigurationException>()));
    expect(() => policy.resolve(Uri.parse('http://169.254.169.254/latest'), advanced),
        throwsA(isA<DnsConfigurationException>()));
  });

  test('Compatibility keeps DoH for HTTP hostnames; System explicitly opts out', () {
    const compatibility = DnsSettings(mode: DnsSecurityMode.compatibility);
    expect(policy.resolve(Uri.parse('http://api.example.com'), compatibility), 'api.example.com');
    expect(policy.resolve(Uri.parse('https://api.example.com'), advanced.copyWith(mode: DnsSecurityMode.system)), isNull);
  });

  test('public DNS answers cannot rebind into loopback, LAN or metadata addresses', () {
    for (final ip in ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fc00::1', '::ffff:127.0.0.1']) {
      expect(() => policy.validateResolvedAddress(InternetAddress(ip)),
          throwsA(isA<DnsConfigurationException>()), reason: ip);
    }
    policy.validateResolvedAddress(InternetAddress('93.184.216.34'));
    policy.validateResolvedAddress(InternetAddress('2606:4700::1112'));
    expect(DnsTransportPolicy.isPrivateLanAddress(InternetAddress('172.32.0.1')), isFalse);
    expect(DnsTransportPolicy.isPrivateLanAddress(InternetAddress('::ffff:192.168.1.1')), isTrue);
  });

  test('DNS voice intent is read-only and distinct from the subnet scanner', () {
    expect(JarvisIntent.fallback('open DNS security').type, JarvisIntentType.dnsSecurity);
    expect(JarvisIntent.fallback('check dns').type, JarvisIntentType.dnsSecurity);
    expect(JarvisIntent.fallback('audit my network').type, JarvisIntentType.networkAudit);
    expect(JarvisIntent.fallback('what is DNS').type, isNot(JarvisIntentType.dnsSecurity));
  });
}
