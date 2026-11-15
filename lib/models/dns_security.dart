import 'dart:io';

/// DNS protection for JARVIS-owned Dart HTTP/WebSocket connections only.
/// This is not an Android VPN or a system Private DNS configuration.
enum DnsSecurityMode {
  /// Restore the platform resolver and transport behavior explicitly.
  system,

  /// Encrypted, fail-closed DNS; retain compatibility with remote HTTP APIs.
  compatibility,

  /// Encrypted, fail-closed DNS; reject remote HTTP and WebSocket traffic.
  advanced,
}

class DnsConfigurationException implements Exception {
  final String message;
  const DnsConfigurationException(this.message);
  @override
  String toString() => message;
}

/// A validated RFC 8484 endpoint and its literal bootstrap addresses.
/// Bootstrap addresses avoid a plaintext lookup of the resolver itself.
class DnsProviderProfile {
  final String id;
  final String label;
  final String description;
  final String endpoint;
  final List<String> bootstrapAddresses;
  final bool filtersThreats;
  final String? filteringTestDomain;

  const DnsProviderProfile({
    required this.id,
    required this.label,
    required this.description,
    required this.endpoint,
    required this.bootstrapAddresses,
    this.filtersThreats = false,
    this.filteringTestDomain,
  });

  static const cloudflareSecurity = DnsProviderProfile(
    id: 'cloudflare_security',
    label: 'Cloudflare Security',
    description: 'Malware and phishing filtering · global anycast',
    endpoint: 'https://security.cloudflare-dns.com/dns-query',
    bootstrapAddresses: [
      '1.1.1.2', '1.0.0.2', '2606:4700:4700::1112', '2606:4700:4700::1002',
    ],
    filtersThreats: true,
    filteringTestDomain: 'malware.testcategory.com',
  );

  static const cloudflareFamily = DnsProviderProfile(
    id: 'cloudflare_family',
    label: 'Cloudflare Family',
    description: 'Malware, phishing and adult-content filtering',
    endpoint: 'https://family.cloudflare-dns.com/dns-query',
    bootstrapAddresses: [
      '1.1.1.3', '1.0.0.3', '2606:4700:4700::1113', '2606:4700:4700::1003',
    ],
    filtersThreats: true,
    filteringTestDomain: 'nudity.testcategory.com',
  );

  static const cloudflareStandard = DnsProviderProfile(
    id: 'cloudflare_standard',
    label: 'Cloudflare Standard',
    description: 'Unfiltered resolution · use for compatibility diagnosis',
    endpoint: 'https://cloudflare-dns.com/dns-query',
    bootstrapAddresses: [
      '1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001',
    ],
  );

  static const presets = <DnsProviderProfile>[
    cloudflareSecurity,
    cloudflareFamily,
    cloudflareStandard,
  ];

  Uri get uri => validateEndpoint(endpoint);

  /// Normalize a DNS owner name. IDN must be supplied in ASCII/punycode form.
  static String normalizeHost(String value) {
    var host = value.trim().toLowerCase();
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.substring(1, host.length - 1);
    }
    if (host.endsWith('.')) host = host.substring(0, host.length - 1);
    if (host.isEmpty || host.length > 253 ||
        !RegExp(r'^[a-z0-9._-]+$').hasMatch(host) ||
        host.split('.').any((label) =>
            label.isEmpty || label.length > 63 ||
            label.startsWith('-') || label.endsWith('-'))) {
      throw const DnsConfigurationException(
        'Use a valid ASCII DNS hostname (international names need punycode).',
      );
    }
    return host;
  }

  static Uri validateEndpoint(String value) {
    final Uri uri;
    try {
      uri = Uri.parse(value.trim());
    } on FormatException {
      throw const DnsConfigurationException('Enter a valid HTTPS DoH URL.');
    }
    if (uri.scheme != 'https' || uri.host.isEmpty ||
        uri.userInfo.isNotEmpty || uri.hasQuery || uri.hasFragment ||
        uri.port == 0) {
      throw const DnsConfigurationException(
        'DoH needs HTTPS, a valid port, and no credentials, query or fragment.',
      );
    }
    if (InternetAddress.tryParse(uri.host) == null) normalizeHost(uri.host);
    return uri;
  }

  static List<String> parseBootstrapAddresses(String value) {
    final items = value.split(RegExp(r'[\s,;]+')).where((s) => s.isNotEmpty);
    final addresses = <String>[];
    for (final item in items) {
      final address = InternetAddress.tryParse(item);
      if (address == null || address.rawAddress.every((b) => b == 0) || address.isMulticast ||
          address.isLoopback || address.isLinkLocal) {
        throw DnsConfigurationException('Invalid resolver IP: $item. Use literal IPv4/IPv6 addresses.');
      }
      final canonical = address.address.toLowerCase();
      if (!addresses.contains(canonical)) addresses.add(canonical);
    }
    if (addresses.isEmpty || addresses.length > 8) {
      throw const DnsConfigurationException('Provide between 1 and 8 resolver IP addresses.');
    }
    return List.unmodifiable(addresses);
  }

  void validate() {
    validateEndpoint(endpoint);
    final addresses = parseBootstrapAddresses(bootstrapAddresses.join(','));
    if (addresses.isEmpty) {
      throw const DnsConfigurationException('At least one bootstrap IP is required.');
    }
  }
}

class DnsSettings {
  final DnsSecurityMode mode;
  final String providerId;
  final String customEndpoint;
  final String customBootstrapAddresses;
  final bool allowPrivateLan;

  const DnsSettings({
    this.mode = DnsSecurityMode.advanced,
    this.providerId = 'cloudflare_security',
    this.customEndpoint = '',
    this.customBootstrapAddresses = '',
    this.allowPrivateLan = true,
  });

  bool get isEncrypted => mode != DnsSecurityMode.system;
  String get modeLabel => switch (mode) {
    DnsSecurityMode.advanced => 'Advanced / strict',
    DnsSecurityMode.compatibility => 'Compatibility',
    DnsSecurityMode.system => 'System DNS',
  };

  DnsProviderProfile get profile {
    if (providerId != 'custom') {
      final preset = DnsProviderProfile.presets.where((p) => p.id == providerId).firstOrNull;
      if (preset == null) {
        throw const DnsConfigurationException('Unknown DNS profile. Select a provider again.');
      }
      return preset;
    }
    final result = DnsProviderProfile(
      id: 'custom',
      label: 'Custom resolver',
      description: 'Your RFC 8484 resolver · certificate validation required',
      endpoint: customEndpoint,
      bootstrapAddresses: DnsProviderProfile.parseBootstrapAddresses(customBootstrapAddresses),
    );
    result.validate();
    return result;
  }

  String get cacheIdentity => '$providerId|$customEndpoint|$customBootstrapAddresses';

  void validate() {
    if (isEncrypted) profile.validate();
  }

  DnsSettings copyWith({
    DnsSecurityMode? mode,
    String? providerId,
    String? customEndpoint,
    String? customBootstrapAddresses,
    bool? allowPrivateLan,
  }) => DnsSettings(
    mode: mode ?? this.mode,
    providerId: providerId ?? this.providerId,
    customEndpoint: customEndpoint ?? this.customEndpoint,
    customBootstrapAddresses: customBootstrapAddresses ?? this.customBootstrapAddresses,
    allowPrivateLan: allowPrivateLan ?? this.allowPrivateLan,
  );
}

/// Transport policy is enforced again on redirects by HttpClient.openUrl.
class DnsTransportPolicy {
  const DnsTransportPolicy();

  static bool isPrivateLanAddress(InternetAddress address) {
    final bytes = address.rawAddress;
    if (address.type == InternetAddressType.IPv4) {
      return bytes[0] == 10 ||
          (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
          (bytes[0] == 192 && bytes[1] == 168);
    }
    if (bytes.length == 16 && bytes.take(10).every((b) => b == 0) &&
        bytes[10] == 255 && bytes[11] == 255) {
      return isPrivateLanAddress(InternetAddress.fromRawAddress(bytes.sublist(12)));
    }
    return bytes.isNotEmpty && (bytes[0] & 0xfe) == 0xfc;
  }

  static bool isSafeLocalAddress(InternetAddress address, {required bool allowLan}) {
    if (address.rawAddress.every((b) => b == 0) || address.isMulticast || address.isLinkLocal) return false;
    if (address.isLoopback) return true;
    final bytes = address.rawAddress;
    if (bytes.length == 16 && bytes.take(10).every((b) => b == 0) &&
        bytes[10] == 255 && bytes[11] == 255) {
      return isSafeLocalAddress(InternetAddress.fromRawAddress(bytes.sublist(12)), allowLan: allowLan);
    }
    return allowLan && isPrivateLanAddress(address);
  }

  /// Returns null for a literal/local connection that needs no DNS lookup.
  String? resolve(Uri uri, DnsSettings settings) {
    if (!settings.isEncrypted) return null; // Explicit platform transport mode.
    final host = uri.host.toLowerCase();
    if (host.isEmpty || uri.userInfo.isNotEmpty) {
      throw const DnsConfigurationException('Invalid destination or embedded URL credentials.');
    }
    if (!uri.isScheme('https') && !uri.isScheme('http')) {
      throw const DnsConfigurationException('Only HTTP and HTTPS connections are supported.');
    }
    if (settings.mode == DnsSecurityMode.advanced && !uri.isScheme('https')) {
      final literal = InternetAddress.tryParse(host);
      final loopbackName = host == 'localhost' || host.endsWith('.localhost');
      if (!(loopbackName || (literal != null &&
          isSafeLocalAddress(literal, allowLan: settings.allowPrivateLan)))) {
        throw const DnsConfigurationException(
          'Advanced mode blocked plaintext HTTP. Use HTTPS, or explicitly select Compatibility.',
        );
      }
    }
    final literal = InternetAddress.tryParse(host);
    if (literal != null) {
      if (!isSafeLocalAddress(literal, allowLan: settings.allowPrivateLan)) return null;
      return null;
    }
    if (host == 'localhost' || host.endsWith('.localhost')) return null;
    return DnsProviderProfile.normalizeHost(host);
  }

  List<InternetAddress> localAddresses(String host) {
    final literal = InternetAddress.tryParse(host);
    if (literal != null) return [literal];
    // localhost is resolved locally, never sent to the public DoH provider.
    return [InternetAddress.loopbackIPv4, InternetAddress.loopbackIPv6];
  }

  /// Reject private, loopback, link-local, documentation, benchmark and other
  /// reserved answers. A public DNS name must not become a route into the LAN.
  static bool isPublicUnicastAddress(InternetAddress address) {
    final b = address.rawAddress;
    if (address.type == InternetAddressType.IPv6) {
      if (b.length == 16 && b.take(10).every((x) => x == 0) && b[10] == 255 && b[11] == 255) {
        return isPublicUnicastAddress(InternetAddress.fromRawAddress(b.sublist(12)));
      }
      // Current IPv6 global-unicast allocation; exclude the documentation prefix.
      return b.length == 16 && (b[0] & 0xe0) == 0x20 &&
          !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8);
    }
    if (b.length != 4) return false;
    if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return false;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
    if (b[0] == 169 && b[1] == 254) return false;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
    if (b[0] == 192 &&
        (b[1] == 168 ||
            (b[1] == 0 && (b[2] == 0 || b[2] == 2)) ||
            (b[1] == 88 && b[2] == 99))) {
      return false;
    }
    if (b[0] == 198 &&
        ((b[1] == 18 || b[1] == 19) || (b[1] == 51 && b[2] == 100))) {
      return false;
    }
    if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
    return true;
  }

  void validateResolvedAddress(InternetAddress address) {
    if (isPublicUnicastAddress(address)) return;
    throw const DnsConfigurationException(
      'DNS returned a local or reserved address. Use an explicit local IP for a trusted LAN service.',
    );
  }
}
