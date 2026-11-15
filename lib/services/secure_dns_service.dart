import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import '../models/dns_security.dart';
import 'dns_resolver.dart';
import 'settings_service.dart';

class DnsProbeReport {
  final bool transportVerified;
  final int latencyMs;
  final bool? filteringObserved;
  final bool upstreamDnssec;
  final String message;
  final DateTime checkedAt;
  const DnsProbeReport({
    required this.transportVerified,
    required this.latencyMs,
    required this.filteringObserved,
    required this.upstreamDnssec,
    required this.message,
    required this.checkedAt,
  });
}

/// Installs a Dart HttpClient override, not a VPN. All JARVIS HTTP helpers and
/// the Edge neural-TTS WebSocket use this transport. Native Android recognizers,
/// external apps, WebViews and plugin-owned network stacks are NOT covered.
class SecureDnsService extends ChangeNotifier {
  SecureDnsService._();
  static final SecureDnsService instance = SecureDnsService._();
  static const coverageNotice =
      'JARVIS HTTP helpers + neural TTS only. Other apps, Android speech '
      'recognition and plugin-owned network stacks use their own DNS.';

  bool _installed = false;
  int _generation = 0;
  String _identity = '';
  DnsResolver? _resolver;
  DohTransport _transport = postDnsOverHttps;
  final Set<DnsHttpClient> _clients = {};
  DnsResolverStats _archivedStats = const DnsResolverStats();
  int _connectionsOpened = 0;
  bool _checking = false;
  bool _lastCheckSucceeded = false;
  DateTime? _lastCheckedAt;
  String? _lastError;
  DnsProbeReport? _lastReport;

  DnsSettings get configuration => SettingsService.instance.dnsSettings;
  bool get isInstalled => _installed;
  bool get isChecking => _checking;
  bool get lastCheckSucceeded => _lastCheckSucceeded;
  DateTime? get lastCheckedAt => _lastCheckedAt;
  String? get lastError => _lastError;
  DnsProbeReport? get lastReport => _lastReport;
  int get connectionsOpened => _connectionsOpened;
  int get networkQueries => _archivedStats.networkQueries + (_resolver?.stats.networkQueries ?? 0);
  int get cacheHits => _archivedStats.cacheHits + (_resolver?.stats.cacheHits ?? 0);
  int get failedQueries => _archivedStats.failures + (_resolver?.stats.failures ?? 0);
  int get sinkholedReplies => _archivedStats.sinkholedReplies + (_resolver?.stats.sinkholedReplies ?? 0);
  int get cachedRecords => _resolver?.cachedRecords ?? 0;
  String get statusLabel {
    final settings = configuration;
    if (!settings.isEncrypted) return 'System DNS · not encrypted by JARVIS';
    try { settings.profile.validate(); }
    catch (_) { return 'Invalid DNS configuration · requests fail closed'; }
    if (_checking) return 'Checking encrypted resolver…';
    if (_lastError != null) return 'Recent DNS error · protected requests fail closed';
    if (_lastCheckedAt == null) return 'Configured · run a connection check';
    return _lastCheckSucceeded ? 'Last DoH check passed · JARVIS scope' : 'Check failed · protected requests fail closed';
  }

  void install() {
    if (_installed) return;
    _installed = true;
    _identity = _identityOf(configuration);
    SettingsService.instance.addListener(_settingsChanged);
    HttpOverrides.global = _JarvisHttpOverrides(this);
  }

  /// Test seam: no real network is needed for resolver/transport-policy tests.
  void setTransportForTesting(DohTransport transport) {
    _transport = transport;
    clearCache();
  }

  void _settingsChanged() {
    final next = _identityOf(configuration);
    if (next == _identity) return;
    _identity = next;
    clearCache();
  }

  String _identityOf(DnsSettings settings) =>
      '${settings.mode.name}|${settings.cacheIdentity}|${settings.allowPrivateLan}';

  void clearCache() {
    final stats = _resolver?.stats;
    if (stats != null) {
      _archivedStats = DnsResolverStats(
        networkQueries: _archivedStats.networkQueries + stats.networkQueries,
        cacheHits: _archivedStats.cacheHits + stats.cacheHits,
        failures: _archivedStats.failures + stats.failures,
        sinkholedReplies: _archivedStats.sinkholedReplies + stats.sinkholedReplies,
      );
    }
    _resolver?.dispose();
    _resolver = null;
    // Abort idle/active native clients immediately. Otherwise an in-flight
    // response could follow a redirect over a connection opened under the old
    // policy without calling DnsHttpClient.openUrl again.
    for (final client in _clients.toList()) {
      client._invalidate();
    }
    _generation++;
    _lastCheckedAt = null;
    _lastCheckSucceeded = false;
    _lastReport = null;
    _lastError = null;
    notifyListeners();
  }

  DnsResolver _resolverFor(DnsSettings settings) {
    if (!settings.isEncrypted) {
      throw const DnsConfigurationException('Encrypted DNS is explicitly disabled.');
    }
    return _resolver ??= DnsResolver(profile: settings.profile, transport: _transport);
  }

  http.Client httpClient() => IOClient(DnsHttpClient(this));

  /// The original URI is retained for HTTP Host and TLS certificate validation.
  Future<Socket> _openSocket(
    Uri uri,
    DnsSettings settings,
    SecurityContext? context,
    int generation,
    bool Function() cancelled,
    void Function(void Function()) setCancel,
  ) async {
    final resolver = _resolverFor(settings);
    final name = const DnsTransportPolicy().resolve(uri, settings);
    List<InternetAddress> addresses;
    if (name == null) {
      addresses = const DnsTransportPolicy().localAddresses(uri.host);
    } else {
      try {
        addresses = await resolver.resolveHost(name);
        for (final address in addresses) {
          const DnsTransportPolicy().validateResolvedAddress(address);
        }
      } catch (error) {
        _lastError = error.toString();
        notifyListeners();
        rethrow;
      }
    }
    if (cancelled() || generation != _generation) {
      throw const SocketException('Connection cancelled after a DNS policy change.');
    }
    Object? lastError;
    for (final address in addresses.take(8)) {
      Socket? socket;
      try {
        final task = await Socket.startConnect(address, uri.port);
        setCancel(task.cancel);
        if (cancelled()) throw const SocketException('Connection cancelled.');
        socket = await task.socket.timeout(const Duration(seconds: 5), onTimeout: () {
          task.cancel();
          throw const SocketException('Target connection timed out.');
        });
        if (uri.isScheme('https')) {
          setCancel(socket.destroy);
          final secure = await SecureSocket.secure(
            socket,
            host: uri.host,
            context: context,
            supportedProtocols: ['http/1.1'],
          ).timeout(const Duration(seconds: 5));
          socket = null;
          socket = secure;
        }
        if (cancelled() || generation != _generation) {
          throw const SocketException('Connection cancelled after a DNS policy change.');
        }
        setCancel(socket.destroy);
        _connectionsOpened++;
        _lastError = null;
        notifyListeners();
        return socket;
      } catch (error) {
        socket?.destroy();
        lastError = error;
        if (cancelled() || generation != _generation) rethrow;
        if (error is HandshakeException) {
          // Authentication failures must never turn into plaintext requests.
          rethrow;
        }
      }
    }
    throw SocketException('Could not connect securely: ${lastError ?? 'no addresses'}');
  }

  /// A live, user-initiated RFC 8484 check. A saved preference alone is never
  /// presented as proof of connectivity. Candidate checks do not change policy.
  Future<DnsProbeReport> checkResolver({DnsSettings? candidate}) async {
    final settings = candidate ?? configuration;
    final activeCheck = candidate == null;
    final probeGeneration = _generation;
    if (activeCheck && _checking) throw StateError('A DNS check is already running.');
    settings.validate();
    if (!settings.isEncrypted) {
      throw const DnsConfigurationException('Select an encrypted mode to check DoH.');
    }
    if (activeCheck) {
      _checking = true;
      _lastError = null;
      notifyListeners();
    }
    final resolver = DnsResolver(profile: settings.profile, transport: _transport);
    final watch = Stopwatch()..start();
    try {
      final reply = await resolver.lookup('example.com', 1, bypassCache: true);
      if (reply.addresses.isEmpty || reply.isSinkholed) {
        throw const DnsResolutionException('Resolver returned no usable test address.');
      }
      bool? filtering;
      var note = '';
      final testDomain = settings.profile.filteringTestDomain;
      if (testDomain != null) {
        try {
          final test = await resolver.lookup(testDomain, 1, bypassCache: true);
          filtering = test.isSinkholed || test.isNegative;
          if (filtering != true) note = ' The filtering test was not blocked; check the provider profile.';
        } catch (error) {
          filtering = error is DnsResolutionException && error.resultCode == 3;
          if (filtering != true) note = ' The filtering test was inconclusive.';
        }
      }
      final report = DnsProbeReport(
        transportVerified: true,
        latencyMs: watch.elapsedMilliseconds,
        filteringObserved: filtering,
        upstreamDnssec: reply.authenticatedData,
        message: 'Authenticated DoH connection verified.$note',
        checkedAt: DateTime.now(),
      );
      if (activeCheck && probeGeneration == _generation) {
        _lastReport = report;
        _lastCheckSucceeded = true;
        _lastCheckedAt = report.checkedAt;
      }
      return report;
    } catch (error) {
      final report = DnsProbeReport(
        transportVerified: false,
        latencyMs: watch.elapsedMilliseconds,
        filteringObserved: null,
        upstreamDnssec: false,
        message: error.toString(),
        checkedAt: DateTime.now(),
      );
      if (activeCheck && probeGeneration == _generation) {
        _lastReport = report;
        _lastCheckSucceeded = false;
        _lastCheckedAt = report.checkedAt;
        _lastError = report.message;
      }
      return report;
    } finally {
      watch.stop();
      resolver.dispose();
      if (activeCheck) {
        _checking = false;
        notifyListeners();
      }
    }
  }

  @override
  void dispose() {
    SettingsService.instance.removeListener(_settingsChanged);
    _resolver?.dispose();
    for (final client in _clients.toList()) {
      client.close(force: true);
    }
    _installed = false;
    HttpOverrides.global = null;
    super.dispose();
  }
}

class _JarvisHttpOverrides extends HttpOverrides {
  final SecureDnsService service;
  _JarvisHttpOverrides(this.service);
  @override
  HttpClient createHttpClient(SecurityContext? context) => DnsHttpClient(service, context: context);
}

/// A forwarding HttpClient that guards every open method, including redirects.
/// TLS is performed inside connectionFactory because a custom factory replaces
/// Dart's normal TLS connection path. The original hostname is used for SNI and
/// default certificate verification; only the socket address comes from DoH.
class DnsHttpClient implements HttpClient {
  final SecureDnsService _service;
  final SecurityContext? _context;
  HttpClient? _inner;
  int _innerGeneration = -1;
  bool _closed = false;

  // A private field cannot be an initializing formal for a named parameter.
  // ignore: prefer_initializing_formals
  DnsHttpClient(this._service, {SecurityContext? context}) : _context = context {
    _service._clients.add(this);
  }

  void _invalidate() {
    _inner?.close(force: true);
    _inner = null;
    _innerGeneration = -1;
  }

  HttpClient _client() {
    if (_closed) throw StateError('Client is closed.');
    final generation = _service._generation;
    if (_inner == null || generation != _innerGeneration) {
      _inner?.close(force: true);
      // The override may be installed after a singleton constructed its client.
      // Lazily creating the native client here still puts it behind the policy.
      _inner = HttpOverrides.runWithHttpOverrides(
        () => HttpClient(context: _context), _NativeClientOverrides(),
      );
      _innerGeneration = generation;
    }
    final settings = _service.configuration;
    final client = _inner!;
    client.connectionTimeout = const Duration(seconds: 20);
    client.idleTimeout = const Duration(seconds: 15);
    client.badCertificateCallback = null;
    client.findProxy = settings.isEncrypted ? (_) => 'DIRECT' : null;
    client.connectionFactory = settings.isEncrypted
        ? (uri, proxyHost, proxyPort) {
            if (proxyHost != null) {
              throw const DnsConfigurationException('Proxies are not supported in encrypted DNS modes.');
            }
            var cancelled = false;
            void Function()? cancel;
            final socket = _service._openSocket(
              uri, settings, _context, generation,
              () => cancelled, (callback) => cancel = callback,
            );
            return Future.value(ConnectionTask.fromSocket<Socket>(socket, () {
              cancelled = true;
              cancel?.call();
            }));
          }
        : null;
    return client;
  }

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) {
    final settings = _service.configuration;
    const DnsTransportPolicy().resolve(url, settings);
    // Validate configuration before opening any socket, including IP literals.
    if (settings.isEncrypted) settings.profile.validate();
    return _client().openUrl(method, url);
  }

  Uri _httpUri(String host, int port, String path) {
    final authority = host.contains(':') ? '[$host]:$port' : '$host:$port';
    return Uri.parse('http://$authority${path.startsWith('/') ? path : '/$path'}');
  }

  @override
  Future<HttpClientRequest> open(String method, String host, int port, String path) =>
      openUrl(method, _httpUri(host, port, path));
  @override
  Future<HttpClientRequest> get(String host, int port, String path) => open('GET', host, port, path);
  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl('GET', url);
  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl('POST', url);
  @override
  Future<HttpClientRequest> post(String host, int port, String path) => open('POST', host, port, path);
  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl('PUT', url);
  @override
  Future<HttpClientRequest> put(String host, int port, String path) => open('PUT', host, port, path);
  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl('PATCH', url);
  @override
  Future<HttpClientRequest> patch(String host, int port, String path) => open('PATCH', host, port, path);
  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl('DELETE', url);
  @override
  Future<HttpClientRequest> delete(String host, int port, String path) => open('DELETE', host, port, path);
  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl('HEAD', url);
  @override
  Future<HttpClientRequest> head(String host, int port, String path) => open('HEAD', host, port, path);

  @override
  bool get autoUncompress => _client().autoUncompress;
  @override
  set autoUncompress(bool value) => _client().autoUncompress = value;
  @override
  Duration? get connectionTimeout => _client().connectionTimeout;
  @override
  set connectionTimeout(Duration? value) => _client().connectionTimeout = value;
  @override
  Duration get idleTimeout => _client().idleTimeout;
  @override
  set idleTimeout(Duration value) => _client().idleTimeout = value;
  @override
  int? get maxConnectionsPerHost => _client().maxConnectionsPerHost;
  @override
  set maxConnectionsPerHost(int? value) => _client().maxConnectionsPerHost = value;
  @override
  String? get userAgent => _client().userAgent;
  @override
  set userAgent(String? value) => _client().userAgent = value;
  @override
  set findProxy(String Function(Uri url)? f) {
    if (_service.configuration.isEncrypted && f != null) {
      throw const DnsConfigurationException('Encrypted DNS modes use direct connections, not proxies.');
    }
    _client().findProxy = f;
  }
  @override
  set authenticate(Future<bool> Function(Uri url, String scheme, String? realm)? f) =>
      _client().authenticate = f;
  @override
  set authenticateProxy(Future<bool> Function(String host, int port, String scheme, String? realm)? f) {
    if (_service.configuration.isEncrypted && f != null) {
      throw const DnsConfigurationException('Proxy authentication is disabled in encrypted DNS modes.');
    }
    _client().authenticateProxy = f;
  }
  @override
  void addCredentials(Uri url, String realm, HttpClientCredentials credentials) =>
      _client().addCredentials(url, realm, credentials);
  @override
  void addProxyCredentials(String host, int port, String realm, HttpClientCredentials credentials) {
    if (_service.configuration.isEncrypted) {
      throw const DnsConfigurationException('Proxies are disabled in encrypted DNS modes.');
    }
    _client().addProxyCredentials(host, port, realm, credentials);
  }
  @override
  set badCertificateCallback(bool Function(X509Certificate cert, String host, int port)? callback) {
    if (callback != null && _service.configuration.isEncrypted) {
      throw const DnsConfigurationException('Certificate bypasses are disabled in encrypted DNS modes.');
    }
    _client().badCertificateCallback = callback;
  }
  @override
  set keyLog(Function(String line)? callback) {
    if (callback != null && _service.configuration.isEncrypted) {
      throw const DnsConfigurationException('TLS key logging is disabled in encrypted DNS modes.');
    }
    _client().keyLog = callback;
  }
  @override
  set connectionFactory(Future<ConnectionTask<Socket>> Function(Uri url, String? proxyHost, int? proxyPort)? f) {
    if (f != null && _service.configuration.isEncrypted) {
      throw const DnsConfigurationException('Use SecureDnsService instead of bypassing its connection factory.');
    }
    _client().connectionFactory = f;
  }
  @override
  void close({bool force = false}) {
    _closed = true;
    _service._clients.remove(this);
    _inner?.close(force: force);
    _inner = null;
  }
}

class _NativeClientOverrides extends HttpOverrides {}
