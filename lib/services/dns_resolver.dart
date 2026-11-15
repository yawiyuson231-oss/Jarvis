import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../models/dns_security.dart';
import 'dns_message.dart';

/// Injectable RFC 8484 POST transport. Production uses bootstrap IPs + TLS;
/// tests can supply deterministic responses without touching the network.
typedef DohTransport = Future<Uint8List> Function(
  DnsProviderProfile profile,
  Uint8List query,
  Duration timeout,
);

class DnsResolutionException implements Exception {
  final String message;
  final int? resultCode;
  const DnsResolutionException(this.message, {this.resultCode});
  @override
  String toString() => message;
}

class DnsResolverStats {
  final int networkQueries;
  final int cacheHits;
  final int failures;
  final int sinkholedReplies;
  final int? lastLatencyMs;
  const DnsResolverStats({
    this.networkQueries = 0,
    this.cacheHits = 0,
    this.failures = 0,
    this.sinkholedReplies = 0,
    this.lastLatencyMs,
  });
}

/// TTL-bounded, coalesced and fail-closed. It never calls InternetAddress.lookup.
class DnsResolver {
  final DnsProviderProfile profile;
  final DohTransport transport;
  final Duration queryTimeout;
  final DateTime Function() _now;
  final Random _random = Random.secure();
  final Map<String, _CacheEntry> _cache = {};
  final Map<String, Future<DnsReply>> _inFlight = {};
  bool _disposed = false;
  int _networkQueries = 0;
  int _cacheHits = 0;
  int _failures = 0;
  int _sinkholedReplies = 0;
  int? _lastLatencyMs;

  DnsResolver({
    required this.profile,
    required this.transport,
    this.queryTimeout = const Duration(seconds: 3),
    DateTime Function()? now,
  }) : _now = now ?? DateTime.now {
    profile.validate();
  }

  DnsResolverStats get stats => DnsResolverStats(
    networkQueries: _networkQueries,
    cacheHits: _cacheHits,
    failures: _failures,
    sinkholedReplies: _sinkholedReplies,
    lastLatencyMs: _lastLatencyMs,
  );
  int get cachedRecords => _cache.length;

  Future<DnsReply> lookup(String hostname, int type, {bool bypassCache = false}) {
    if (_disposed) return Future.error(const DnsResolutionException('DNS resolver is closed.'));
    final name = DnsProviderProfile.normalizeHost(hostname);
    final key = '$name/$type';
    if (!bypassCache) {
      final cached = _cache[key];
      if (cached != null) {
        if (cached.expires.isAfter(_now())) {
          _cacheHits++;
          return Future.value(cached.reply);
        }
        _cache.remove(key);
      }
      final pending = _inFlight[key];
      if (pending != null) {
        _cacheHits++; // Count a coalesced lookup as a cache hit.
        return pending;
      }
    }
    final question = DnsQuestion(name: name, type: type, id: _random.nextInt(65536));
    final future = _query(question);
    if (!bypassCache) {
      _inFlight[key] = future;
      return future.whenComplete(() {
        if (identical(_inFlight[key], future)) _inFlight.remove(key);
      });
    }
    return future;
  }

  Future<DnsReply> _query(DnsQuestion question) async {
    final wire = DnsMessage.encodeQuery(question);
    Object? lastError;
    for (final bootstrap in profile.bootstrapAddresses) {
      if (_disposed) break;
      final attempt = DnsProviderProfile(
        id: profile.id,
        label: profile.label,
        description: profile.description,
        endpoint: profile.endpoint,
        bootstrapAddresses: [bootstrap],
        filtersThreats: profile.filtersThreats,
        filteringTestDomain: profile.filteringTestDomain,
      );
      final watch = Stopwatch()..start();
      _networkQueries++;
      try {
        final response = await transport(attempt, wire, queryTimeout).timeout(queryTimeout);
        final reply = DnsMessage.decodeReply(response, question);
        _lastLatencyMs = watch.elapsedMilliseconds;
        if (reply.isSinkholed) _sinkholedReplies++;
        _put(question, reply);
        return reply;
      } catch (error) {
        _failures++;
        lastError = error;
      } finally {
        watch.stop();
      }
    }
    final detail = lastError is DnsProtocolException
        ? lastError.message
        : 'Encrypted resolver unavailable. No system-DNS fallback was attempted.';
    throw DnsResolutionException(
      detail,
      resultCode: lastError is DnsProtocolException ? lastError.resultCode : null,
    );
  }

  void _put(DnsQuestion question, DnsReply reply) {
    if (_disposed) return;
    final key = '${question.name}/${question.type}';
    _cache.removeWhere((_, entry) => !entry.expires.isAfter(_now()));
    while (_cache.length >= 512) {
      _cache.remove(_cache.keys.first);
    }
    _cache[key] = _CacheEntry(reply, _now().add(Duration(seconds: reply.ttlSeconds)));
  }

  /// Prefer IPv6 when available, then IPv4. A broken address family must not
  /// cause a plaintext fallback; a successful public answer from either is safe.
  Future<List<InternetAddress>> resolveHost(String hostname) async {
    final results = await Future.wait([
      _familyResult(hostname, 28),
      _familyResult(hostname, 1),
    ]);
    final addresses = <InternetAddress>[];
    for (final result in results) {
      final reply = result.reply;
      if (reply != null && !reply.isNegative && !reply.isSinkholed) {
        addresses.addAll(reply.addresses.map(InternetAddress.fromRawAddress));
      }
    }
    if (addresses.isNotEmpty) return addresses;
    final error = results.where((r) => r.error != null).firstOrNull;
    if (error != null) throw error.error!;
    throw const DnsResolutionException(
      'No public A/AAAA addresses returned. The domain may be filtered or unavailable.',
    );
  }

  Future<_FamilyResult> _familyResult(String hostname, int type) async {
    try {
      return _FamilyResult(await lookup(hostname, type), null);
    } catch (error) {
      return _FamilyResult(null, error);
    }
  }

  void clearCache() => _cache.clear();

  void dispose() {
    _disposed = true;
    _cache.clear();
    _inFlight.clear();
  }
}

class _CacheEntry {
  final DnsReply reply;
  final DateTime expires;
  const _CacheEntry(this.reply, this.expires);
}

class _FamilyResult {
  final DnsReply? reply;
  final Object? error;
  const _FamilyResult(this.reply, this.error);
}

/// Uses a native HttpClient outside the app's overrides. The connection factory
/// connects to a literal bootstrap IP, but TLS SNI/verification and the HTTP Host
/// remain the configured resolver hostname. No certificate exceptions are used.
Future<Uint8List> postDnsOverHttps(
  DnsProviderProfile profile,
  Uint8List query,
  Duration timeout,
) async {
  profile.validate();
  final endpoint = profile.uri;
  final bootstrap = InternetAddress(profile.bootstrapAddresses.single);
  final client = HttpOverrides.runWithHttpOverrides(
    () => HttpClient(), _NativeBootstrapOverrides(),
  );
  client.findProxy = (_) => 'DIRECT';
  client
    ..connectionTimeout = timeout
    ..idleTimeout = const Duration(seconds: 1)
    ..userAgent = null
    ..autoUncompress = false
    ..badCertificateCallback = null
    ..connectionFactory = (url, proxyHost, proxyPort) async {
      if (proxyHost != null || url.host != endpoint.host || url.port != endpoint.port) {
        throw const DnsResolutionException('Unexpected DoH transport destination.');
      }
      final task = await Socket.startConnect(bootstrap, endpoint.port);
      Socket? socket;
      try {
        socket = await task.socket;
        final secure = await SecureSocket.secure(
          socket,
          host: endpoint.host,
          supportedProtocols: ['http/1.1'],
        );
        socket = null; // SecureSocket now owns the underlying socket.
        return ConnectionTask.fromSocket<Socket>(Future.value(secure), secure.destroy);
      } catch (_) {
        socket?.destroy();
        task.cancel();
        rethrow;
      }
    };

  HttpClientRequest? request;
  // Bound the entire exchange, not just TCP/TLS establishment. Closing the
  // owned client also destroys an in-progress bootstrap connection.
  final deadline = Timer(timeout, () => client.close(force: true));
  try {
    request = await client.postUrl(endpoint);
    request
      ..followRedirects = false
      ..persistentConnection = false
      ..headers.set(HttpHeaders.contentTypeHeader, 'application/dns-message')
      ..headers.set(HttpHeaders.acceptHeader, 'application/dns-message')
      ..headers.set(HttpHeaders.acceptEncodingHeader, 'identity')
      ..contentLength = query.length;
    request.add(query);
    final response = await request.close();
    if (response.statusCode != 200 ||
        response.headers.contentType?.mimeType != 'application/dns-message') {
      await response.drain<void>();
      throw DnsResolutionException('DoH endpoint returned HTTP ${response.statusCode}.');
    }
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in response) {
      if (bytes.length + chunk.length > DnsMessage.maxResponseBytes) {
        throw const DnsProtocolException('Oversized DoH response.');
      }
      bytes.add(chunk);
    }
    return bytes.takeBytes();
  } on TimeoutException {
    request?.abort();
    throw const DnsResolutionException('Encrypted DNS request timed out.');
  } finally {
    deadline.cancel();
    client.close(force: true);
  }
}

class _NativeBootstrapOverrides extends HttpOverrides {}
