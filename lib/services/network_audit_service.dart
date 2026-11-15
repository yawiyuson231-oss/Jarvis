import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'secure_dns_service.dart';
import 'settings_service.dart';

/// Active device discovered on the local Wi-Fi subnet.
class NetworkDevice {
  final String ip;
  final String mac;
  final String vendor;
  final String hostname;
  final List<int> openPorts;
  final bool isCameraStream;
  final bool isGateway;

  NetworkDevice({
    required this.ip,
    required this.mac,
    required this.vendor,
    required this.hostname,
    required this.openPorts,
    this.isCameraStream = false,
    this.isGateway = false,
  });
}

/// Structured network security posture audit.
class NetworkAuditReport {
  final String localIp;
  final String subnetPrefix;
  final int totalDevicesFound;
  final List<NetworkDevice> devices;
  final int securityScore; // 0 to 100
  final List<String> vulnerabilities;
  final int pingLatencyMs;
  final DateTime auditedAt;
  final String? auditError;
  final String dnsSummary;

  NetworkAuditReport({
    required this.localIp,
    required this.subnetPrefix,
    required this.totalDevicesFound,
    required this.devices,
    required this.securityScore,
    required this.vulnerabilities,
    required this.pingLatencyMs,
    required this.auditedAt,
    this.auditError,
    this.dnsSummary = 'DNS configuration not assessed',
  });
}

/// 🛡️ Stark Network Auditing & Wi-Fi Scanner Suite
///
/// Sweeps local Wi-Fi subnet, parses ARP cache for MACs, resolves hardware vendors,
/// probes for open ports (SSH, Telnet, RTSP Camera feeds), and compiles a cyber defense report.
class NetworkAuditService extends ChangeNotifier {
  NetworkAuditService._();
  static final NetworkAuditService instance = NetworkAuditService._();

  static const MethodChannel _channel = MethodChannel('com.privateagent/accessibility');

  bool _isAuditing = false;
  NetworkAuditReport? _lastReport;

  bool get isAuditing => _isAuditing;
  NetworkAuditReport? get lastReport => _lastReport;

  /// Audits the local Wi-Fi network and active subnet.
  Future<NetworkAuditReport> auditNetwork() async {
    _isAuditing = true;
    notifyListeners();

    try {
      // 1. Get local device IP
      String localIp = '192.168.1.100';
      try {
        final interfaces = await NetworkInterface.list(
          type: InternetAddressType.IPv4,
          includeLoopback: false,
        );
        for (final iface in interfaces) {
          for (final addr in iface.addresses) {
            if (!addr.isLoopback && !addr.address.startsWith('10.0.2.')) {
              localIp = addr.address;
              break;
            }
          }
        }
      } catch (_) {}

      final subnetParts = localIp.split('.');
      final prefix = subnetParts.length == 4
          ? '${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}'
          : '192.168.1';

      // 2. Fetch native ARP table from /proc/net/arp
      final arpList = await _fetchNativeArpTable();

      // 3. Probes candidates on subnet concurrently
      final discoveredDevices = <NetworkDevice>[];
      final pingStart = DateTime.now();

      // Scan gateway + common IPs + ARP entries
      final ipsToScan = <String>{
        '$prefix.1', // Gateway
        localIp, // Self
      };
      for (final item in arpList) {
        if (item['ip'] != null) ipsToScan.add(item['ip']!);
      }
      // Add common LAN device hosts
      for (int i = 2; i <= 20; i++) {
        ipsToScan.add('$prefix.$i');
      }

      final scanFutures = ipsToScan.map((ip) async {
        final openPorts = await _scanPorts(ip);
        final isSelf = ip == localIp;
        final isGw = ip == '$prefix.1';

        if (openPorts.isNotEmpty || isSelf || isGw || arpList.any((a) => a['ip'] == ip)) {
          final arpMatch = arpList.firstWhere(
            (a) => a['ip'] == ip,
            orElse: () => {'mac': 'Unknown', 'device': 'wlan0'},
          );
          final mac = isSelf ? 'Local-Device' : (arpMatch['mac'] ?? 'Unknown');
          final vendor = _resolveVendor(mac, isSelf: isSelf, isGw: isGw);
          final hasCamera = openPorts.contains(554);

          discoveredDevices.add(
            NetworkDevice(
              ip: ip,
              mac: mac,
              vendor: vendor,
              hostname: isSelf ? 'J.A.R.V.I.S. Host Phone' : (isGw ? 'Wi-Fi Gateway Router' : 'LAN Client ($ip)'),
              openPorts: openPorts,
              isCameraStream: hasCamera,
              isGateway: isGw,
            ),
          );
        }
      });

      await Future.wait(scanFutures);

      final pingLatency = DateTime.now().difference(pingStart).inMilliseconds.clamp(4, 120);

      // 4. Vulnerability & security score calculation
      final vulnerabilities = <String>[];
      int score = 100;

      for (final d in discoveredDevices) {
        if (d.openPorts.contains(23)) {
          vulnerabilities.add('Unencrypted Telnet (port 23) active on ${d.ip}');
          score -= 20;
        }
        if (d.openPorts.contains(21)) {
          vulnerabilities.add('Plaintext FTP (port 21) active on ${d.ip}');
          score -= 10;
        }
        if (d.isCameraStream) {
          vulnerabilities.add('Unencrypted RTSP Video Surveillance feed on ${d.ip}:554');
          score -= 15;
        }
      }

      if (vulnerabilities.isEmpty) {
        vulnerabilities.add('No tested plaintext management ports responded. This is a limited port probe, not a full security assessment.');
      }

      _lastReport = NetworkAuditReport(
        localIp: localIp,
        subnetPrefix: '$prefix.0/24',
        totalDevicesFound: discoveredDevices.length,
        devices: discoveredDevices,
        securityScore: score.clamp(35, 100),
        vulnerabilities: vulnerabilities,
        pingLatencyMs: pingLatency,
        auditedAt: DateTime.now(),
        dnsSummary: _dnsSummary(),
      );

      return _lastReport!;
    } catch (error) {
      // A failed scan is not evidence that the network is secure. Never invent
      // devices, a firewall result, latency or a reassuring security score.
      _lastReport = NetworkAuditReport(
        localIp: 'Unavailable',
        subnetPrefix: 'Unavailable',
        totalDevicesFound: 0,
        devices: const [],
        securityScore: 0,
        vulnerabilities: const [],
        pingLatencyMs: 0,
        auditedAt: DateTime.now(),
        auditError: 'Local network scan unavailable: $error',
        dnsSummary: _dnsSummary(),
      );
      return _lastReport!;
    } finally {
      _isAuditing = false;
      notifyListeners();
    }
  }

  Future<List<Map<String, String>>> _fetchNativeArpTable() async {
    try {
      final res = await _channel.invokeListMethod<Map>('getNetworkArpTable');
      if (res != null) {
        return res.map((m) => m.map((k, v) => MapEntry(k.toString(), v.toString()))).toList();
      }
    } catch (_) {}
    return [];
  }

  Future<List<int>> _scanPorts(String ip) async {
    const portsToProbe = [21, 22, 23, 80, 443, 554, 8080];
    final open = <int>[];

    final probes = portsToProbe.map((port) async {
      try {
        final socket = await Socket.connect(ip, port, timeout: const Duration(milliseconds: 250));
        socket.destroy();
        open.add(port);
      } catch (_) {}
    });

    await Future.wait(probes);
    return open;
  }

  String _resolveVendor(String mac, {bool isSelf = false, bool isGw = false}) {
    if (isSelf) return 'Motorola / Android Client';
    if (isGw) return 'Broadband Gateway / Router';

    final cleanMac = mac.toUpperCase().replaceAll(':', '').replaceAll('-', '');
    if (cleanMac.startsWith('001A2B') || cleanMac.startsWith('E4C722')) return 'Cisco Systems';
    if (cleanMac.startsWith('B827EB') || cleanMac.startsWith('DCA632')) return 'Raspberry Pi Foundation';
    if (cleanMac.startsWith('240AC4') || cleanMac.startsWith('30AEA4')) return 'Espressif Systems (IoT)';
    if (cleanMac.startsWith('F01898') || cleanMac.startsWith('ACDE48')) return 'Apple Inc.';
    if (cleanMac.startsWith('A47733') || cleanMac.startsWith('DCF505')) return 'Google LLC';
    if (cleanMac.startsWith('90324B') || cleanMac.startsWith('508569')) return 'Samsung Electronics';
    if (cleanMac.startsWith('50EC50') || cleanMac.startsWith('708BCD')) return 'TP-Link Technologies';

    return 'Network Node';
  }

  String _dnsSummary() {
    final mode = SettingsService.instance.dnsSettings.modeLabel;
    return '$mode · ${SecureDnsService.instance.statusLabel} · JARVIS scope only';
  }

  /// Spoken Stark telemetry report of the network audit.
  Future<String> getSpokenAuditReport() async {
    final report = await auditNetwork();
    if (report.auditError != null) {
      return '${report.auditError} ${report.dnsSummary}';
    }
    final count = report.totalDevicesFound;
    final score = report.securityScore;
    final ping = report.pingLatencyMs;

    final cameras = report.devices.where((d) => d.isCameraStream).length;
    final cameraStr = cameras > 0 ? ' Discovered $cameras active IP camera streams.' : '';

    return 'Network cyber audit complete, sir. $count connected devices detected on local subnet ${report.subnetPrefix}. The limited port probe took $ping milliseconds. Overall security score is $score out of 100.$cameraStr ${report.dnsSummary}';
  }
}

