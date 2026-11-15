import 'package:flutter/material.dart';

import '../../models/dns_security.dart';
import '../../services/secure_dns_service.dart';
import '../../services/settings_service.dart';
import '../../widgets/glass_widgets.dart';

/// Advanced DNS controls with an explicit application-only coverage boundary.
class DnsSecurityScreen extends StatefulWidget {
  const DnsSecurityScreen({super.key});
  @override
  State<DnsSecurityScreen> createState() => _DnsSecurityScreenState();
}

class _DnsSecurityScreenState extends State<DnsSecurityScreen> {
  final _settings = SettingsService.instance;
  final _dns = SecureDnsService.instance;
  late DnsSettings _draft;
  late final TextEditingController _endpoint;
  late final TextEditingController _bootstrap;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _dns.install();
    _draft = _settings.dnsSettings;
    _endpoint = TextEditingController(text: _draft.customEndpoint);
    _bootstrap = TextEditingController(text: _draft.customBootstrapAddresses);
  }

  @override
  void dispose() {
    _endpoint.dispose();
    _bootstrap.dispose();
    super.dispose();
  }

  DnsSettings get _form => _draft.copyWith(
    customEndpoint: _endpoint.text.trim(),
    customBootstrapAddresses: _bootstrap.text.trim(),
  );

  bool get _dirty =>
      _form.mode != _settings.dnsSettings.mode ||
      _form.providerId != _settings.dnsSettings.providerId ||
      _form.customEndpoint != _settings.dnsSettings.customEndpoint ||
      _form.customBootstrapAddresses != _settings.dnsSettings.customBootstrapAddresses ||
      _form.allowPrivateLan != _settings.dnsSettings.allowPrivateLan;

  void _message(String text, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(
        content: Text(text),
        behavior: SnackBarBehavior.floating,
        backgroundColor: error ? Theme.of(context).colorScheme.error : null,
      ));
  }

  Future<void> _apply() async {
    final next = _form;
    try {
      next.validate();
    } catch (error) {
      _message(error.toString(), error: true);
      return;
    }
    if (next.mode != DnsSecurityMode.advanced) {
      final warning = next.mode == DnsSecurityMode.system
          ? 'JARVIS will use the system resolver. This module will no longer encrypt its DNS queries. Other Android settings will not be changed.'
          : 'DNS will remain encrypted and fail closed, but remote HTTP API content can be sent in plaintext. HTTPS endpoints remain encrypted.';
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(next.mode == DnsSecurityMode.system ? 'Disable JARVIS DoH?' : 'Allow plaintext APIs?'),
          content: Text(warning),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Confirm')),
          ],
        ),
      );
      if (confirmed != true || !mounted) return;
    }
    setState(() => _saving = true);
    try {
      await _settings.setDnsSettings(next);
      if (!mounted) return;
      setState(() => _draft = next);
      _message('DNS policy applied. Run a connection check to verify the resolver.');
    } catch (error) {
      _message(error.toString(), error: true);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _check() async {
    try {
      final report = await _dns.checkResolver();
      _message(report.message, error: !report.transportVerified);
    } catch (error) {
      _message(error.toString(), error: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('DNS security')),
      body: ListenableBuilder(
        listenable: Listenable.merge([_settings, _dns]),
        builder: (context, _) {
          final active = _settings.dnsSettings;
          final report = _dns.lastReport;
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 40),
            children: [
              _statusCard(theme, active),
              const SizedBox(height: 20),
              _heading(theme, Icons.tune_rounded, 'Protection mode'),
              GlassCard(
                child: Column(children: [
                  _mode(theme, DnsSecurityMode.advanced, 'Advanced / strict',
                      'Encrypted DNS, fail closed, HTTPS-only remote connections. Recommended.', Icons.verified_user_outlined),
                  const Divider(height: 20),
                  _mode(theme, DnsSecurityMode.compatibility, 'Compatibility',
                      'Encrypted DNS, fail closed. Allows existing remote HTTP APIs; their content is not encrypted.', Icons.swap_horiz_rounded),
                  const Divider(height: 20),
                  _mode(theme, DnsSecurityMode.system, 'System DNS',
                      'Explicitly disable this module. Use the platform resolver and transport behavior.', Icons.settings_ethernet_rounded),
                ]),
              ),
              const SizedBox(height: 20),
              _heading(theme, Icons.public_rounded, 'Encrypted resolver'),
              GlassCard(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Text('Global anycast presets · JARVIS connections only',
                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 12),
                  RadioGroup<String>(
                    groupValue: _draft.providerId,
                    onChanged: (value) {
                      if (_saving || value == null) return;
                      setState(() => _draft = _draft.copyWith(providerId: value));
                    },
                    child: Column(children: [
                      for (final profile in DnsProviderProfile.presets)
                        RadioListTile<String>(
                          value: profile.id,
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                          title: Text(profile.label, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
                          subtitle: Text(profile.description, style: const TextStyle(fontSize: 12)),
                        ),
                      const RadioListTile<String>(
                        value: 'custom',
                        contentPadding: EdgeInsets.zero,
                        dense: true,
                        title: Text('Custom DoH resolver', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
                        subtitle: Text('RFC 8484 POST · HTTPS · valid certificate required', style: TextStyle(fontSize: 12)),
                      ),
                    ]),
                  ),
                  if (_draft.providerId == 'custom') ...[
                    const SizedBox(height: 10),
                    GlassTextField(
                      controller: _endpoint,
                      labelText: 'DoH endpoint',
                      hintText: 'https://resolver.example/dns-query',
                      keyboardType: TextInputType.url,
                      enabled: !_saving,
                      onChanged: (_) => setState(() {}),
                    ),
                    const SizedBox(height: 12),
                    GlassTextField(
                      controller: _bootstrap,
                      labelText: 'Resolver bootstrap IPs',
                      hintText: 'IPv4 / IPv6, separated by commas',
                      maxLines: 2,
                      enabled: !_saving,
                      onChanged: (_) => setState(() {}),
                    ),
                    const SizedBox(height: 8),
                    Text('Use the resolver operator’s published IPs, not an arbitrary DNS lookup. '
                        'Self-signed certificates and credentials in the URL are rejected.',
                        style: theme.textTheme.bodySmall),
                  ],
                  if (active.isEncrypted) ...[
                    const SizedBox(height: 12),
                    Text('Active endpoint: ${_endpointFor(active)}',
                        style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 11)),
                  ],
                ]),
              ),
              const SizedBox(height: 20),
              _heading(theme, Icons.lan_outlined, 'Local services & privacy'),
              GlassCard(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  GlassSwitchTile(
                    title: 'Private-LAN HTTP exception',
                    subtitle: 'Allow HTTP to explicit private IPs in Advanced mode. Loopback is always allowed; DNS answers pointing into your LAN remain blocked.',
                    value: _draft.allowPrivateLan,
                    icon: Icons.router_outlined,
                    onChanged: _saving ? (_) {} : (value) => setState(() => _draft = _draft.copyWith(allowPrivateLan: value)),
                  ),
                  const SizedBox(height: 8),
                  Text('For local Ollama, use 127.0.0.1 or localhost. For Home Assistant, prefer HTTPS; '
                      'use a private IP for a trusted HTTP server. Public hostnames are resolved through DoH.',
                      style: theme.textTheme.bodySmall),
                ]),
              ),
              const SizedBox(height: 16),
              if (_dirty)
                Padding(padding: const EdgeInsets.only(bottom: 10),
                    child: Text('Unapplied changes', style: TextStyle(color: theme.colorScheme.primary, fontWeight: FontWeight.w600))),
              FilledButton.icon(
                onPressed: _saving || !_dirty ? null : _apply,
                icon: _saving
                    ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.check_rounded),
                label: Text(_saving ? 'Applying…' : 'Apply DNS settings'),
              ),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: _dns.isChecking || !active.isEncrypted || _dirty ? null : _check,
                icon: _dns.isChecking
                    ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.network_check_rounded),
                label: Text(_dns.isChecking ? 'Checking DoH…' : 'Run connection check'),
              ),
              if (_dirty)
                const Padding(padding: EdgeInsets.only(top: 6),
                    child: Text('Apply your changes before checking the active resolver.', style: TextStyle(fontSize: 11))),
              const SizedBox(height: 8),
              Text('The check queries example.com and, for filtering presets, the provider’s safe test domain. '
                  'It does not send chat content. Results describe this check, not continuous protection.',
                  style: theme.textTheme.bodySmall),
              if (report != null) ...[
                const SizedBox(height: 16),
                GlassCard(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(report.transportVerified ? 'Last check: DoH reachable' : 'Last check: failed',
                      style: TextStyle(fontWeight: FontWeight.w700,
                          color: report.transportVerified ? theme.colorScheme.primary : theme.colorScheme.error)),
                  const SizedBox(height: 8),
                  Text(report.message, style: theme.textTheme.bodySmall),
                  const SizedBox(height: 8),
                  Text('Elapsed: ${report.latencyMs} ms · Filtering: ${report.filteringObserved == null ? 'not tested / inconclusive' : report.filteringObserved! ? 'observed' : 'not observed'}',
                      style: theme.textTheme.bodySmall),
                  if (report.transportVerified)
                    Text('Upstream DNSSEC AD flag: ${report.upstreamDnssec ? 'set' : 'not set'} (not independently validated by JARVIS)',
                        style: theme.textTheme.bodySmall),
                ])),
              ],
              const SizedBox(height: 20),
              _heading(theme, Icons.analytics_outlined, 'Session diagnostics'),
              GlassCard(child: Column(children: [
                Row(children: [
                  _metric(theme, 'DoH queries', _dns.networkQueries),
                  _metric(theme, 'Cache hits', _dns.cacheHits),
                  _metric(theme, 'Filter replies', _dns.sinkholedReplies),
                ]),
                const SizedBox(height: 12),
                Text('${_dns.cachedRecords} cached records · ${_dns.failedQueries} failed query attempts · ${_dns.connectionsOpened} connections opened',
                    style: theme.textTheme.bodySmall),
                if (_dns.lastError != null) ...[
                  const SizedBox(height: 8),
                  Text(_dns.lastError!, style: TextStyle(color: theme.colorScheme.error, fontSize: 12)),
                ],
                const SizedBox(height: 8),
                Align(alignment: Alignment.centerRight,
                    child: TextButton.icon(onPressed: _dns.clearCache,
                        icon: const Icon(Icons.cleaning_services_outlined, size: 18), label: const Text('Clear DNS cache'))),
                Text('Counters are memory-only and reset when the app restarts. Domain names are not logged here. '
                    'Clearing the cache closes existing app HTTP connections so stale answers cannot be reused.',
                    style: theme.textTheme.bodySmall),
              ])),
              const SizedBox(height: 20),
              GlassCard(child: ExpansionTile(
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(bottom: 12),
                title: const Text('Coverage & limitations', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
                children: const [
                  _CoverageLine('Covers JARVIS Dart HTTP helpers and Edge neural TTS, including redirects and WebSockets.'),
                  _CoverageLine('Does not cover other Android apps, native speech recognition, external browsers, WebViews or plugin-owned network stacks.'),
                  _CoverageLine('No VPN, root access, Android Private DNS changes or new Android permissions.'),
                  _CoverageLine('The resolver sees queried domains and your network address. DoH is not anonymity, a full traffic tunnel, antivirus or a guarantee against malicious sites.'),
                  _CoverageLine('Direct IP URLs need no DNS. Local exceptions are explicit; certificate validation is never bypassed.'),
                  _CoverageLine('Captive portals and networks that block DoH can cause requests to fail. Change mode explicitly if needed; there is no silent downgrade.'),
                ],
              )),
            ],
          );
        },
      ),
    );
  }

  String _endpointFor(DnsSettings settings) {
    try { return settings.profile.endpoint; }
    catch (_) { return 'Invalid configuration — requests fail closed'; }
  }

  Widget _statusCard(ThemeData theme, DnsSettings active) {
    final color = !active.isEncrypted || _dns.lastCheckedAt == null
        ? theme.colorScheme.onSurfaceVariant
        : (_dns.lastCheckSucceeded && _dns.lastError == null)
            ? theme.colorScheme.primary
            : theme.colorScheme.error;
    return GlassCard(
      borderColor: color.withValues(alpha: 0.45),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(Icons.shield_outlined, color: color, size: 30),
          const SizedBox(width: 12),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('APPLICATION DNS SHIELD', style: TextStyle(fontSize: 11, letterSpacing: 1.2, fontWeight: FontWeight.w800)),
            const SizedBox(height: 4),
            Text(active.modeLabel, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
          ])),
        ]),
        const SizedBox(height: 14),
        Text(_dns.statusLabel, style: TextStyle(color: color, fontWeight: FontWeight.w700, fontSize: 13)),
        const SizedBox(height: 8),
        const Text(SecureDnsService.coverageNotice, style: TextStyle(fontSize: 12, height: 1.5)),
        const SizedBox(height: 12),
        Wrap(spacing: 8, runSpacing: 8, children: [
          GlassPill(label: active.isEncrypted ? 'DNS over HTTPS' : 'Platform resolver', color: color, icon: const Icon(Icons.lock_outline, size: 13)),
          GlassPill(label: 'No VPN permission', color: color, icon: const Icon(Icons.phone_android_rounded, size: 13)),
        ]),
      ]),
    );
  }

  Widget _mode(ThemeData theme, DnsSecurityMode mode, String title, String description, IconData icon) {
    final selected = _draft.mode == mode;
    return Semantics(
      selected: selected,
      button: true,
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: _saving ? null : () => setState(() => _draft = _draft.copyWith(mode: mode)),
        child: Padding(padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4), child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: selected ? theme.colorScheme.primary : theme.colorScheme.onSurfaceVariant, size: 22),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(title, style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700,
                  color: selected ? theme.colorScheme.primary : null)),
              const SizedBox(height: 4),
              Text(description, style: theme.textTheme.bodySmall?.copyWith(height: 1.4)),
            ])),
            const SizedBox(width: 8),
            Icon(selected ? Icons.radio_button_checked : Icons.radio_button_off,
                color: selected ? theme.colorScheme.primary : theme.colorScheme.outline, size: 20),
          ],
        )),
      ),
    );
  }

  Widget _heading(ThemeData theme, IconData icon, String title) => Padding(
    padding: const EdgeInsets.fromLTRB(4, 0, 4, 10),
    child: Row(children: [
      Icon(icon, size: 17, color: theme.colorScheme.primary),
      const SizedBox(width: 8),
      Text(title, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
    ]),
  );

  Widget _metric(ThemeData theme, String label, int value) => Expanded(
    child: Column(children: [
      Text('$value', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: theme.colorScheme.primary)),
      const SizedBox(height: 4),
      Text(label, textAlign: TextAlign.center, style: theme.textTheme.bodySmall),
    ]),
  );
}

class _CoverageLine extends StatelessWidget {
  final String text;
  const _CoverageLine(this.text);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const Text('•  '),
      Expanded(child: Text(text, style: Theme.of(context).textTheme.bodySmall?.copyWith(height: 1.4))),
    ]),
  );
}
