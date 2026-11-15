# Advanced DNS security — JARVIS scope

This upgrade protects **JARVIS-owned Dart HTTP and WebSocket connections**. It is
not an Android VPN, does not change Android Private DNS, and does not protect other
apps. No Android permission or native privileged setting was added.

## What changed

- RFC 8484 DNS-over-HTTPS (DoH) using `application/dns-message` POST.
- Resolver connections use published **bootstrap IP literals**, so looking up the
  resolver itself does not leak through the system resolver.
- TLS keeps the resolver hostname for SNI, HTTP Host and normal certificate
  verification. Certificate bypasses, TLS key logging and proxy overrides are
  rejected while encrypted DNS is enabled.
- A/AAAA resolution, IPv4/IPv6 bootstrap failover within the selected provider,
  concurrent-query coalescing and a bounded in-memory TTL cache.
- **Fail closed:** DoH errors never fall back to UDP/TCP port 53 or another
  unfiltered provider. Filtering responses are not bypassed.
- Bounds-checked DNS parsing: matching ID/question, CNAME chains, compression
  pointer-loop rejection, address-length checks, response-size/record limits and
  no trailing-data acceptance.
- Public DNS answers that point into loopback, private LAN, link-local or other
  reserved ranges are rejected to reduce DNS-rebinding risk.
- A settings screen with real connection checks, filtering checks, session-only
  counters and an explicit coverage notice. Saved preferences alone are not shown
  as proof that DoH is working.
- The ISS integration now uses the HTTPS “Where the ISS at?” API instead of the
  old plaintext OpenNotify endpoint. Failed satellite lookups no longer fabricate
  a live position.

## Modes

| Mode | DNS behavior | Remote HTTP / `ws://` | Failure behavior |
|---|---|---|---|
| **Advanced / strict** (default) | DoH through selected profile | Blocked, except explicit local exceptions below | No plaintext DNS fallback |
| **Compatibility** | DoH through selected profile | Allowed for existing APIs; payload is still plaintext | No plaintext DNS fallback |
| **System DNS** | Platform resolver; this module is disabled | Platform behavior | No JARVIS DNS guarantee |

Changing to Compatibility or System requires confirmation in the settings UI.
Voice commands such as **“DNS security”**, **“DNS status”** or **“check DNS”** open
the controls and report status; they do not silently change security policy.

## Resolver profiles

The built-in presets use Cloudflare's globally distributed anycast service:

| Profile | Endpoint | Published bootstrap IPs |
|---|---|---|
| Security (default) | `https://security.cloudflare-dns.com/dns-query` | `1.1.1.2`, `1.0.0.2`, `2606:4700:4700::1112`, `2606:4700:4700::1002` |
| Family | `https://family.cloudflare-dns.com/dns-query` | `1.1.1.3`, `1.0.0.3`, `2606:4700:4700::1113`, `2606:4700:4700::1003` |
| Standard (unfiltered) | `https://cloudflare-dns.com/dns-query` | `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` |

Sources: [Cloudflare setup documentation](https://github.com/cloudflare/cloudflare-docs/blob/production/src/content/docs/1.1.1.1/setup/index.mdx)
and [Cloudflare resolver IP addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/).
“Global” describes the provider's anycast reach, **not device-wide coverage**.
The presets share one operator; use a custom resolver if you need operator diversity.

### Custom resolver requirements

- HTTPS URL with no embedded credentials, query string or fragment.
- RFC 8484 wire-format POST and `application/dns-message` responses.
- HTTP/1.1 support (the transport offers `http/1.1` ALPN). HTTP/2-only and JSON-only
  DoH APIs are not supported by this implementation.
- A certificate trusted by the platform and valid for the endpoint hostname.
- One to eight published IPv4/IPv6 bootstrap addresses from the operator.

The connection check queries `example.com`; filtering presets also query the
provider's safe test domain (`malware.testcategory.com` or
`nudity.testcategory.com`). No chat content is sent by the check. Filtering is
best-effort upstream categorization, not antivirus or a guarantee of safety.

## Coverage

Covered after bootstrap in the main and overlay isolates:

- AI/chat/vision HTTP clients and streaming completions.
- JARVIS news/search/weather tools, finance, commute and sound lookup clients.
- Telegram bot HTTP, Home Assistant HTTP and airspace/YouTube lookups.
- Edge neural TTS `wss://` connections.
- Future Dart `HttpClient()`/`http.Client()` calls that honor `HttpOverrides`,
  including HTTP redirects (each redirect is checked again).

Not covered:

- Other Android apps, browsers opened with `url_launcher`, or WebViews.
- Android's native speech recognizer and other plugin-owned native network stacks.
- Raw IP sockets such as the local subnet port scanner (they do not use DNS).
- Code that deliberately creates a client outside Dart's `HttpOverrides` or runs
  in an isolate that has not installed the service. The DoH bootstrap transport
  intentionally does this to avoid recursive resolution.

## Local services

- `127.0.0.1`, `::1`, `localhost` and `*.localhost` are handled locally and are not
  sent to the public resolver. Loopback HTTP remains available for local Ollama.
- The **Private-LAN HTTP exception** allows HTTP to explicit RFC1918/ULA IP URLs
  in Advanced mode. Turn it off to require HTTPS for private IP URLs too.
- Link-local/metadata addresses are not part of the LAN exception.
- A public hostname whose DNS answer is private/reserved is still blocked. Configure
  a trusted local server by explicit IP, or use a public HTTPS hostname.
- `.local` mDNS names are not given a public-DNS exception; use an IP address or a
  properly configured HTTPS hostname.

## Cache and diagnostics

- Maximum 512 records; address TTL clamped to 5–3600 seconds; negative/empty
  answers cached for 30 seconds. No stale-on-error answers.
- Cache and counters are memory-only. The UI does not log queried domain names.
- Clearing the cache or changing policy invalidates verification and immediately
  closes existing app HTTP connections, including in-flight redirects, so answers
  and connections from the old policy cannot be reused.
- The upstream DNSSEC **AD flag** is reported only as the resolver's assertion.
  JARVIS does not independently validate DNSSEC signatures.

## Limitations and operational notes

- DoH hides DNS query content from the local network path, but the resolver sees
  queries and the device's network address. Destination IPs and normal TLS SNI can
  still be visible; this is not anonymity or a full traffic tunnel.
- Captive portals and networks that block DoH can break requests. Protection does
  not silently downgrade; explicitly choose Compatibility/System if appropriate.
- Encrypted modes use direct connections, not HTTP proxies. System mode restores
  the normal client transport behavior.
- HTTPS API payloads remain protected by TLS in every mode; Compatibility only
  relaxes the restriction on remote plaintext HTTP endpoints.
- Provider bootstrap IPs are published constants. Review them when the operator
  changes its infrastructure; do not replace them with an arbitrary DNS lookup.

## Verification

Run with the project's Flutter/Dart toolchain:

```sh
flutter pub get
flutter analyze
flutter test test/dns_message_test.dart test/dns_security_test.dart \
  test/dns_resolver_test.dart test/secure_dns_service_test.dart
flutter test
```

On a real Android device:

1. Open **Settings → Network Privacy & DNS → Advanced DNS security**.
2. Apply Advanced mode and run the connection check. Confirm DoH reachability and,
   for Security/Family, whether the safe filtering test was blocked.
3. Exercise an HTTPS AI provider, neural TTS and a normal JARVIS web tool.
4. Confirm local Ollama still works through `127.0.0.1`/`localhost`.
5. In Advanced mode, confirm a remote `http://` API is rejected with the plaintext
   warning; Compatibility should permit it while still using DoH for its hostname.
6. Disable connectivity and confirm protected hostname requests fail rather than
   resolving through the system resolver. A packet capture should show no port-53
   fallback for covered connections.
7. Test an invalid/self-signed custom resolver certificate and confirm failure.
8. Switch to System mode only after the explicit confirmation; the UI must stop
   claiming JARVIS DoH protection.

The automated tests use an injected DoH transport and a loopback HTTP server for
policy/cache/fail-closed behavior. Real provider TLS, Android networking and
packet-capture checks still require device/network validation.
