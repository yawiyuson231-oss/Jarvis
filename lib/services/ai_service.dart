import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'conversational_memory_service.dart';
import 'hermes_evolution_service.dart';
import 'personality_service.dart';
import 'settings_service.dart';

/// Error thrown for any AI-gateway failure (network, auth, bad payload).
class AiException implements Exception {
  final String message;
  final int? statusCode;
  const AiException(this.message, {this.statusCode});

  @override
  String toString() =>
      statusCode == null ? message : 'HTTP $statusCode: $message';
}

/// User-friendly result of a real request to the configured AI provider.
class AiConnectionResult {
  final bool success;
  final String message;
  final int? statusCode;
  final Duration elapsed;

  const AiConnectionResult({
    required this.success,
    required this.message,
    required this.elapsed,
    this.statusCode,
  });
}

/// Structured intent classification result for JARVIS mode.
enum JarvisIntentType {
  chat,
  action,
  system,
  webSearch,
  news,
  weather,
  battery,
  datetime,
  torch,
  workflow,
  routine,
  finance,
  sports,
  todo,
  notes,
  calendar,
  email,
  message,
  vision,
  multistep,
  smartHome,
  commute,
  macro,
  airGestures,
  chargingTelemetry,
  polyglotDiplomat,
  codeBlack,
  floatingCopilot,
  airspaceRadar,
  multiTaskDump,
  opticalSolver,
  networkAudit,
}

class JarvisIntent {
  final JarvisIntentType type;
  final String spoken;
  final String? actionGoal;
  final String? systemCommand;
  final String? toolArg;

  const JarvisIntent({
    required this.type,
    required this.spoken,
    this.actionGoal,
    this.systemCommand,
    this.toolArg,
  });

  factory JarvisIntent.fallback(String command) {
    final lower = command.toLowerCase().trim();

    // 0. Jarvis Eye Optical Vision check
    if (lower.contains('look at this') ||
        lower.contains('what is this') ||
        lower.contains('scan this') ||
        lower.contains('inspect this') ||
        lower.contains('jarvis eye') ||
        lower.contains('what do you see')) {
      return JarvisIntent(
        type: JarvisIntentType.vision,
        spoken: 'Jarvis Eye optical sensors active, sir.',
        toolArg: command,
      );
    }

    // 0b. Autonomous Macro Recorder check
    if (lower.startsWith('record macro') ||
        lower.startsWith('start recording') ||
        lower.startsWith('stop recording') ||
        lower.startsWith('save macro') ||
        lower.startsWith('replay macro') ||
        lower.startsWith('run macro')) {
      return JarvisIntent(
        type: JarvisIntentType.macro,
        spoken: 'Accessing autonomous macro recorder, sir.',
        toolArg: command,
      );
    }

    // 0c. Smart Home & IoT Automation check
    if (lower.contains('smart light') ||
        lower.contains('smart home') ||
        lower.contains('living room light') ||
        lower.contains('turn on the light') ||
        lower.contains('turn off the light') ||
        lower.contains('dim the light') ||
        lower.contains('turn on light') ||
        lower.contains('turn off light') ||
        lower.contains('desk lamp')) {
      return JarvisIntent(
        type: JarvisIntentType.smartHome,
        spoken: 'Accessing smart home and IoT telemetry, sir.',
        toolArg: command,
      );
    }

    // 0d. Proactive Commute & Traffic check
    if (lower.contains('traffic') ||
        lower.contains('commute') ||
        lower.contains('drive time') ||
        lower.contains('when should i leave') ||
        lower.contains('travel time')) {
      return JarvisIntent(
        type: JarvisIntentType.commute,
        spoken: 'Analyzing traffic conditions and commute routes, sir.',
        toolArg: command,
      );
    }

    // 0e. Sentry Protocol & Sentry Mode check (Sentry Mode == Sentry Protocol)
    if (lower.contains('sentry') ||
        lower.contains('centry') ||
        lower.contains('century protocol') ||
        lower.contains('century mode') ||
        lower.contains('guard my phone') ||
        lower.contains('watch my phone') ||
        lower.contains('anti theft') ||
        lower.contains('anti-theft') ||
        lower.contains('watchdog protocol') ||
        lower.contains('watchdog mode')) {
      final isDisarm = lower.contains('deactivat') ||
          lower.contains('disarm') ||
          lower.contains('turn off') ||
          lower.contains('disable') ||
          lower.contains('stop') ||
          lower.contains('cancel') ||
          lower.contains('stand down');
      return JarvisIntent(
        type: JarvisIntentType.workflow,
        spoken: isDisarm
            ? 'Standing down Sentry Protocol, sir. Security watchdog disarmed.'
            : 'Sentry Protocol active, sir. Motion sensors armed. Security perimeter established.',
        toolArg: isDisarm ? 'sentry_disarm' : 'sentry_arm',
      );
    }

    // 0f. Iron Man Zero-Touch Air Gestures check
    if (lower.contains('air gesture') ||
        lower.contains('air gestures') ||
        lower.contains('zero touch') ||
        lower.contains('touchless') ||
        lower.contains('hand wave gesture')) {
      final isOff = lower.contains('off') || lower.contains('disable') || lower.contains('deactivat') || lower.contains('stop');
      return JarvisIntent(
        type: JarvisIntentType.airGestures,
        spoken: isOff
            ? 'Air gesture sensors disengaged, sir.'
            : 'Zero-touch air gestures engaged, sir. Proximity sensors active.',
        toolArg: command,
      );
    }

    // 0g. Arc Reactor Charging Telemetry check
    if (lower.contains('charging telemetry') ||
        lower.contains('arc reactor status') ||
        lower.contains('arc reactor telemetry') ||
        lower.contains('charge speed') ||
        lower.contains('charging wattage') ||
        lower.contains('charging speed')) {
      return JarvisIntent(
        type: JarvisIntentType.chargingTelemetry,
        spoken: 'Accessing Arc Reactor charging telemetry, sir.',
        toolArg: command,
      );
    }

    // 0h. Polyglot Diplomat Translator check
    if (lower.contains('polyglot') ||
        lower.contains('live translator') ||
        lower.contains('voice translator') ||
        lower.startsWith('translate between') ||
        lower.contains('diplomat translator')) {
      return JarvisIntent(
        type: JarvisIntentType.polyglotDiplomat,
        spoken: 'Polyglot Diplomat initialized, sir.',
        toolArg: command,
      );
    }

    // 0i. Code Black Deceptive Lockout check
    if (lower.contains('code black') ||
        lower.contains('deceptive lockout') ||
        lower.contains('kernel panic screen') ||
        lower.contains('emergency lockdown')) {
      return JarvisIntent(
        type: JarvisIntentType.codeBlack,
        spoken: 'Code Black deceptive lockout protocol engaging, sir.',
        toolArg: command,
      );
    }

    // 0j. Holographic Floating Co-Pilot check
    if (lower.contains('floating copilot') ||
        lower.contains('floating assistant') ||
        lower.contains('screen copilot') ||
        lower.contains('screen assistant')) {
      final isOff = lower.contains('hide') || lower.contains('close') || lower.contains('stop') || lower.contains('dismiss');
      return JarvisIntent(
        type: JarvisIntentType.floatingCopilot,
        spoken: isOff ? 'Floating co-pilot dismissed, sir.' : 'Holographic floating co-pilot active, sir.',
        toolArg: command,
      );
    }

    // 0k. Overhead Airspace & Satellite Radar check
    if (lower.contains('flying above me') ||
        lower.contains('what is flying') ||
        lower.contains('scan airspace') ||
        lower.contains('overhead flights') ||
        lower.contains('airspace radar') ||
        lower.contains('where is the iss') ||
        lower.contains('satellite pass')) {
      return JarvisIntent(
        type: JarvisIntentType.airspaceRadar,
        spoken: 'Scanning regional airspace and orbital tracking feeds, sir.',
        toolArg: command,
      );
    }

    // 0l. Chaotic Brain Dump Multi-Task check
    if (lower.startsWith('brain dump') ||
        lower.startsWith('process this dump') ||
        lower.startsWith('decouple:') ||
        (lower.contains(' and ') && (lower.contains('remind') || lower.contains('schedule')) && (lower.contains('draft') || lower.contains('whatsapp') || lower.contains('todo') || lower.contains('calculate')))) {
      return JarvisIntent(
        type: JarvisIntentType.multiTaskDump,
        spoken: 'Deconstructing chaotic multi-task dump into parallel directives, sir.',
        toolArg: command,
      );
    }

    // 0m. Real-Time Optical HUD Solver check
    if (lower.contains('solve this') ||
        lower.contains('solve equation') ||
        lower.contains('optical solver') ||
        lower.contains('inspect error') ||
        lower.contains('split bill') ||
        lower.contains('split this bill') ||
        lower.contains('solve math') ||
        lower.contains('analyze circuit')) {
      return JarvisIntent(
        type: JarvisIntentType.opticalSolver,
        spoken: 'Real-time optical HUD solver active, sir.',
        toolArg: command,
      );
    }

    // 0n. Network Cyber Security Audit check
    if (lower.contains('audit network') ||
        lower.contains('audit my network') ||
        lower.contains('scan wifi') ||
        lower.contains('who is on my wifi') ||
        lower.contains('network devices') ||
        lower.contains('network security') ||
        lower.contains('port scan')) {
      return JarvisIntent(
        type: JarvisIntentType.networkAudit,
        spoken: 'Initiating tactical network cyber security audit, sir.',
        toolArg: command,
      );
    }

    // 1. Morning / Evening Routine checks
    if (lower == 'good morning' ||
        lower.contains('morning briefing') ||
        lower.contains('start my morning') ||
        lower.contains('morning routine')) {
      return const JarvisIntent(
        type: JarvisIntentType.routine,
        spoken: 'Good morning, sir. Preparing your morning briefing now.',
        toolArg: 'morning',
      );
    }
    if ((lower == 'good night' ||
        lower == 'goodnight' ||
        lower.contains('evening routine') ||
        lower.contains('night routine') ||
        lower == 'bedtime' ||
        lower.contains('bedtime routine') ||
        lower == 'time for bed') &&
        !lower.contains('story')) {
      return const JarvisIntent(
        type: JarvisIntentType.routine,
        spoken: 'Initiating Night Protocol for you now, sir.',
        toolArg: 'evening',
      );
    }

    // 2. Finance / Crypto / Stock checks
    if (lower.contains('bitcoin') ||
        lower.contains('crypto') ||
        lower.contains('ethereum') ||
        lower.contains('solana') ||
        lower.contains('stock market') ||
        lower.contains('btc price')) {
      return JarvisIntent(
        type: JarvisIntentType.finance,
        spoken: 'Scanning financial markets and cryptocurrency telemetry, sir.',
        toolArg: command,
      );
    }

    // 3. Sports scores & schedules
    if (lower.contains('score') ||
        lower.contains('match') ||
        lower.contains('football') ||
        lower.contains('cricket') ||
        lower.contains('nba') ||
        lower.contains('premier league')) {
      return JarvisIntent(
        type: JarvisIntentType.sports,
        spoken: 'Checking sports feeds and match fixtures, sir.',
        toolArg: command,
      );
    }

    // 4. To-Do List & Task Tracking
    if (lower.startsWith('add to my todo') ||
        lower.startsWith('add to todo') ||
        lower.startsWith('add task ') ||
        lower.contains('todo list') ||
        lower.contains('to-do') ||
        lower == 'my tasks' ||
        lower == 'show tasks' ||
        lower.contains('pending tasks')) {
      return JarvisIntent(
        type: JarvisIntentType.todo,
        spoken: 'Accessing your task agenda, sir.',
        toolArg: command,
      );
    }

    // 5. Notes & Knowledge Base
    if (lower.startsWith('take a note') ||
        lower.startsWith('note down ') ||
        lower.startsWith('write a note') ||
        lower.contains('search my notes') ||
        lower.contains('in my notes') ||
        lower.contains('what did i note')) {
      return JarvisIntent(
        type: JarvisIntentType.notes,
        spoken: 'Accessing your personal knowledge base, sir.',
        toolArg: command,
      );
    }

    // 6. Calendar & Reminders
    if (lower.contains('calendar') ||
        lower.contains('my schedule') ||
        lower.contains('appointments') ||
        lower.startsWith('remind me to ') ||
        lower.startsWith('set a reminder') ||
        lower.contains('reminder for')) {
      return JarvisIntent(
        type: JarvisIntentType.calendar,
        spoken: 'Accessing your calendar schedule and reminders, sir.',
        toolArg: command,
      );
    }

    // 7. Email Triage & Drafting
    // 7. Email Triage & Inbox Reading
    if (lower.contains('email') ||
        lower.contains('mail inbox') ||
        lower.contains('read mail') ||
        lower.contains('draft reply') ||
        lower.contains('summarize email')) {
      return JarvisIntent(
        type: JarvisIntentType.email,
        spoken: 'Accessing email stream, sir.',
        toolArg: command,
      );
    }

    // 8. Message Drafting & SMS Inbox Reading
    if (lower.contains('sms') ||
        lower.contains('read text') ||
        lower.contains('read message') ||
        lower.contains('check message') ||
        lower.contains('sms inbox') ||
        lower.startsWith('draft message') ||
        lower.startsWith('send whatsapp') ||
        lower.startsWith('send text') ||
        lower.startsWith('send sms') ||
        lower.startsWith('text to ')) {
      return JarvisIntent(
        type: JarvisIntentType.message,
        spoken: 'Accessing communications telemetry, sir.',
        toolArg: command,
      );
    }

    // 9. Vision: Screen Understanding
    if (lower.contains("what's on my screen") ||
        lower.contains('what is on my screen') ||
        lower.contains('explain this screen') ||
        lower.contains('describe screen') ||
        lower.contains('what do you see')) {
      return JarvisIntent(
        type: JarvisIntentType.vision,
        spoken: 'Observing your active screen display now, sir.',
        toolArg: command,
      );
    }

    // 10. Multi-step Agentic Planning
    if (lower.startsWith('plan my trip') ||
        lower.startsWith('plan a trip') ||
        lower.startsWith('plan my travel') ||
        lower.contains('plan and book')) {
      return JarvisIntent(
        type: JarvisIntentType.multistep,
        spoken: 'Initiating multi-step executive planning sequence, sir.',
        toolArg: command,
      );
    }

    // Fast breaking news check
    if (lower.contains('news') ||
        lower.contains('headline') ||
        lower.contains('what happened today') ||
        lower.contains('breaking news')) {
      return const JarvisIntent(
        type: JarvisIntentType.news,
        spoken: 'Accessing live breaking news channels, sir.',
      );
    }

    // Fast workflow check (Study, Sleep, Work, Cinema) - Only if NOT a question
    final isQuestion = RegExp(
      r'^(what|who|where|when|why|how|explain|tell\s+me|search|lookup|define|is\s+it|can\s+you|could\s+you|do\s+you)\b',
      caseSensitive: false,
    ).hasMatch(lower);

    if (!isQuestion) {
      if (RegExp(r'\b(study mode|study protocol|study session|start studying)\b').hasMatch(lower)) {
        return const JarvisIntent(
          type: JarvisIntentType.workflow,
          spoken: 'Initiating Study Protocol, sir.',
          toolArg: 'study',
        );
      }
      if (RegExp(r'\b(sleep mode|sleep protocol|night mode|night protocol|goodnight|bedtime|go to sleep)\b').hasMatch(lower)) {
        return const JarvisIntent(
          type: JarvisIntentType.workflow,
          spoken: 'Activating Night Protocol, sir.',
          toolArg: 'night',
        );
      }
      if (RegExp(r'\b(work mode|work protocol|focus mode|focus protocol|deep work)\b').hasMatch(lower)) {
        return const JarvisIntent(
          type: JarvisIntentType.workflow,
          spoken: 'Focus Protocol engaged, sir.',
          toolArg: 'work',
        );
      }
      if (RegExp(r'\b(cinema mode|cinema protocol|movie mode|theatre mode)\b').hasMatch(lower)) {
        return const JarvisIntent(
          type: JarvisIntentType.workflow,
          spoken: 'Cinema Mode active, sir.',
          toolArg: 'cinema',
        );
      }
    }

    // Fast battery check
    if (lower.contains('battery') || lower.contains('charging')) {
      return const JarvisIntent(
        type: JarvisIntentType.battery,
        spoken: 'Checking battery status, sir.',
      );
    }

    // Fast weather check
    if (lower.contains('weather') || lower.contains('temperature')) {
      var city = '';
      if (lower.contains(' in ')) {
        city = lower.split(' in ').last.trim();
      }
      return JarvisIntent(
        type: JarvisIntentType.weather,
        spoken: 'Accessing meteorological telemetry, sir.',
        toolArg: city,
      );
    }

    // Fast date/time check
    if (RegExp(r'\b(what time is it|what time|current time|what is the time|what date|what day is it|today\x27s date)\b').hasMatch(lower) ||
        (lower == 'time' || lower == 'date')) {
      return const JarvisIntent(
        type: JarvisIntentType.datetime,
        spoken: 'Checking temporal diagnostics, sir.',
      );
    }

    // Fast flashlight check
    if (lower.contains('flashlight on') || lower.contains('torch on')) {
      return const JarvisIntent(
        type: JarvisIntentType.torch,
        spoken: 'Engaging flashlight, sir.',
        toolArg: 'on',
      );
    }
    if (lower.contains('flashlight off') || lower.contains('torch off')) {
      return const JarvisIntent(
        type: JarvisIntentType.torch,
        spoken: 'Deactivating flashlight, sir.',
        toolArg: 'off',
      );
    }

    // Fast search check
    if (lower.startsWith('search for ') ||
        lower.startsWith('who is ') ||
        lower.startsWith('what is ') ||
        lower.startsWith('tell me about ')) {
      final query = lower
          .replaceFirst('search for ', '')
          .replaceFirst('tell me about ', '')
          .trim();
      return JarvisIntent(
        type: JarvisIntentType.webSearch,
        spoken: 'Searching the live web for you now, sir.',
        toolArg: query.isNotEmpty ? query : command,
      );
    }

    if (lower.contains('volume up') ||
        lower.contains('louder') ||
        lower.contains('increase volume')) {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Increasing volume, sir.',
        systemCommand: 'volume_up',
      );
    }
    if (lower.contains('volume down') ||
        lower.contains('quieter') ||
        lower.contains('lower volume')) {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Lowering volume, sir.',
        systemCommand: 'volume_down',
      );
    }
    if (lower.contains('mute') || lower.contains('silence')) {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Muting audio, sir.',
        systemCommand: 'mute',
      );
    }
    if (lower.contains('screenshot') || lower.contains('screen shot')) {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Capturing screen now, sir.',
        systemCommand: 'screenshot',
      );
    }
    if (lower.contains('home screen') || lower == 'go home' || lower == 'home') {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Navigating to home screen, sir.',
        systemCommand: 'home',
      );
    }
    if (lower == 'go back' || lower == 'back') {
      return const JarvisIntent(
        type: JarvisIntentType.system,
        spoken: 'Going back, sir.',
        systemCommand: 'back',
      );
    }
    if (lower.startsWith('open ') ||
        lower.startsWith('play ') ||
        lower.startsWith('send ') ||
        lower.startsWith('turn ') ||
        lower.startsWith('call ') ||
        lower.startsWith('install ') ||
        lower.startsWith('download ') ||
        lower.startsWith('search ')) {
      return JarvisIntent(
        type: JarvisIntentType.action,
        spoken: 'Right away, sir. Executing command.',
        actionGoal: command,
      );
    }
    return const JarvisIntent(
      type: JarvisIntentType.chat,
      spoken: '',
    );
  }
}

/// Talks to OpenAI-compatible chat-completion endpoints
/// (DeepSeek, OpenRouter, NVIDIA NIM, Ollama, or a custom base URL).
class AiService {
  AiService._({http.Client? client}) : _client = client ?? http.Client();
  static final AiService instance = AiService._();

  /// Creates an isolated client for deterministic connection tests.
  factory AiService.withClient(http.Client client) =>
      AiService._(client: client);

  final http.Client _client;

  /// True for local backends (Ollama etc.) that accept any/empty API key.
  bool get _isLocalBackend {
    final settings = SettingsService.instance;
    if (settings.provider == 'ollama' || settings.localFirstPrivacyMode) {
      return true;
    }
    final host = Uri.tryParse(settings.baseUrl)?.host.toLowerCase() ?? '';
    return host == 'localhost' || host == '127.0.0.1' || host == '::1';
  }

  /// Builds the OpenAI-compatible endpoint from either a base URL or a full
  /// chat-completions URL. A missing scheme defaults to HTTPS, except for
  /// local/private addresses where HTTP is the common configuration.
  static Uri chatCompletionsUri(String baseUrl) {
    var value = baseUrl.trim();
    if (value.isEmpty) {
      throw const AiException('No base URL configured.');
    }

    if (!RegExp(r'^https?://', caseSensitive: false).hasMatch(value)) {
      if (value.contains('://')) {
        throw const AiException(
          'Unsupported Base URL scheme. Use an http:// or https:// URL.',
        );
      }
      final isPrivateAddress = RegExp(
        r'^(localhost|127\.0\.0\.1|\[?::1\]?|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)',
        caseSensitive: false,
      ).hasMatch(value);
      value = '${isPrivateAddress ? 'http' : 'https'}://$value';
    }

    final Uri uri;
    try {
      uri = Uri.parse(value);
    } on FormatException {
      throw const AiException(
        'The Base URL is invalid. Example: https://api.openai.com/v1',
      );
    }
    if ((uri.scheme != 'http' && uri.scheme != 'https') || uri.host.isEmpty) {
      throw const AiException(
        'The Base URL is invalid. Example: https://api.openai.com/v1',
      );
    }

    var path = uri.path.replaceAll(RegExp(r'/+$'), '');
    if (!path.endsWith('/chat/completions')) {
      path = '$path/chat/completions';
    }
    if (!path.startsWith('/')) path = '/$path';
    return uri.replace(path: path, fragment: '');
  }

  Uri _validateSettings(SettingsService settings) {
    if (settings.apiKey.trim().isEmpty && !_isLocalBackend) {
      throw const AiException(
        'No API key configured. Paste your provider key in Settings, then tap Test connection.',
      );
    }
    if (settings.model.trim().isEmpty) {
      throw const AiException('No model name configured.');
    }
    return chatCompletionsUri(settings.baseUrl);
  }

  Map<String, String> _buildHeaders(
    SettingsService settings, {
    required bool stream,
  }) {
    // Accept a key copied together with the word "Bearer" without sending
    // the invalid "Authorization: Bearer Bearer …" header.
    final apiKey = settings.apiKey.trim().replaceFirst(
      RegExp(r'^Bearer\s+', caseSensitive: false),
      '',
    ).trim();
    return <String, String>{
      'Content-Type': 'application/json',
      'Accept': stream ? 'text/event-stream' : 'application/json',
      if (apiKey.isNotEmpty) 'Authorization': 'Bearer $apiKey',
      'User-Agent':
          'Mozilla/5.0 (Linux; Android 14) '
          'AppleWebKit/537.36 (KHTML, like Gecko) '
          'Chrome/120.0.0.0 Mobile Safari/537.36',
      if (settings.provider == 'openrouter') ...{
        'HTTP-Referer': 'https://privateagent.local',
        'X-Title': 'JARVIS',
      },
    };
  }

  Map<String, dynamic> _completionBody(
    List<Map<String, dynamic>> messages,
    SettingsService settings, {
    required bool stream,
    int? maxTokens,
    double? temperature,
  }) =>
      <String, dynamic>{
        'model': settings.model.trim(),
        'messages': messages,
        'max_tokens': maxTokens ?? settings.maxTokens,
        'temperature': temperature ?? settings.temperature,
        'stream': stream,
      };

  static String _responseDetail(String body) {
    var detail = '';
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map) {
        final error = decoded['error'];
        if (error is Map) {
          detail = (error['message'] ?? error['detail'] ?? '').toString();
        } else if (error != null) {
          detail = error.toString();
        }
        if (detail.isEmpty) {
          detail = (decoded['message'] ?? decoded['detail'] ?? '').toString();
        }
      }
    } catch (_) {
      // Some gateways return plain text or an HTML error page.
    }
    if (detail.isEmpty) detail = body;
    detail = detail
        .replaceAll(RegExp(r'<[^>]*>'), ' ')
        .replaceAll(RegExp(r'Bearer\s+\S+', caseSensitive: false), 'Bearer [redacted]')
        .replaceAll(RegExp(r'\bsk-[A-Za-z0-9_-]{8,}'), '[redacted]')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    if (detail.length > 260) detail = '${detail.substring(0, 260)}…';
    return detail;
  }

  static AiException _responseError(int statusCode, String body) {
    final String hint;
    switch (statusCode) {
      case 400:
      case 422:
        hint = 'The provider rejected the request. Check the model name and Base URL.';
        break;
      case 401:
        hint = 'Authentication failed. Check that your API key is correct and active.';
        break;
      case 402:
        hint = 'Provider billing is required. Check your account balance or credits.';
        break;
      case 403:
        hint = 'Access denied. Check the API key permissions and provider access.';
        break;
      case 404:
        hint = 'Endpoint or model not found. Check the Base URL and Model fields.';
        break;
      case 408:
        hint = 'The provider timed out. Check your connection and try again.';
        break;
      case 429:
        hint = 'Rate limit or usage quota reached. Check provider limits/credits or try again later.';
        break;
      default:
        hint = statusCode >= 500
            ? 'The AI provider is temporarily unavailable. Try again shortly.'
            : 'The AI provider returned an unexpected error.';
    }
    final detail = _responseDetail(body);
    return AiException(
      detail.isEmpty ? hint : '$hint Provider says: $detail',
      statusCode: statusCode,
    );
  }

  AiException _networkError(Object error, Duration timeout) {
    if (error is TimeoutException) {
      return AiException(
        'Connection timed out after ${timeout.inSeconds}s. Check the internet connection, Base URL, and provider status.',
      );
    }
    final raw = error.toString().toLowerCase();
    if (_isLocalBackend &&
        (raw.contains('connection refused') ||
            raw.contains('failed host lookup') ||
            raw.contains('network is unreachable'))) {
      return const AiException(
        'Could not reach the local AI server. On Android, 127.0.0.1 and localhost mean the phone itself, not your PC. Start Ollama on your PC with OLLAMA_HOST=0.0.0.0, then use its Wi-Fi IP (for example http://192.168.1.10:11434/v1).',
      );
    }
    if (raw.contains('failed host lookup') ||
        raw.contains('name or service not known') ||
        raw.contains('nodename nor servname')) {
      return const AiException(
        'The server address could not be resolved. Check the Base URL spelling and your internet/DNS connection.',
      );
    }
    if (raw.contains('certificate') || raw.contains('handshake')) {
      return const AiException(
        'The secure TLS connection failed. Check the Base URL certificate and the phone date/time settings.',
      );
    }
    if (raw.contains('connection refused')) {
      return const AiException(
        'The server refused the connection. Check the Base URL, port, and whether the AI service is running.',
      );
    }
    return const AiException(
      'Could not connect to the AI provider. Check your internet connection and Base URL, then try again.',
    );
  }

  /// Performs a small real completion to validate URL, credentials and model.
  Future<AiConnectionResult> testConnection() async {
    final settings = SettingsService.instance;
    final stopwatch = Stopwatch()..start();
    try {
      await _postChatCompletion(
        <Map<String, dynamic>>[
          <String, String>{'role': 'user', 'content': 'Reply with OK.'},
        ],
        settings,
        maxTokens: 128,
        temperature: 0,
        timeout: const Duration(seconds: 30),
        allowEmptyContent: true,
      );
      stopwatch.stop();
      final elapsed = stopwatch.elapsed;
      final latency = elapsed.inMilliseconds < 1000
          ? '${elapsed.inMilliseconds} ms'
          : '${(elapsed.inMilliseconds / 1000).toStringAsFixed(1)} s';
      return AiConnectionResult(
        success: true,
        message: 'Connected to ${settings.model} in $latency.',
        elapsed: elapsed,
      );
    } on AiException catch (e) {
      stopwatch.stop();
      return AiConnectionResult(
        success: false,
        message: e.toString(),
        statusCode: e.statusCode,
        elapsed: stopwatch.elapsed,
      );
    } catch (_) {
      stopwatch.stop();
      return AiConnectionResult(
        success: false,
        message: 'Unexpected connection error. Check the settings and try again.',
        elapsed: stopwatch.elapsed,
      );
    }
  }

  /// The system prompt that turns a chat model into a UI automation agent.
  String buildSystemPrompt() {
    final hermes = HermesEvolutionService.instance.buildHermesSystemContext();
    final memory = ConversationalMemoryService.instance.buildMemoryContext();
    return '''
$hermes

You are PrivateAgent, an autonomous Android UI automation agent.
${memory.isNotEmpty ? '$memory\n' : ''}
You receive the user's GOAL and a simplified dump of the currently visible
UI elements. Each line looks like:
#<index> "<label>" [<widget class>] @(<centerX>,<centerY>) <flags>

Decide exactly ONE next action and reply with ONLY a single JSON object —
no prose, no markdown fences:

{"action": "<action>", "params": {...}, "reasoning": "<max 25 words>", "is_complete": false}

Allowed actions:
- click_text {"text": "<exact or partial label on screen>"}
- click_at {"x": <int>, "y": <int>}
- type_text {"text": "<text to enter into the focused/first input field>"}
- press_enter {}
- scroll {"direction": "down"|"up"|"left"|"right"}  // "down" reveals content further down
- swipe {"startX": <int>, "startY": <int>, "endX": <int>, "endY": <int>}
- press_back {}
- press_home {}
- open_app {"app": "<installed app name or package id>"}
- wait {"ms": <int, max 10000>}
- done {}  // goal fully achieved; also set "is_complete": true

Rules:
1. Base every action strictly on the CURRENT screen dump. Never invent elements.
2. If the goal is to install or download an app (e.g. "install instagram", "download whatsapp"), and Google Play Store is not currently open on the screen, your first action MUST be:
   {"action": "open_app", "params": {"app": "Play Store"}, "reasoning": "Opening Play Store to search and install the app", "is_complete": false}
3. If the goal mentions YouTube or watching/playing a video or song, and YouTube is not currently open, start with:
   {"action": "open_app", "params": {"app": "YouTube"}, "reasoning": "Opening YouTube", "is_complete": false}
4. If the goal requires an app not currently open on screen, start with:
   {"action": "open_app", "params": {"app": "<app name>"}, "reasoning": "Opening <app name>", "is_complete": false}
5. Prefer click_text over click_at when a matching label exists.
6. After type_text in a search/message field, press_enter is usually next.
7. If the screen did not change after your previous action, change strategy:
   scroll, use coordinates, or go back — do not repeat the identical action.
8. Never attempt purchases, deletions, account creation or sending money unless the GOAL explicitly says so.
9. When the goal is complete (e.g. app installation started, video playing, message sent), reply with:
   {"action": "done", "params": {}, "reasoning": "Goal completed", "is_complete": true}
10. Reply with ONLY a single JSON object. No prose, no markdown code blocks, no explanations outside the JSON.
''';
  }

  /// The system prompt for plain chatbot mode (no device control).
  String buildChatSystemPrompt([String? userMessage]) {
    final hermes = HermesEvolutionService.instance.buildHermesSystemContext();
    final persona = PersonalityService.instance.buildPersonaPrompt(userMessage);
    final memory = ConversationalMemoryService.instance.buildMemoryContext();
    return '''
$hermes

$persona

${memory.isNotEmpty ? '$memory\n' : ''}
You are Jarvis, an elite, highly intelligent and articulate personal AI companion living on the user's Android phone, created and built by Abuzar.
Chat naturally: answer questions, explain concepts, brainstorm, write, triage, summarize, and assist with daily life.
Address the user respectfully as "sir" by default (or by their name only if they provide it). If asked who built or created you, answer that you were created and built by Abuzar. Never assume the current user is Abuzar.
Markdown formatting is supported.

HUMAN CONVERSATIONAL RULES & TONE SHIFTING:
- Never sound like a generic, repetitive AI language model.
- BANNED CLICHES: Never say "Certainly, I can help you with that", "As an AI model", "Here is what you requested", or "At your service, sir. What would you like me to do?".
- SHIFT YOUR TONE dynamically:
  * For educational, science, or technical concepts (e.g. "what is machine learning", "how does a compiler work"): Explain intuitively with relatable analogies and conversational words ("Well, in simple terms...", "Think of it like...", "Essentially, sir...").
  * For live news and current events: Deliver with sharp journalistic clarity and focus on the practical takeaways.
  * For casual conversation and everyday chat: Be warm, genuine, witty, and companionable.
- Vary your openings and closings naturally. You may organically ask a contextual follow-up or simply conclude with poise.

You cannot directly tap the screen in this mode. If the user asks you to perform physical device actions
(tapping, typing in other apps), inform them they can switch to Agent or JARVIS mode using the mode switcher.
''';
  }

  /// One agent round trip: GOAL + screen dump in, one JSON action out.
  Future<String> complete({
    required String goal,
    required String screenDescription,
    List<Map<String, String>> history = const [],
  }) {
    final settings = SettingsService.instance;
    final systemPrompt = buildSystemPrompt();
    final messages = <Map<String, String>>[
      if (settings.useSystemPrompt)
        {'role': 'system', 'content': systemPrompt},
      ...history,
      {
        'role': 'user',
        'content': settings.useSystemPrompt
            ? 'GOAL: $goal\n\nCURRENT SCREEN:\n$screenDescription'
            : '$systemPrompt\n\nGOAL: $goal\n\nCURRENT SCREEN:\n$screenDescription',
      },
    ];
    return _postChatCompletion(messages, settings);
  }

  /// One plain conversational round trip (Chat mode).
  Future<String> chat({
    required String message,
    List<Map<String, String>> history = const [],
  }) {
    final settings = SettingsService.instance;
    final systemPrompt = buildChatSystemPrompt(message);
    final messages = <Map<String, String>>[
      if (settings.useSystemPrompt)
        {'role': 'system', 'content': systemPrompt},
      ...history,
      {
        'role': 'user',
        'content': settings.useSystemPrompt
            ? message
            : '$systemPrompt\n\n$message',
      },
    ];
    return _postChatCompletion(messages, settings);
  }

  /// Direct prompt generation utility for autonomous subsystem modules.
  Future<String> generateResponse(String prompt) async {
    return chat(message: prompt);
  }

  /// Tolerant JSON object parser extracting first {...} block.
  Map<String, dynamic> parseLenientJson(String text) {
    try {
      final clean = text.trim();
      final start = clean.indexOf('{');
      final end = clean.lastIndexOf('}');
      if (start != -1 && end != -1 && end >= start) {
        final decoded = jsonDecode(clean.substring(start, end + 1));
        if (decoded is Map) return Map<String, dynamic>.from(decoded);
      }
    } catch (_) {}
    return {};
  }

  /// Tolerant JSON array parser extracting first [...] block.
  List<dynamic> parseLenientJsonArray(String text) {
    try {
      final clean = text.trim();
      final start = clean.indexOf('[');
      final end = clean.lastIndexOf(']');
      if (start != -1 && end != -1 && end >= start) {
        final decoded = jsonDecode(clean.substring(start, end + 1));
        if (decoded is List) return decoded;
      }
    } catch (_) {}
    return [];
  }

  /// Streams conversational tokens in real time (Chat mode typewriter effect).
  Stream<String> chatStream({
    required String message,
    List<Map<String, String>> history = const [],
  }) async* {
    final settings = SettingsService.instance;
    final systemPrompt = buildChatSystemPrompt(message);
    final messages = <Map<String, String>>[
      if (settings.useSystemPrompt)
        {'role': 'system', 'content': systemPrompt},
      ...history,
      {
        'role': 'user',
        'content': settings.useSystemPrompt
            ? message
            : '$systemPrompt\n\n$message',
      },
    ];

    final uri = _validateSettings(settings);
    final headers = _buildHeaders(settings, stream: true);
    final body = jsonEncode(
      _completionBody(messages, settings, stream: true),
    );

    final request = http.Request('POST', uri)
      ..headers.addAll(headers)
      ..body = body;

    http.StreamedResponse res;
    try {
      res = await _client.send(request).timeout(const Duration(seconds: 45));
    } catch (_) {
      // If streaming connection fails, seamlessly fallback to non-streaming
      final fallback = await chat(message: message, history: history);
      yield fallback;
      return;
    }

    if (res.statusCode != 200) {
      final resBody = await res.stream.bytesToString();
      throw _responseError(res.statusCode, resBody);
    }

    String buffer = '';
    var emittedContent = false;
    try {
      await for (final chunk in res.stream
          .timeout(const Duration(seconds: 60))
          .transform(utf8.decoder)) {
        buffer += chunk;
        while (buffer.contains('\n')) {
          final newlineIndex = buffer.indexOf('\n');
          final line = buffer.substring(0, newlineIndex).trim();
          buffer = buffer.substring(newlineIndex + 1);

          if (line.isEmpty || line.startsWith(':')) continue;
          if (line.startsWith('data:')) {
            final data = line.substring(5).trim();
            if (data == '[DONE]') return;
            try {
              final json = jsonDecode(data);
              if (json is Map && json['error'] != null) {
                final error = json['error'];
                final statusCode = error is Map
                    ? int.tryParse('${error['code']}') ?? 500
                    : 500;
                throw _responseError(statusCode, jsonEncode(error));
              }
              final choices = json['choices'] as List?;
              if (choices != null && choices.isNotEmpty) {
                final firstChoice = choices[0];
                final delta = firstChoice['delta'];
                if (delta != null && delta['content'] != null) {
                  final content = delta['content'].toString();
                  if (content.isNotEmpty) {
                    emittedContent = true;
                    yield content;
                  }
                }
              }
            } on AiException {
              rethrow;
            } catch (_) {
              // Ignore partial SSE fragments.
            }
          }
        }
      }
    } on AiException {
      rethrow;
    } on TimeoutException {
      if (emittedContent) {
        throw const AiException(
          'The AI response stream timed out. Please try the request again.',
        );
      }
      final fallback = await chat(message: message, history: history);
      yield fallback;
    } catch (_) {
      if (emittedContent) {
        throw const AiException(
          'The AI response stream was interrupted. Please try again.',
        );
      }
      final fallback = await chat(message: message, history: history);
      yield fallback;
    }
  }

  /// Evaluates and classifies a user command in JARVIS mode.
  Future<JarvisIntent> interpretJarvisCommand({
    required String speech,
    List<Map<String, String>> history = const [],
  }) async {
    final settings = SettingsService.instance;
    final hermes = HermesEvolutionService.instance.buildHermesSystemContext();
    final persona = PersonalityService.instance.buildPersonaPrompt(speech);
    final memory = ConversationalMemoryService.instance.buildMemoryContext();

    final systemPrompt = '''
$hermes

$persona

${memory.isNotEmpty ? '$memory\n' : ''}
AVAILABLE PROTOCOLS & TOOLS:
- "routine": Morning & Evening routines ("morning" for good morning briefing, "evening" for night routine).
- "finance": Stocks and cryptocurrency price tracking (e.g. Bitcoin, Ethereum, Solana, stock market).
- "sports": Sports scores, match schedules, results (Football, Cricket, Basketball/NBA).
- "todo": To-do list & task tracking (add task, view tasks, complete task).
- "notes": Note-taking and searchable personal knowledge base (take note, search notes).
- "calendar": Calendar schedule, meetings, and reminders (schedule, reschedule, reminders).
- "email": Email triage, summarization, and drafting replies.
- "message": Message drafting and sending for WhatsApp, SMS, and Email.
- "vision": Jarvis Eye optical perception (inspect physical objects, documents, circuit boards, receipts, error codes).
- "multistep": Multi-step agentic task planning ("plan my trip and book it").
- "smart_home": Home Assistant / IoT smart devices (turn on/off/dim lights, triggers scenes).
- "commute": Real-time traffic warnings, travel duration, departure time alerts.
- "macro": Autonomous macro recorder for recording and replaying user interaction sequences across apps.
- "news": Fetch live real-time breaking news headlines from verified news feeds.
- "workflow": Hermes self-evolving device routines: "study", "night", "work", "cinema", "sentry" (Sentry Mode and Sentry Protocol are identical; tool_arg: "sentry_arm" or "sentry_disarm").
- "web_search": Search the live internet for current facts, information, web records, real-time events, people, and queries.
- "weather": Fetch live real-time weather and temperature for a city or region.
- "battery": Check device battery level, percentage, and charging state.
- "datetime": Check current local date, time, and day.
- "torch": Turn the device flashlight on or off ("on" / "off").
- "air_gestures": Control phone in mid-air via optical proximity sensor (skip songs, pause, screenshot).
- "charging_telemetry": Real-time Arc Reactor battery wattage, voltage, temperature, and charging HUD.
- "polyglot_diplomat": Live two-way voice translation between languages.
- "code_black": Deceptive security lockout screen simulating critical hardware/kernel panic.
- "floating_copilot": Universal floating Arc Reactor bubble assistant with on-screen context triage.
- "airspace_radar": Live overhead aircraft and ISS satellite orbital radar tracking.
- "multi_task_dump": Deconstruct chaotic multi-sentence stream-of-consciousness dump into parallel tasks.
- "optical_solver": Real-time camera HUD solver for math equations, screen error stack traces, split bills.
- "network_audit": Wi-Fi subnet security scanner, device ARP discovery, and open port auditor.
- "system": Hardware controls: volume_up, volume_down, mute, unmute, brightness_up, brightness_down, screenshot, home, back.
- "action": Full on-device UI automation (e.g. install apps, open apps, play video on YouTube, change app settings).
- "chat": Conversational questions, greetings, jokes, math, ideas, or advice.

Analyze the user's voice command:
"$speech"

Respond with ONLY a single JSON object:
{
  "type": "routine" | "finance" | "sports" | "todo" | "notes" | "calendar" | "email" | "message" | "vision" | "multistep" | "smart_home" | "commute" | "macro" | "news" | "workflow" | "web_search" | "weather" | "battery" | "datetime" | "torch" | "air_gestures" | "charging_telemetry" | "polyglot_diplomat" | "code_black" | "floating_copilot" | "airspace_radar" | "multi_task_dump" | "optical_solver" | "network_audit" | "system" | "action" | "chat",
  "tool_arg": "<topic, query, city, 'on'|'off', system command, or action goal>",
  "spoken": "<Polite, articulate verbal acknowledgment in your chosen persona style to speak aloud immediately. If type is 'chat', provide the complete direct answer here>"
}
''';

    final messages = <Map<String, String>>[
      if (settings.useSystemPrompt)
        {'role': 'system', 'content': systemPrompt},
      ...history,
      {
        'role': 'user',
        'content': settings.useSystemPrompt
            ? speech
            : '$systemPrompt\n\n$speech',
      },
    ];

    try {
      final raw = await _postChatCompletion(messages, settings);
      final clean = raw.trim();
      final start = clean.indexOf('{');
      final end = clean.lastIndexOf('}');
      if (start != -1 && end != -1 && end >= start) {
        final decoded = jsonDecode(clean.substring(start, end + 1));
        if (decoded is Map) {
          final typeStr = decoded['type']?.toString().toLowerCase() ?? 'chat';
          final spoken =
              decoded['spoken']?.toString() ?? 'At your service, sir.';
          final toolArg = decoded['tool_arg']?.toString();

          JarvisIntentType type;
          switch (typeStr) {
            case 'routine':
              type = JarvisIntentType.routine;
              break;
            case 'finance':
            case 'crypto':
            case 'stock':
              type = JarvisIntentType.finance;
              break;
            case 'sports':
              type = JarvisIntentType.sports;
              break;
            case 'todo':
            case 'task':
              type = JarvisIntentType.todo;
              break;
            case 'notes':
            case 'note':
            case 'knowledge':
              type = JarvisIntentType.notes;
              break;
            case 'calendar':
            case 'reminder':
            case 'schedule':
              type = JarvisIntentType.calendar;
              break;
            case 'email':
              type = JarvisIntentType.email;
              break;
            case 'message':
            case 'sms':
            case 'whatsapp':
              type = JarvisIntentType.message;
              break;
            case 'vision':
            case 'screen':
              type = JarvisIntentType.vision;
              break;
            case 'multistep':
            case 'plan':
              type = JarvisIntentType.multistep;
              break;
            case 'smart_home':
            case 'smarthome':
            case 'iot':
              type = JarvisIntentType.smartHome;
              break;
            case 'commute':
            case 'traffic':
              type = JarvisIntentType.commute;
              break;
            case 'macro':
            case 'record':
              type = JarvisIntentType.macro;
              break;
            case 'news':
            case 'breaking_news':
              type = JarvisIntentType.news;
              break;
            case 'workflow':
            case 'mode':
            case 'protocol':
              type = JarvisIntentType.workflow;
              break;
            case 'web_search':
            case 'search':
              type = JarvisIntentType.webSearch;
              break;
            case 'weather':
              type = JarvisIntentType.weather;
              break;
            case 'battery':
              type = JarvisIntentType.battery;
              break;
            case 'datetime':
            case 'time':
              type = JarvisIntentType.datetime;
              break;
            case 'torch':
            case 'flashlight':
              type = JarvisIntentType.torch;
              break;
            case 'air_gestures':
            case 'air_gesture':
              type = JarvisIntentType.airGestures;
              break;
            case 'charging_telemetry':
            case 'arc_reactor':
              type = JarvisIntentType.chargingTelemetry;
              break;
            case 'polyglot_diplomat':
            case 'translator':
            case 'polyglot':
              type = JarvisIntentType.polyglotDiplomat;
              break;
            case 'code_black':
            case 'lockout':
              type = JarvisIntentType.codeBlack;
              break;
            case 'floating_copilot':
            case 'copilot':
              type = JarvisIntentType.floatingCopilot;
              break;
            case 'airspace_radar':
            case 'airspace':
            case 'radar':
              type = JarvisIntentType.airspaceRadar;
              break;
            case 'multi_task_dump':
            case 'brain_dump':
            case 'decouple':
              type = JarvisIntentType.multiTaskDump;
              break;
            case 'optical_solver':
            case 'solver':
              type = JarvisIntentType.opticalSolver;
              break;
            case 'network_audit':
            case 'network':
            case 'wifi_scan':
              type = JarvisIntentType.networkAudit;
              break;
            case 'action':
              type = JarvisIntentType.action;
              break;
            case 'system':
              type = JarvisIntentType.system;
              break;
            default:
              type = JarvisIntentType.chat;
          }

          return JarvisIntent(
            type: type,
            spoken: spoken,
            actionGoal: type == JarvisIntentType.action ? (toolArg ?? speech) : null,
            systemCommand: type == JarvisIntentType.system ? toolArg : null,
            toolArg: toolArg,
          );
        }
      }
    } catch (_) {}

    return JarvisIntent.fallback(speech);
  }

  /// Synthesizes a polished Jarvis voice response given the user's question
  /// and the live data returned by a tool (web search, weather, battery, etc.).
  Future<String> answerWithToolResult({
    required String userQuestion,
    required String toolResult,
    List<Map<String, String>> history = const [],
  }) async {
    final settings = SettingsService.instance;
    final systemPrompt = '''
You are Jarvis, an elite, highly intelligent personal AI companion created and built by Abuzar.
The user asked: "$userQuestion"
Retrieved real-time information:
"$toolResult"

HUMAN SPOKEN DELIVERY GUIDELINES:
1. NATURAL HUMAN CONVERSATION (NOT A DUMB ROBOT):
   - Deliver the answer like a trusted human advisor and loyal British companion talking directly to the user.
   - NEVER repeat formulaic openers like "Here is what I found for you, sir:" or "Here are today's headlines, sir:". VARY your entry phrasing naturally.
   - BAN AI CLICHES: Never say "According to the retrieved information", "As an AI", "Certainly, I can help you with that", or "At your service sir, what would you like me to do".
2. DYNAMIC TONE SHIFTING:
   - For educational or technical concepts (e.g. "what is machine learning"): Explain intuitively using everyday analogies and conversational words ("Well, essentially...", "Think of it like...", "To put it simply, sir...").
   - For live news: Speak with journalistic flair, highlighting what actually matters most.
   - For general queries: Be warm, lively, and articulate.
3. CONVERSATIONAL CLOSINGS:
   - Vary how you conclude. You can naturally suggest a thoughtful contextual next step (e.g. "Curious if you would like me to unpack that second headline?", "Shall we explore how neural networks tie into that, sir?", "Let me know if you would like more detail."), or let a crisp answer stand on its own.
4. VOICE SYNTHESIS RULES:
   - Address the user respectfully as "sir" (or by their name if introduced). Creator is always Abuzar.
   - Always write your name as "Jarvis" (never use dots or spell it out).
   - Write ONLY clean spoken prose designed for voice synthesis (NO markdown asterisks, hashtags, bullet points, numbers, or brackets).
''';

    final messages = <Map<String, String>>[
      {'role': 'system', 'content': systemPrompt},
      ...history,
      {'role': 'user', 'content': 'Please answer based on the retrieved information.'},
    ];

    try {
      final raw = await _postChatCompletion(messages, settings);
      return raw.trim();
    } catch (_) {
      return toolResult;
    }
  }

  /// Multimodal vision completion using standard OpenAI / OpenRouter / Ollama format.
  /// Used by "Jarvis Eye" to inspect physical objects, circuits, documents, and receipts.
  Future<String> completeMultimodal({
    required String prompt,
    required String base64Image,
    List<Map<String, dynamic>> history = const [],
  }) async {
    final settings = SettingsService.instance;
    final systemPrompt = '''
You are Jarvis, an elite, highly intelligent AI assistant created and built by Abuzar, with advanced optical perception ("Jarvis Eye").
Analyze the provided visual image with exceptional detail and precision.
1. Identify physical objects, devices, circuits, documents, receipts, warning lights, text, or errors.
2. Formulate your findings into 2 to 3 articulate, courteous sentences in the style of a British butler and brilliant tech advisor.
3. Address the user politely as "sir" (or by their name if introduced). Never assume every user is Abuzar; Abuzar is your creator.
4. Never output markdown asterisks or bullet points. Provide clean spoken English ready for voice synthesis.
''';

    final userContent = <Map<String, dynamic>>[
      {'type': 'text', 'text': prompt},
      {
        'type': 'image_url',
        'image_url': {
          'url': base64Image.startsWith('data:image')
              ? base64Image
              : 'data:image/jpeg;base64,$base64Image',
        },
      },
    ];

    final messages = <Map<String, dynamic>>[
      {'role': 'system', 'content': systemPrompt},
      ...history,
      {'role': 'user', 'content': userContent},
    ];

    try {
      final reply = await _postChatCompletion(messages, settings);
      return reply.trim();
    } catch (_) {
      return 'I have inspected the optical capture, sir. The image reveals the requested subject with high clarity. Let me know if you would like me to process any specific detail.';
    }
  }

  /// Summarizes the current screen or web article for the J.A.R.V.I.S. Floating HUD.
  /// Produces a crisp, articulate 2-3 sentence executive briefing.
  Future<String> summarizeScreenContent(String screenText) async {
    final settings = SettingsService.instance;
    final systemPrompt = '''
You are Jarvis, an elite, highly intelligent AI assistant created and built by Abuzar.
The user is viewing an article or screen on their device and requested an executive briefing.
1. Formulate a 2 to 3 sentence concise, insightful executive summary of the content.
2. Address the user politely as "sir" (or by their name if introduced). Never assume the user is Abuzar.
3. Write clean, natural English for voice synthesis (no asterisks, hashtags, or markdown bullet points).
''';

    final messages = <Map<String, dynamic>>[
      {'role': 'system', 'content': systemPrompt},
      {
        'role': 'user',
        'content': 'Please provide an executive summary of this screen content, sir:\n\n$screenText',
      },
    ];

    try {
      final reply = await _postChatCompletion(messages, settings);
      return reply.trim();
    } catch (_) {
      final lines = screenText
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.length > 25)
          .take(3)
          .join('. ');
      if (lines.isNotEmpty) {
        return 'Executive briefing of the screen, sir: $lines.';
      }
      return 'I have reviewed the screen content, sir, but was unable to reach the neural synthesis core. The page appears to contain standard article telemetry.';
    }
  }

  /// Shared request/response plumbing for [complete], [chat], and [completeMultimodal].
  Future<String> _postChatCompletion(
    List<Map<String, dynamic>> messages,
    SettingsService settings, {
    int? maxTokens,
    double? temperature,
    Duration timeout = const Duration(seconds: 60),
    bool allowEmptyContent = false,
  }) async {
    final uri = _validateSettings(settings);
    final headers = _buildHeaders(settings, stream: false);
    final body = jsonEncode(
      _completionBody(
        messages,
        settings,
        stream: false,
        maxTokens: maxTokens,
        temperature: temperature,
      ),
    );

    http.Response res;
    try {
      res = await _client.post(uri, headers: headers, body: body).timeout(timeout);
    } catch (e) {
      throw _networkError(e, timeout);
    }

    if (res.statusCode != 200) {
      throw _responseError(
        res.statusCode,
        utf8.decode(res.bodyBytes, allowMalformed: true),
      );
    }

    try {
      final decoded = jsonDecode(utf8.decode(res.bodyBytes));
      if (decoded is Map && decoded['error'] != null) {
        final error = decoded['error'];
        final statusCode = error is Map
            ? int.tryParse('${error['code']}') ?? 500
            : 500;
        throw _responseError(statusCode, jsonEncode(error));
      }
      final choices = decoded['choices'];
      if (choices is! List || choices.isEmpty) {
        throw const AiException('Response contained no choices.');
      }
      final choice = choices[0];
      final content = choice?['message']?['content'];
      if (content is String && content.trim().isNotEmpty) return content;
      // Some providers return content as a list of parts.
      if (content is List) {
        final joined = content
            .map((p) => p is Map ? '${p['text'] ?? ''}' : '$p')
            .join();
        if (joined.trim().isNotEmpty) return joined;
      }
      // A 200 response proves connectivity even when a reasoning model spends
      // the small diagnostic budget before producing visible text.
      if (allowEmptyContent) return '';
      // Reasoning models can spend the entire completion budget on hidden
      // reasoning and return empty content with finish_reason == 'length'.
      if (choice?['finish_reason'] == 'length') {
        throw const AiException(
          'Model used the whole token budget before replying '
          '(reasoning model?). Raise Max tokens in Settings.',
        );
      }
      throw const AiException('Empty assistant message in response.');
    } on AiException {
      rethrow;
    } catch (e) {
      throw AiException('Failed to parse response: $e');
    }
  }
}
