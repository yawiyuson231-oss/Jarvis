import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_agent/services/ai_service.dart';
import 'package:private_agent/services/settings_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

http.Response completionResponse([String content = 'OK']) => http.Response(
      jsonEncode({
        'choices': [
          {
            'message': {'role': 'assistant', 'content': content},
            'finish_reason': 'stop',
          },
        ],
      }),
      200,
      headers: {'content-type': 'application/json'},
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('OpenAI-compatible endpoint normalization', () {
    test('appends chat completions to a base URL', () {
      expect(
        AiService.chatCompletionsUri(' https://api.openai.com/v1/ ').toString(),
        'https://api.openai.com/v1/chat/completions',
      );
    });

    test('does not duplicate a pasted full endpoint', () {
      expect(
        AiService.chatCompletionsUri(
          'https://openrouter.ai/api/v1/chat/completions/',
        ).toString(),
        'https://openrouter.ai/api/v1/chat/completions',
      );
    });

    test('defaults private scheme-less addresses to HTTP', () {
      expect(
        AiService.chatCompletionsUri('192.168.1.10:11434/v1').toString(),
        'http://192.168.1.10:11434/v1/chat/completions',
      );
      expect(
        AiService.chatCompletionsUri('localhost:11434/v1').toString(),
        'http://localhost:11434/v1/chat/completions',
      );
    });

    test('rejects unsupported URL schemes', () {
      expect(
        () => AiService.chatCompletionsUri('ftp://example.com/v1'),
        throwsA(isA<AiException>()),
      );
    });
  });

  group('AI connection diagnostics', () {
    late SettingsService settings;

    setUp(() async {
      SharedPreferences.setMockInitialValues({});
      settings = SettingsService.instance;
      await settings.init();
      await settings.setProvider('custom');
      await settings.setBaseUrl('https://ai.example.test/v1');
      await settings.setApiKey('test-secret');
      await settings.setModel('test-model');
    });

    test('makes a real completion and normalizes a pasted Bearer key', () async {
      late http.Request captured;
      final service = AiService.withClient(
        MockClient((request) async {
          captured = request;
          return completionResponse();
        }),
      );
      await settings.setApiKey('Bearer test-secret');

      final result = await service.testConnection();

      expect(result.success, isTrue);
      expect(result.message, contains('Connected to test-model'));
      expect(captured.url.toString(), 'https://ai.example.test/v1/chat/completions');
      expect(captured.headers['Authorization'], 'Bearer test-secret');
      expect(captured.headers['Accept'], 'application/json');
      final body = jsonDecode(captured.body) as Map<String, dynamic>;
      expect(body['model'], 'test-model');
      expect(body['stream'], isFalse);
      expect(body['max_tokens'], 128);
    });

    test('local Ollama requests do not send an empty Authorization header', () async {
      late http.Request captured;
      final service = AiService.withClient(
        MockClient((request) async {
          captured = request;
          return completionResponse();
        }),
      );
      await settings.setProvider('ollama');
      await settings.setBaseUrl('http://192.168.1.10:11434/v1');
      await settings.setApiKey('');

      final result = await service.testConnection();

      expect(result.success, isTrue);
      expect(captured.headers.containsKey('Authorization'), isFalse);
    });

    test('explains authentication errors with provider detail', () async {
      final service = AiService.withClient(
        MockClient((request) async => http.Response(
              jsonEncode({
                'error': {'message': 'Invalid API key'},
              }),
              401,
            )),
      );

      final result = await service.testConnection();

      expect(result.success, isFalse);
      expect(result.statusCode, 401);
      expect(result.message, contains('Authentication failed'));
      expect(result.message, contains('Invalid API key'));
    });

    test('explains rate limits and quota failures', () async {
      final service = AiService.withClient(
        MockClient((request) async => http.Response(
              jsonEncode({
                'error': {'message': 'Insufficient credits'},
              }),
              429,
            )),
      );

      final result = await service.testConnection();

      expect(result.success, isFalse);
      expect(result.statusCode, 429);
      expect(result.message, contains('Rate limit or usage quota'));
      expect(result.message, contains('Insufficient credits'));
    });

    test('turns DNS failures into actionable guidance', () async {
      final service = AiService.withClient(
        MockClient((request) async {
          throw http.ClientException('Failed host lookup');
        }),
      );

      final result = await service.testConnection();

      expect(result.success, isFalse);
      expect(result.message, contains('could not be resolved'));
      expect(result.message, contains('Base URL'));
    });

    test('explains that localhost on Android is not a PC', () async {
      final service = AiService.withClient(
        MockClient((request) async {
          throw http.ClientException('Connection refused');
        }),
      );
      await settings.setProvider('ollama');
      await settings.setApiKey('');

      final result = await service.testConnection();

      expect(result.success, isFalse);
      expect(result.message, contains('mean the phone itself'));
      expect(result.message, contains('Wi-Fi IP'));
    });

    test('a valid empty reasoning response still proves connectivity', () async {
      final service = AiService.withClient(
        MockClient((request) async => http.Response(
              jsonEncode({
                'choices': [
                  {
                    'message': {'role': 'assistant', 'content': ''},
                    'finish_reason': 'length',
                  },
                ],
              }),
              200,
            )),
      );

      final result = await service.testConnection();

      expect(result.success, isTrue);
    });
  });
}
