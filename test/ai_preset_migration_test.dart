import 'package:flutter_test/flutter_test.dart';
import 'package:private_agent/services/settings_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('cold start upgrades the retired Gemini preset model', () async {
    SharedPreferences.setMockInitialValues({
      'ai_provider': 'gemini',
      'ai_model': 'gemini-2.0-flash',
    });
    final settings = SettingsService.instance;

    await settings.init();

    expect(settings.model, 'gemini-3.8-flash');
  });
}
