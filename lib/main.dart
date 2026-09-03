import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

const relayDefault = String.fromEnvironment(
  'ESHGHAM_RELAY_URL',
  defaultValue: '',
);

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const EshgamApp());
}

class Vault {
  static const storage = FlutterSecureStorage();
  static const secretKey = 'eshgam_shared_secret';
  static const deviceKey = 'eshgam_device_id';
  static const nameKey = 'eshgam_display_name';
  static const relayKey = 'eshgam_relay_url';

  Future<String?> secret() => storage.read(key: secretKey);
  Future<void> setSecret(String value) =>
      storage.write(key: secretKey, value: value);

  Future<String> deviceId() async {
    var value = await storage.read(key: deviceKey);
    if (value == null) {
      value = base64UrlEncode(
        List<int>.generate(18, (_) => Random.secure().nextInt(256)),
      );
      await storage.write(key: deviceKey, value: value);
    }
    return value;
  }

  Future<String?> name() => storage.read(key: nameKey);
  Future<void> setName(String value) =>
      storage.write(key: nameKey, value: value);
  Future<String?> relay() => storage.read(key: relayKey);
  Future<void> setRelay(String value) =>
      storage.write(key: relayKey, value: value);
  Future<void> clear() => storage.deleteAll();
}

class CryptoBox {
  final AesGcm aes = AesGcm.with256bits();

  Future<SecretKey> keyFrom(String secret) async {
    final digest = await Sha256().hash(utf8.encode(secret));
    return SecretKey(digest.bytes);
  }

  Future<String> hash(String secret) async {
    final digest = await Sha256().hash(utf8.encode(secret));
    return base64UrlEncode(digest.bytes);
  }

  Future<String> encrypt(String secret, String text) async {
    final nonce = List<int>.generate(
      12,
      (_) => Random.secure().nextInt(256),
    );
    final box = await aes.encrypt(
      utf8.encode(text),
      secretKey: await keyFrom(secret),
      nonce: nonce,
    );
    return jsonEncode({
      'n': base64Encode(nonce),
      'c': base64Encode(box.cipherText),
      'm': base64Encode(box.mac.bytes),
    });
  }

  Future<String> decrypt(String secret, String payload) async {
    final data = jsonDecode(payload) as Map<String, dynamic>;
    final box = SecretBox(
      base64Decode(data['c'] as String),
      nonce: base64Decode(data['n'] as String),
      mac: Mac(base64Decode(data['m'] as String)),
    );
    final clear = await aes.decrypt(
      box,
      secretKey: await keyFrom(secret),
    );
    return utf8.decode(clear);
  }

  Future<String> hmac(String secret, String data) async {
    final mac = await Hmac.sha256().calculateMac(
      utf8.encode(data),
      secretKey: await keyFrom(secret),
    );
    return base64UrlEncode(mac.bytes);
  }
}

class RelayClient {
  final String url;
  final String pairId;
  final String deviceId;
  final String secretHash;
  WebSocketChannel? channel;

  RelayClient({
    required this.url,
    required this.pairId,
    required this.deviceId,
    required this.secretHash,
  });

  Future<void> connect(
    void Function(Map<String, dynamic>) onMessage,
  ) async {
    final timestamp = DateTime.now().millisecondsSinceEpoch.toString();
    final signature = await CryptoBox().hmac(
      secretHash,
      'WS:$pairId:$deviceId:$timestamp',
    );
    final base = url.endsWith('/') ? url.substring(0, url.length - 1) : url;
    final uri = Uri.parse(
      '$base/ws?pairId=${Uri.encodeComponent(pairId)}'
      '&deviceId=${Uri.encodeComponent(deviceId)}'
      '&timestamp=$timestamp'
      '&secretHash=${Uri.encodeComponent(secretHash)}'
      '&signature=${Uri.encodeComponent(signature)}',
    );

    channel = WebSocketChannel.connect(uri);
    await channel!.ready;
    channel!.stream.listen((raw) {
      try {
        final value = jsonDecode(raw.toString());
        if (value is Map<String, dynamic>) {
          onMessage(value);
        }
      } catch (_) {}
    });
  }

  void send(Map<String, dynamic> value) {
    channel?.sink.add(jsonEncode(value));
  }

  Future<void> close() async {
    await channel?.sink.close();
  }
}

class EshgamApp extends StatelessWidget {
  const EshgamApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'عشقم ❤️',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xffd81b60),
        ),
        scaffoldBackgroundColor: const Color(0xfffff7fa),
      ),
      home: const LockGate(),
    );
  }
}

class LockGate extends StatefulWidget {
  const LockGate({super.key});

  @override
  State<LockGate> createState() => _LockGateState();
}

class _LockGateState extends State<LockGate> {
  final Vault vault = Vault();
  final LocalAuthentication auth = LocalAuthentication();
  bool loading = true;
  bool paired = false;
  bool deviceLock = false;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    final secret = await vault.secret();
    var supported = false;
    try {
      supported = await auth.isDeviceSupported();
    } catch (_) {}
    if (!mounted) return;
    setState(() {
      paired = secret != null;
      deviceLock = supported;
      loading = false;
    });
  }

  Future<void> unlock() async {
    if (deviceLock) {
      try {
        final ok = await auth.authenticate(
          localizedReason: 'برای ورود به «عشقم» هویت خود را تأیید کنید',
          options: const AuthenticationOptions(
            biometricOnly: false,
            stickyAuth: true,
          ),
        );
        if (!ok) return;
      } catch (_) {}
    }
    if (!mounted) return;
    Navigator.pushReplacement(
      context,
      MaterialPageRoute(builder: (_) => const HomeScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }
    if (!paired) return PairScreen(onDone: load);

    return Scaffold(
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('❤️', style: TextStyle(fontSize: 76)),
            const Text(
              'عشقم',
              style: TextStyle(fontSize: 36, fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: unlock,
              icon: const Icon(Icons.lock_open),
              label: const Text('ورود امن'),
            ),
          ],
        ),
      ),
    );
  }
}

class PairScreen extends StatefulWidget {
  final VoidCallback onDone;

  const PairScreen({super.key, required this.onDone});

  @override
  State<PairScreen> createState() => _PairScreenState();
}

class _PairScreenState extends State<PairScreen> {
  final code = TextEditingController();
  final name = TextEditingController();
  final relay = TextEditingController(text: relayDefault);
  bool busy = false;
  String? error;

  Future<void> pair() async {
    final secret = code.text.trim();
    final displayName = name.text.trim();
    if (secret.length < 16) {
      setState(() => error = 'رمز مشترک باید حداقل ۱۶ کاراکتر باشد.');
      return;
    }
    if (displayName.isEmpty) {
      setState(() => error = 'نام را وارد کنید.');
      return;
    }

    setState(() {
      busy = true;
      error = null;
    });
    await Vault().setSecret(secret);
    await Vault().setName(displayName);
    if (relay.text.trim().isNotEmpty) {
      await Vault().setRelay(relay.text.trim());
    }
    if (mounted) widget.onDone();
  }

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.rtl,
      child: Scaffold(
        body: SafeArea(
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              const SizedBox(height: 48),
              const Text(
                '❤️',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 80),
              ),
              const SizedBox(height: 8),
              const Text(
                'عشقم',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 38, fontWeight: FontWeight.w900),
              ),
              const SizedBox(height: 8),
              const Text(
                'پیام‌رسان خصوصی فقط برای دو دستگاه مورد اعتماد',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 30),
              TextField(
                controller: name,
                decoration: const InputDecoration(
                  labelText: 'نام شما',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.person),
                ),
              ),
              const SizedBox(height: 14),
              TextField(
                controller: code,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: 'رمز مشترک خصوصی',
                  helperText: 'این رمز را فقط شما و همسرتان داشته باشید.',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.key),
                ),
              ),
              const SizedBox(height: 14),
              TextField(
                controller: relay,
                decoration: const InputDecoration(
                  labelText: 'Relay امن',
                  hintText: 'wss://your-domain',
                  helperText: 'برای پیام‌رسانی اینترنتی لازم است.',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.cloud_done),
                ),
              ),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.all(8),
                  child: Text(
                    error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: busy ? null : pair,
                icon: const Icon(Icons.verified_user),
                label: const Text('فعال‌سازی امن'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int tab = 0;

  @override
  Widget build(BuildContext context) {
    return Directionality(
      textDirection: TextDirection.rtl,
      child: Scaffold(
        appBar: AppBar(
          title: const Text(
            'عشقم ❤️',
            style: TextStyle(fontWeight: FontWeight.w800),
          ),
          actions: [
            IconButton(
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const SettingsScreen(),
                  ),
                );
              },
              icon: const Icon(Icons.settings),
            ),
          ],
        ),
        body: tab == 0 ? const ChatList() : const SecurityScreen(),
        bottomNavigationBar: NavigationBar(
          selectedIndex: tab,
          onDestinationSelected: (value) => setState(() => tab = value),
          destinations: const [
            NavigationDestination(
              icon: Icon(Icons.favorite_border),
              selectedIcon: Icon(Icons.favorite),
              label: 'عشقم',
            ),
            NavigationDestination(
              icon: Icon(Icons.shield_outlined),
              selectedIcon: Icon(Icons.shield),
              label: 'امنیت',
            ),
          ],
        ),
      ),
    );
  }
}

class ChatList extends StatelessWidget {
  const ChatList({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(14),
      children: [
        Card(
          child: ListTile(
            contentPadding: const EdgeInsets.all(12),
            leading: const CircleAvatar(
              radius: 28,
              child: Text('❤️', style: TextStyle(fontSize: 24)),
            ),
            title: const Text(
              'همسرم ❤️',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            subtitle: const Text('پیام‌های رمزنگاری‌شده و خصوصی'),
            trailing: const Icon(Icons.lock),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const ChatScreen()),
              );
            },
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            leading: const Icon(Icons.call),
            title: const Text('تماس صوتی'),
            subtitle: const Text('WebRTC - زیرساخت تماس در حال تکمیل'),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const CallScreen(video: false),
                ),
              );
            },
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.videocam),
            title: const Text('تماس تصویری'),
            subtitle: const Text('WebRTC - زیرساخت تماس در حال تکمیل'),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => const CallScreen(video: true),
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}

class Message {
  final String text;
  final bool mine;
  final DateTime time;

  Message(this.text, this.mine, this.time);

  Map<String, dynamic> toJson() => {
        't': text,
        'm': mine,
        'd': time.toIso8601String(),
      };

  static Message fromJson(Map<String, dynamic> value) {
    return Message(
      value['t'] as String,
      value['m'] as bool,
      DateTime.parse(value['d'] as String),
    );
  }
}

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final input = TextEditingController();
  final vault = Vault();
  final crypto = CryptoBox();
  final messages = <Message>[];
  RelayClient? relay;
  bool connected = false;
  bool busy = true;

  @override
  void initState() {
    super.initState();
    start();
  }

  Future<void> start() async {
    final secret = await vault.secret();
    final relayUrl = await vault.relay();
    if (secret == null) {
      if (mounted) setState(() => busy = false);
      return;
    }

    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString('eshgam_messages');
    if (saved != null) {
      try {
        final clear = await crypto.decrypt(secret, saved);
        final list = jsonDecode(clear) as List<dynamic>;
        messages.addAll(
          list.map(
            (item) => Message.fromJson(item as Map<String, dynamic>),
          ),
        );
      } catch (_) {}
    }

    if (relayUrl != null && relayUrl.startsWith('wss://')) {
      final secretHash = await crypto.hash(secret);
      final pairId = secretHash.substring(0, min(32, secretHash.length));
      relay = RelayClient(
        url: relayUrl,
        pairId: pairId,
        deviceId: await vault.deviceId(),
        secretHash: secretHash,
      );
      try {
        await relay!.connect(onRemote);
        connected = true;
      } catch (_) {
        connected = false;
      }
    }

    if (mounted) setState(() => busy = false);
  }

  Future<void> persist(String secret) async {
    final prefs = await SharedPreferences.getInstance();
    final clear = jsonEncode(messages.map((m) => m.toJson()).toList());
    await prefs.setString(
      'eshgam_messages',
      await crypto.encrypt(secret, clear),
    );
  }

  Future<void> send() async {
    final text = input.text.trim();
    final secret = await vault.secret();
    if (text.isEmpty || secret == null) return;

    final message = Message(text, true, DateTime.now());
    setState(() => messages.add(message));
    await persist(secret);
    input.clear();

    if (relay != null && connected) {
      final ciphertext = await crypto.encrypt(
        secret,
        jsonEncode({
          'text': text,
          'time': message.time.toIso8601String(),
        }),
      );
      relay!.send({
        'type': 'message',
        'ciphertext': ciphertext,
      });
    }
  }

  Future<void> onRemote(Map<String, dynamic> value) async {
    if (value['type'] != 'message') return;
    final secret = await vault.secret();
    if (secret == null) return;

    try {
      final clear = await crypto.decrypt(
        secret,
        value['ciphertext'] as String,
      );
      final data = jsonDecode(clear) as Map<String, dynamic>;
      final message = Message(
        data['text'] as String,
        false,
        DateTime.parse(data['time'] as String),
      );
      if (mounted) setState(() => messages.add(message));
      await persist(secret);
    } catch (_) {}
  }

  @override
  void dispose() {
    relay?.close();
    input.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('همسرم ❤️'),
        actions: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Icon(
              connected ? Icons.cloud_done : Icons.cloud_off,
              color: connected ? Colors.green : Colors.grey,
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: messages.isEmpty
                ? const Center(
                    child: Text('اولین پیام عاشقانه را بفرستید ❤️'),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: messages.length,
                    itemBuilder: (_, index) {
                      final message = messages[index];
                      return Align(
                        alignment: message.mine
                            ? Alignment.centerRight
                            : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.only(bottom: 10),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 16,
                            vertical: 11,
                          ),
                          decoration: BoxDecoration(
                            color: message.mine
                                ? Theme.of(context)
                                    .colorScheme
                                    .primaryContainer
                                : Theme.of(context)
                                    .colorScheme
                                    .surfaceContainerHighest,
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text(message.text),
                        ),
                      );
                    },
                  ),
          ),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Row(
                children: [
                  IconButton(
                    onPressed: () {
                      showModalBottomSheet<void>(
                        context: context,
                        builder: (_) => const SizedBox(
                          height: 180,
                          child: Center(
                            child: Text(
                              'اشتراک عکس، فایل و استیکر در مرحله بعدی اضافه می‌شود ❤️',
                            ),
                          ),
                        ),
                      );
                    },
                    icon: const Icon(Icons.add_circle_outline),
                  ),
                  Expanded(
                    child: TextField(
                      controller: input,
                      minLines: 1,
                      maxLines: 4,
                      decoration: const InputDecoration(
                        hintText: 'پیام عاشقانه...',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: busy ? null : send,
                    icon: const Icon(Icons.send),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final name = TextEditingController();
  final relay = TextEditingController();

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    name.text = await Vault().name() ?? '';
    relay.text = await Vault().relay() ?? relayDefault;
    if (mounted) setState(() {});
  }

  Future<void> save() async {
    await Vault().setName(name.text.trim());
    await Vault().setRelay(relay.text.trim());
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('تنظیمات ذخیره شد')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('تنظیمات خصوصی')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          TextField(
            controller: name,
            decoration: const InputDecoration(
              labelText: 'نام',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 14),
          TextField(
            controller: relay,
            decoration: const InputDecoration(
              labelText: 'Relay URL',
              hintText: 'wss://your-domain',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: save,
            icon: const Icon(Icons.save),
            label: const Text('ذخیره'),
          ),
        ],
      ),
    );
  }
}

class SecurityScreen extends StatelessWidget {
  const SecurityScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const Card(
          child: ListTile(
            leading: Icon(Icons.verified_user),
            title: Text('رمزنگاری محتوای پیام'),
            subtitle: Text(
              'متن پیام قبل از ارسال با AES-GCM رمز می‌شود.',
            ),
          ),
        ),
        const Card(
          child: ListTile(
            leading: Icon(Icons.phonelink_lock),
            title: Text('دو دستگاه مورد اعتماد'),
            subtitle: Text('Relay برای هر Pair حداکثر دو دستگاه دارد.'),
          ),
        ),
        const Card(
          child: ListTile(
            leading: Icon(Icons.lock),
            title: Text('قفل دستگاه'),
            subtitle: Text('ورود می‌تواند با قفل یا بیومتریک سیستم‌عامل باشد.'),
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.delete_forever),
            title: const Text('پاک‌سازی کامل'),
            subtitle: const Text('کلیدها و تاریخچه محلی حذف می‌شوند.'),
            onTap: () async {
              await Vault().clear();
              if (!context.mounted) return;
              await showDialog<void>(
                context: context,
                builder: (_) => const AlertDialog(
                  title: Text('پاک شد'),
                  content: Text('برای استفاده مجدد باید دوباره Pair شوید.'),
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}

class CallScreen extends StatelessWidget {
  final bool video;

  const CallScreen({super.key, required this.video});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: Text(video ? 'تماس تصویری ❤️' : 'تماس صوتی ❤️'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text('❤️', style: TextStyle(fontSize: 90)),
            const Text(
              'تماس خصوصی',
              style: TextStyle(color: Colors.white, fontSize: 22),
            ),
            const SizedBox(height: 28),
            FilledButton.icon(
              onPressed: null,
              icon: const Icon(Icons.call),
              label: const Text('تماس اینترنتی'),
            ),
            const Padding(
              padding: EdgeInsets.all(24),
              child: Text(
                'برای تماس واقعی باید signaling روی همین Relay و STUN/TURN اختصاصی مستقر شود. این بخش هنوز فعال نشده است.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white70),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
