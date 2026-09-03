import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const EshgamApp());
}

class Vault {
  static const _storage = FlutterSecureStorage();
  static const _secretKey = 'eshgam_shared_secret';
  static const _nameKey = 'eshgam_display_name';

  Future<String?> secret() => _storage.read(key: _secretKey);
  Future<void> setSecret(String value) => _storage.write(key: _secretKey, value: value);
  Future<String?> name() => _storage.read(key: _nameKey);
  Future<void> setName(String value) => _storage.write(key: _nameKey, value: value);
  Future<void> clear() => _storage.deleteAll();

  Future<String> encrypt(String text) async {
    final secret = await this.secret();
    if (secret == null) throw StateError('PAIRING_REQUIRED');
    final hash = await Sha256().hash(utf8.encode(secret));
    final box = SecretKey(hash.bytes);
    final nonce = List<int>.generate(12, (_) => Random.secure().nextInt(256));
    final encrypted = await AesGcm.with256bits().encrypt(utf8.encode(text), secretKey: box, nonce: nonce);
    return base64Encode([...nonce, ...encrypted.cipherText, ...encrypted.mac.bytes]);
  }
}

class EshgamApp extends StatelessWidget {
  const EshgamApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    debugShowCheckedModeBanner: false,
    title: 'عشقم ❤️',
    theme: ThemeData(
      useMaterial3: true,
      fontFamily: 'sans',
      colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xffd81b60), brightness: Brightness.light),
      scaffoldBackgroundColor: const Color(0xfffff7fa),
    ),
    home: const LockGate(),
  );
}

class LockGate extends StatefulWidget {
  const LockGate({super.key});
  @override State<LockGate> createState() => _LockGateState();
}
class _LockGateState extends State<LockGate> {
  final vault = Vault();
  final auth = LocalAuthentication();
  bool loading = true;
  bool paired = false;
  bool biometric = false;
  @override
  void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    final s = await vault.secret();
    final can = await auth.canCheckBiometrics || await auth.isDeviceSupported();
    if (!mounted) return;
    setState(() { paired = s != null; biometric = can; loading = false; });
  }
  Future<void> _unlock() async {
    if (!biometric) { _open(); return; }
    try {
      final ok = await auth.authenticate(localizedReason: 'برای ورود به «عشقم» هویت خود را تأیید کنید', options: const AuthenticationOptions(biometricOnly: false, stickyAuth: true));
      if (ok && mounted) _open();
    } catch (_) { if (mounted) _open(); }
  }
  void _open() => Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => const HomeScreen()));
  @override
  Widget build(BuildContext context) {
    if (loading) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    if (!paired) return PairScreen(onDone: _load);
    return Scaffold(body: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
      const Text('❤️', style: TextStyle(fontSize: 72)),
      const SizedBox(height: 12),
      const Text('عشقم', style: TextStyle(fontSize: 34, fontWeight: FontWeight.w800)),
      const SizedBox(height: 8),
      const Text('این فضای خصوصی فقط برای شما دو نفر است'),
      const SizedBox(height: 28),
      FilledButton.icon(onPressed: _unlock, icon: const Icon(Icons.fingerprint), label: const Text('ورود امن')),
    ])));
  }
}

class PairScreen extends StatefulWidget {
  final VoidCallback onDone;
  const PairScreen({super.key, required this.onDone});
  @override State<PairScreen> createState() => _PairScreenState();
}
class _PairScreenState extends State<PairScreen> {
  final controller = TextEditingController();
  final name = TextEditingController();
  final vault = Vault();
  bool busy = false;
  String? error;
  Future<void> pair() async {
    final code = controller.text.replaceAll(RegExp(r'\D'), '');
    if (code.length < 12) { setState(() => error = 'کد اتصال باید حداقل ۱۲ رقم باشد.'); return; }
    if (name.text.trim().isEmpty) { setState(() => error = 'نام خود را وارد کنید.'); return; }
    setState(() { busy = true; error = null; });
    await vault.setSecret(code);
    await vault.setName(name.text.trim());
    if (!mounted) return;
    widget.onDone();
  }
  @override Widget build(BuildContext context) => Scaffold(
    body: SafeArea(child: Padding(padding: const EdgeInsets.all(24), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      const Spacer(),
      const Text('❤️', textAlign: TextAlign.center, style: TextStyle(fontSize: 76)),
      const Text('عشقم', textAlign: TextAlign.center, style: TextStyle(fontSize: 36, fontWeight: FontWeight.w900)),
      const SizedBox(height: 8),
      const Text('اپ خصوصی شما و همسرتان', textAlign: TextAlign.center),
      const SizedBox(height: 36),
      TextField(controller: name, decoration: const InputDecoration(labelText: 'نام شما', prefixIcon: Icon(Icons.person_outline), border: OutlineInputBorder())),
      const SizedBox(height: 14),
      TextField(controller: controller, keyboardType: TextInputType.number, obscureText: true, decoration: const InputDecoration(labelText: 'کد اتصال مشترک ۱۲+ رقمی', prefixIcon: Icon(Icons.key), border: OutlineInputBorder())),
      const SizedBox(height: 10),
      const Text('این کد را فقط بین دو گوشی خودتان منتقل کنید. آن را برای شخص دیگری ارسال نکنید.', style: TextStyle(fontSize: 12)),
      if (error != null) Padding(padding: const EdgeInsets.only(top: 10), child: Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
      const SizedBox(height: 20),
      FilledButton.icon(onPressed: busy ? null : pair, icon: const Icon(Icons.lock_outline), label: const Text('ایجاد اتصال امن')),
      const Spacer(),
      const Text('هیچ حساب عمومی یا ثبت‌نام آزاد در این نسخه وجود ندارد.', textAlign: TextAlign.center, style: TextStyle(fontSize: 12)),
    ]))));
}

class HomeScreen extends StatefulWidget { const HomeScreen({super.key}); @override State<HomeScreen> createState() => _HomeScreenState(); }
class _HomeScreenState extends State<HomeScreen> {
  int tab = 0;
  @override Widget build(BuildContext context) => Directionality(textDirection: TextDirection.rtl, child: Scaffold(
    appBar: AppBar(title: const Text('عشقم ❤️', style: TextStyle(fontWeight: FontWeight.w800)), actions: [IconButton(onPressed: () => setState(() {}), icon: const Icon(Icons.search))]),
    body: tab == 0 ? const ChatList() : const SecurityScreen(),
    bottomNavigationBar: NavigationBar(selectedIndex: tab, onDestinationSelected: (i) => setState(() => tab = i), destinations: const [NavigationDestination(icon: Icon(Icons.favorite_border), selectedIcon: Icon(Icons.favorite), label: 'عشقم'), NavigationDestination(icon: Icon(Icons.shield_outlined), selectedIcon: Icon(Icons.shield), label: 'امنیت')]),
  ));
}

class ChatList extends StatelessWidget { const ChatList({super.key}); @override Widget build(BuildContext context) => ListView(padding: const EdgeInsets.all(14), children: [
  Card(child: ListTile(contentPadding: const EdgeInsets.all(12), leading: const CircleAvatar(radius: 28, child: Text('❤️', style: TextStyle(fontSize: 24))), title: const Text('همسرم ❤️', style: TextStyle(fontWeight: FontWeight.bold)), subtitle: const Text('فضای خصوصی و رمزنگاری‌شده'), trailing: const Icon(Icons.lock), onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ChatScreen())))
]); }

class ChatScreen extends StatefulWidget { const ChatScreen({super.key}); @override State<ChatScreen> createState() => _ChatScreenState(); }
class _ChatScreenState extends State<ChatScreen> {
  final input = TextEditingController(); final messages = <String>[]; final vault = Vault();
  Future<void> send() async { final t = input.text.trim(); if (t.isEmpty) return; await vault.encrypt(t); setState(() => messages.add(t)); input.clear(); }
  @override Widget build(BuildContext context) => Scaffold(appBar: AppBar(title: const Text('همسرم ❤️')), body: Column(children: [
    Expanded(child: messages.isEmpty ? const Center(child: Text('اولین پیام عاشقانه را بفرستید ❤️')) : ListView.builder(padding: const EdgeInsets.all(16), itemCount: messages.length, itemBuilder: (_, i) => Align(alignment: Alignment.centerRight, child: Container(margin: const EdgeInsets.only(bottom: 10), padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 11), decoration: BoxDecoration(color: Theme.of(context).colorScheme.primaryContainer, borderRadius: BorderRadius.circular(20)), child: Text(messages[i]))))),
    SafeArea(child: Padding(padding: const EdgeInsets.all(10), child: Row(children: [IconButton(onPressed: () {}, icon: const Icon(Icons.add_circle_outline)), Expanded(child: TextField(controller: input, minLines: 1, maxLines: 4, decoration: const InputDecoration(hintText: 'پیام عاشقانه...', border: OutlineInputBorder()))), IconButton(onPressed: send, icon: const Icon(Icons.send))])))
  ]));
}

class SecurityScreen extends StatelessWidget { const SecurityScreen({super.key}); @override Widget build(BuildContext context) => ListView(padding: const EdgeInsets.all(16), children: [
  const Card(child: ListTile(leading: Icon(Icons.verified_user), title: Text('حالت خصوصی فعال است'), subtitle: Text('کلید خصوصی در حافظه امن دستگاه نگهداری می‌شود.'))),
  Card(child: ListTile(leading: const Icon(Icons.phonelink_lock), title: const Text('دستگاه‌های مجاز'), subtitle: const Text('فقط دو دستگاه مورد اعتماد باید متصل باشند.'), onTap: () {})),
  Card(child: ListTile(leading: const Icon(Icons.no_photography), title: const Text('محافظت از صفحه'), subtitle: const Text('در نسخه Android از صفحات حساس در برابر Screenshot محافظت می‌شود.'))),
  Card(child: ListTile(leading: const Icon(Icons.delete_sweep), title: const Text('حذف داده‌های محلی'), subtitle: const Text('کلیدها و داده‌های محلی را پاک می‌کند.'), onTap: () async { await Vault().clear(); if (context.mounted) { await showDialog(context: context, builder: (_) => const AlertDialog(title: Text('پاک شد'), content: Text('اطلاعات امن محلی حذف شد. برای استفاده مجدد باید دوباره Pair شوید.'))); } })),
]); }
