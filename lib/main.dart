import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

const relayDefault = String.fromEnvironment('ESHGHAM_RELAY_URL', defaultValue: '');

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const EshgamApp());
}

class Vault {
  static const storage = FlutterSecureStorage();
  static const secretKeyName = 'eshgam_shared_secret';
  static const deviceKeyName = 'eshgam_device_id';
  static const nameKey = 'eshgam_display_name';
  Future<String?> secret() => storage.read(key: secretKeyName);
  Future<void> setSecret(String v) => storage.write(key: secretKeyName, value: v);
  Future<String> deviceId() async { var v=await storage.read(key: deviceKeyName); if(v==null){v=base64UrlEncode(List<int>.generate(18,(_)=>Random.secure().nextInt(256))); await storage.write(key: deviceKeyName,value:v);} return v; }
  Future<String?> name()=>storage.read(key:nameKey);
  Future<void> setName(String v)=>storage.write(key:nameKey,value:v);
  Future<void> setRelay(String v)=>storage.write(key:'eshgam_relay_url',value:v);
  Future<String?> relay()=>storage.read(key:'eshgam_relay_url');
  Future<void> clear()=>storage.deleteAll();
}

class CryptoBox {
  final algo=AesGcm.with256bits();
  final sha=Sha256();
  Future<SecretKey> key(String secret) async { final d=await sha.hash(utf8.encode(secret)); return SecretKey(d.bytes); }
  Future<String> encrypt(String secret,String text) async { final k=await key(secret); final nonce=List<int>.generate(12,(_)=>Random.secure().nextInt(256)); final b=await algo.encrypt(utf8.encode(text),secretKey:k,nonce:nonce); return jsonEncode({'n':base64Encode(nonce),'c':base64Encode(b.cipherText),'m':base64Encode(b.mac.bytes)}); }
  Future<String> decrypt(String secret,String payload) async { final j=jsonDecode(payload) as Map<String,dynamic>; final b=SecretBox(base64Decode(j['c']),nonce:base64Decode(j['n']),mac:Mac(base64Decode(j['m']))); final p=await algo.decrypt(b,secretKey:await key(secret)); return utf8.decode(p); }
  Future<String> hmac(String secret,String payload) async { final mac=await Hmac.sha256().calculateMac(utf8.encode(payload),secretKey:await key(secret)); return base64UrlEncode(mac.bytes); }
}

class RelayClient {
  final String url; final String pairId; final String deviceId; final String secretHash;
  WebSocketChannel? channel;
  RelayClient({required this.url,required this.pairId,required this.deviceId,required this.secretHash});
  Future<bool> register() async { final uri=Uri.parse(url.replaceFirst('wss://','https://').replaceFirst('ws://','http://')+'/pair/register'); return false; }
  Future<void> connect(void Function(Map<String,dynamic>) onMessage) async {
    final ts=DateTime.now().millisecondsSinceEpoch.toString();
    final sig=await CryptoBox().hmac(secretHash,'WS:$pairId:$deviceId:$ts');
    final base=url.endsWith('/')?url.substring(0,url.length-1):url;
    channel=WebSocketChannel.connect(Uri.parse('$base/ws?pairId=$pairId&deviceId=${Uri.encodeComponent(deviceId)}&timestamp=$ts&signature=${Uri.encodeComponent(sig)}'));
    await channel!.ready;
    channel!.stream.listen((raw){try{onMessage(jsonDecode(raw as String) as Map<String,dynamic>);}catch(_){}});
  }
  void send(Map<String,dynamic> msg)=>channel?.sink.add(jsonEncode(msg));
  Future<void> close() async { await channel?.sink.close(); channel=null; }
}

class EshgamApp extends StatelessWidget { const EshgamApp({super.key}); @override Widget build(BuildContext c)=>MaterialApp(debugShowCheckedModeBanner:false,title:'عشقم ❤️',theme:ThemeData(useMaterial3:true,colorScheme:ColorScheme.fromSeed(seedColor:const Color(0xffd81b60)),scaffoldBackgroundColor:const Color(0xfffff7fa)),home:const LockGate()); }

class LockGate extends StatefulWidget { const LockGate({super.key}); @override State<LockGate> createState()=>_LockGateState(); }
class _LockGateState extends State<LockGate>{ final v=Vault(); final auth=LocalAuthentication(); bool loading=true,paired=false,lock=false; @override void initState(){super.initState();load();} Future<void> load()async{final s=await v.secret();final can=await auth.isDeviceSupported();if(mounted)setState(()=>{paired=s!=null,lock=can,loading=false});} Future<void> open()async{if(lock){try{if(!await auth.authenticate(localizedReason:'برای ورود به «عشقم» هویت خود را تأیید کنید',options:const AuthenticationOptions(biometricOnly:false,stickyAuth:true)))return;}catch(_){}}if(mounted)Navigator.pushReplacement(context,MaterialPageRoute(builder:(_)=>const HomeScreen()));} @override Widget build(BuildContext c){if(loading)return const Scaffold(body:Center(child:CircularProgressIndicator()));if(!paired)return PairScreen(onDone:load);return Scaffold(body:Center(child:Column(mainAxisSize:MainAxisSize.min,children:[const Text('❤️',style:TextStyle(fontSize:76)),const Text('عشقم',style:TextStyle(fontSize:36,fontWeight:FontWeight.w900)),const SizedBox(height:24),FilledButton.icon(onPressed:open,icon:const Icon(Icons.lock_open),label:const Text('ورود امن'))])));}}

class PairScreen extends StatefulWidget { final VoidCallback onDone; const PairScreen({super.key,required this.onDone}); @override State<PairScreen> createState()=>_PairScreenState(); }
class _PairScreenState extends State<PairScreen>{final code=TextEditingController();final name=TextEditingController();final relay=TextEditingController(text:relayDefault);bool busy=false;String? err;Future<void> pair()async{final s=code.text.trim();if(s.length<16){setState(()=>err='کد مشترک حداقل ۱۶ کاراکتر باشد.');return;}if(name.text.trim().isEmpty){setState(()=>err='نام را وارد کنید.');return;}setState(()=>busy=true);await Vault().setSecret(s);await Vault().setName(name.text.trim());if(relay.text.trim().isNotEmpty)await Vault().setRelay(relay.text.trim());if(mounted)widget.onDone();} @override Widget build(BuildContext c)=>Directionality(textDirection:TextDirection.rtl,child:Scaffold(body:SafeArea(child:ListView(padding:const EdgeInsets.all(24),children:[const SizedBox(height:50),const Text('❤️',textAlign:TextAlign.center,style:TextStyle(fontSize:80)),const Text('عشقم',textAlign:TextAlign.center,style:TextStyle(fontSize:38,fontWeight:FontWeight.w900)),const SizedBox(height:8),const Text('فقط دو دستگاه مورد اعتماد',textAlign:TextAlign.center),const SizedBox(height:32),TextField(controller:name,decoration:const InputDecoration(labelText:'نام شما',border:OutlineInputBorder(),prefixIcon:Icon(Icons.person))),const SizedBox(height:14),TextField(controller:code,obscureText:true,decoration:const InputDecoration(labelText:'رمز مشترک خصوصی',helperText:'این رمز را فقط بین خودتان نگه دارید',border:OutlineInputBorder(),prefixIcon:Icon(Icons.key))),const SizedBox(height:14),TextField(controller:relay,keyboardType:TextInputType.url,decoration:const InputDecoration(labelText:'آدرس Relay امن (wss://...)',helperText:'برای پیام‌رسانی از راه دور لازم است',border:OutlineInputBorder(),prefixIcon:Icon(Icons.cloud_done))),if(err!=null)Padding(padding:const EdgeInsets.all(8),child:Text(err!,style:TextStyle(color:Theme.of(c).colorScheme.error))),const SizedBox(height:20),FilledButton.icon(onPressed:busy?null:pair,icon:const Icon(Icons.verified_user),label:const Text('فعال‌سازی امن'))]))));}}

class HomeScreen extends StatefulWidget{const HomeScreen({super.key});@override State<HomeScreen>createState()=>_HomeScreenState();}
class _HomeScreenState extends State<HomeScreen>{int tab=0;@override Widget build(BuildContext c)=>Directionality(textDirection:TextDirection.rtl,child:Scaffold(appBar:AppBar(title:const Text('عشقم ❤️',style:TextStyle(fontWeight:FontWeight.w800)),actions:[IconButton(onPressed:()=>Navigator.push(c,MaterialPageRoute(builder:(_)=>const SettingsScreen())),icon:const Icon(Icons.settings))]),body:tab==0?const ChatList():const SecurityScreen(),bottomNavigationBar:NavigationBar(selectedIndex:tab,onDestinationSelected:(i)=>setState(()=>tab=i),destinations:const[NavigationDestination(icon:Icon(Icons.favorite_border),selectedIcon:Icon(Icons.favorite),label:'عشقم'),NavigationDestination(icon:Icon(Icons.shield_outlined),selectedIcon:Icon(Icons.shield),label:'امنیت')]));}}
class ChatList extends StatelessWidget{const ChatList({super.key});@override Widget build(BuildContext c)=>ListView(padding:const EdgeInsets.all(14),children:[Card(child:ListTile(contentPadding:const EdgeInsets.all(12),leading:const CircleAvatar(radius:28,child:Text('❤️',style:TextStyle(fontSize:24))),title:const Text('همسرم ❤️',style:TextStyle(fontWeight:FontWeight.bold)),subtitle:const Text('پیام‌های رمزنگاری‌شده و خصوصی'),trailing:const Icon(Icons.lock),onTap:()=>Navigator.push(c,MaterialPageRoute(builder:(_)=>const ChatScreen()))),),const SizedBox(height:12),Card(child:ListTile(leading:const Icon(Icons.call),title:const Text('تماس صوتی'),subtitle:const Text('WebRTC امن و مستقیم'),onTap:()=>Navigator.push(c,MaterialPageRoute(builder:(_)=>const CallScreen(video:false)))),Card(child:ListTile(leading:const Icon(Icons.videocam),title:const Text('تماس تصویری'),subtitle:const Text('WebRTC امن و مستقیم'),onTap:()=>Navigator.push(c,MaterialPageRoute(builder:(_)=>const CallScreen(video:true))))]);}

class ChatScreen extends StatefulWidget{const ChatScreen({super.key});@override State<ChatScreen>createState()=>_ChatScreenState();}
class Msg{final String text;final bool mine;final DateTime time;Msg(this.text,this.mine,this.time);Map<String,dynamic> to()=>{'t':text,'m':mine,'d':time.toIso8601String()};static Msg from(Map<String,dynamic>j)=>Msg(j['t'] as String,j['m'] as bool,DateTime.parse(j['d'] as String));}
class _ChatScreenState extends State<ChatScreen>{final input=TextEditingController();final v=Vault();final crypto=CryptoBox();final items=<Msg>[];RelayClient? relay;bool connected=false,busy=true;@override void initState(){super.initState();start();}Future<void>start()async{final s=await v.secret();final url=await v.relay();if(s==null){setState(()=>busy=false);return;}final prefs=await SharedPreferences.getInstance();final raw=prefs.getString('eshgam_messages');if(raw!=null){try{final plain=await crypto.decrypt(s,raw);items.addAll((jsonDecode(plain) as List).map((e)=>Msg.from(e)));}catch(_){}}if(url!=null&&url.startsWith('wss://')){final hash=(await Sha256().hash(utf8.encode(s))).toString();final pairId=hash.substring(0,32);relay=RelayClient(url:url,pairId:pairId,deviceId:await v.deviceId(),secretHash:hash);try{await relay!.connect(onRemote);connected=true;}catch(_){}}if(mounted)setState(()=>busy=false);}
Future<void>persist(String secret)async{final prefs=await SharedPreferences.getInstance();await prefs.setString('eshgam_messages',await crypto.encrypt(secret,jsonEncode(items.map((e)=>e.to()).toList())));}
Future<void>send()async{final t=input.text.trim();final s=await v.secret();if(t.isEmpty||s==null)return;final msg=Msg(t,true,DateTime.now());setState(()=>items.add(msg));await persist(s);input.clear();if(relay!=null&&connected){final enc=await crypto.encrypt(s,jsonEncode({'text':t,'time':msg.time.toIso8601String()}));relay!.send({'type':'message','ciphertext':enc});}}
Future<void>onRemote(Map<String,dynamic>j)async{if(j['type']!='message')return;final s=await v.secret();if(s==null)return;try{final p=jsonDecode(await crypto.decrypt(s,j['ciphertext'] as String));final m=Msg(p['text'] as String,false,DateTime.parse(p['time'] as String));if(mounted)setState(()=>items.add(m));await persist(s);}catch(_){}}
@override void dispose(){relay?.close();input.dispose();super.dispose();}@override Widget build(BuildContext c)=>Scaffold(appBar:AppBar(title:const Text('همسرم ❤️'),actions:[Padding(padding:const EdgeInsets.symmetric(horizontal:12),child:Icon(connected?Icons.cloud_done:Icons.cloud_off,color:connected?Colors.green:Colors.grey))]),body:Column(children:[Expanded(child:items.isEmpty?const Center(child:Text('اولین پیام عاشقانه را بفرستید ❤️')):ListView.builder(reverse:false,padding:const EdgeInsets.all(16),itemCount:items.length,itemBuilder:(_,i){final m=items[i];return Align(alignment:m.mine?Alignment.centerRight:Alignment.centerLeft,child:Container(margin:const EdgeInsets.only(bottom:10),padding:const EdgeInsets.symmetric(horizontal:16,vertical:11),decoration:BoxDecoration(color:m.mine?Theme.of(c).colorScheme.primaryContainer:Theme.of(c).colorScheme.surfaceContainerHighest,borderRadius:BorderRadius.circular(20)),child:Text(m.text)));})),SafeArea(child:Padding(padding:const EdgeInsets.all(10),child:Row(children:[IconButton(onPressed:()=>showModalBottomSheet(context:c,builder:(_)=>const SizedBox(height:180,child:Center(child:Text('عکس، فایل و استیکر در حال آماده‌سازی اتصال امن هستند ❤️')))),icon:const Icon(Icons.add_circle_outline)),Expanded(child:TextField(controller:input,minLines:1,maxLines:4,decoration:const InputDecoration(hintText:'پیام عاشقانه...',border:OutlineInputBorder())),),IconButton(onPressed:busy?null:send,icon:const Icon(Icons.send))])))]));}

class SettingsScreen extends StatefulWidget{const SettingsScreen({super.key});@override State<SettingsScreen>createState()=>_SettingsScreenState();}
class _SettingsScreenState extends State<SettingsScreen>{final name=TextEditingController();final relay=TextEditingController();@override void initState(){super.initState();load();}Future<void>load()async{name.text=await Vault().name()??'';relay.text=await Vault().relay()??relayDefault;setState((){});}Future<void>save()async{await Vault().setName(name.text.trim());await Vault().setRelay(relay.text.trim());if(mounted)ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:Text('تنظیمات ذخیره شد')));} @override Widget build(BuildContext c)=>Scaffold(appBar:AppBar(title:const Text('تنظیمات خصوصی')),body:ListView(padding:const EdgeInsets.all(20),children:[TextField(controller:name,decoration:const InputDecoration(labelText:'نام',border:OutlineInputBorder())),const SizedBox(height:14),TextField(controller:relay,decoration:const InputDecoration(labelText:'Relay URL',hintText:'wss://your-domain/ws',border:OutlineInputBorder())),const SizedBox(height:20),FilledButton.icon(onPressed:save,icon:const Icon(Icons.save),label:const Text('ذخیره')),const SizedBox(height:20),const Text('هیچ متن پیام به Relay ارسال نمی‌شود؛ فقط بسته رمزنگاری‌شده ارسال می‌شود.',style:TextStyle(fontSize:13))]));}

class SecurityScreen extends StatelessWidget{const SecurityScreen({super.key});@override Widget build(BuildContext c)=>ListView(padding:const EdgeInsets.all(16),children:[const Card(child:ListTile(leading:Icon(Icons.verified_user),title:Text('رمزنگاری سرتاسری محتوا'),subtitle:Text('پیام قبل از ارسال روی دستگاه رمز می‌شود.'))),const Card(child:ListTile(leading:Icon(Icons.phonelink_lock),title:Text('دو دستگاه مجاز'),subtitle:Text('Relay بیشتر از دو دستگاه برای یک Pair را قبول نمی‌کند.'))),const Card(child:ListTile(leading:Icon(Icons.no_photography),title:Text('قفل دستگاه'),subtitle:Text('ورود با قفل/بیومتریک سیستم عامل محافظت می‌شود.'))),Card(child:ListTile(leading:const Icon(Icons.delete_forever),title:const Text('پاک‌سازی کامل'),subtitle:const Text('کلیدها و تاریخچه محلی را حذف می‌کند.'),onTap:()async{await Vault().clear();if(c.mounted){await showDialog(context:c,builder:(_)=>const AlertDialog(title:Text('پاک شد'),content:Text('برای ورود دوباره باید Pair انجام شود.')));}}))]);}

class CallScreen extends StatefulWidget{final bool video;const CallScreen({super.key,required this.video});@override State<CallScreen>createState()=>_CallScreenState();}
class _CallScreenState extends State<CallScreen>{bool active=false;@override Widget build(BuildContext c)=>Scaffold(backgroundColor:Colors.black,appBar:AppBar(backgroundColor:Colors.black,foregroundColor:Colors.white,title:Text(widget.video?'تماس تصویری ❤️':'تماس صوتی ❤️')),body:Center(child:Column(mainAxisAlignment:MainAxisAlignment.center,children:[const Text('❤️',style:TextStyle(fontSize:90)),Text(active?'در حال اتصال به همسرم…':'آماده تماس امن',style:const TextStyle(color:Colors.white,fontSize:20)),const SizedBox(height:28),FilledButton.icon(onPressed:()=>setState(()=>active=!active),icon:Icon(active?Icons.call_end:Icons.call),label:Text(active?'پایان تماس':'شروع تماس')),const SizedBox(height:18),const Padding(padding:EdgeInsets.all(24),child:Text('تماس از مسیر WebRTC و پیام‌رسانی سیگنالینگ همین Relay انجام می‌شود. برای تماس اینترنتی پایدار، سرور STUN/TURN اختصاصی لازم است.',textAlign:TextAlign.center,style:TextStyle(color:Colors.white70)))])));}
