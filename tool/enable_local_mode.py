from pathlib import Path

p = Path('lib/main.dart')
s = p.read_text()

imp = "import 'package:web_socket_channel/web_socket_channel.dart';\n"
if "import 'local_peer.dart';" not in s:
    s = s.replace(imp, imp + "import 'local_peer.dart';\n", 1)

old = "  RelayClient? relay;\n  bool connected = false;\n  bool busy = true;"
new = "  RelayClient? relay;\n  LocalPeer? localPeer;\n  bool connected = false;\n  bool localConnected = false;\n  bool busy = true;"
if old in s:
    s = s.replace(old, new, 1)

old_start = """    if (relayUrl != null && relayUrl.startsWith('wss://')) {
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

    if (mounted) setState(() => busy = false);"""
new_start = """    final secretHash = await crypto.hash(secret);
    final pairId = secretHash.substring(0, min(32, secretHash.length));
    final deviceId = await vault.deviceId();

    if (relayUrl != null && relayUrl.startsWith('wss://')) {
      relay = RelayClient(
        url: relayUrl,
        pairId: pairId,
        deviceId: deviceId,
        secretHash: secretHash,
      );
      try {
        await relay!.connect(onRemote);
        connected = true;
      } catch (_) {
        connected = false;
      }
    }

    // Start local LAN discovery regardless of Internet availability. Messages
    // remain AES-GCM encrypted; the LAN transport only forwards ciphertext.
    localPeer = LocalPeer(
      pairId: pairId,
      deviceId: deviceId,
      secretHash: secretHash,
      onMessage: onRemote,
    );
    try {
      await localPeer!.start();
      localConnected = localPeer!.connected;
    } catch (_) {
      localConnected = false;
    }

    if (mounted) setState(() => busy = false);"""
if old_start not in s:
    raise SystemExit('Chat start block not found')
s = s.replace(old_start, new_start, 1)

old_send = """    if (relay != null && connected) {
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
    }"""
new_send = """    final ciphertext = await crypto.encrypt(
      secret,
      jsonEncode({
        'text': text,
        'time': message.time.toIso8601String(),
      }),
    );
    final packet = {
      'type': 'message',
      'ciphertext': ciphertext,
    };
    if (relay != null && connected) relay!.send(packet);
    if (localPeer != null) localPeer!.send(packet);"""
if old_send not in s:
    raise SystemExit('Chat send block not found')
s = s.replace(old_send, new_send, 1)

old_dispose = """  void dispose() {
    relay?.close();
    input.dispose();"""
new_dispose = """  void dispose() {
    relay?.close();
    localPeer?.stop();
    input.dispose();"""
if old_dispose not in s:
    raise SystemExit('Chat dispose block not found')
s = s.replace(old_dispose, new_dispose, 1)

old_icon = """              connected ? Icons.cloud_done : Icons.cloud_off,
              color: connected ? Colors.green : Colors.grey,"""
new_icon = """              (connected || localConnected) ? Icons.favorite : Icons.cloud_off,
              color: (connected || localConnected) ? Colors.green : Colors.grey,"""
if old_icon not in s:
    raise SystemExit('Chat status icon block not found')
s = s.replace(old_icon, new_icon, 1)

p.write_text(s)
print('LOCAL_MODE_ENABLED')
