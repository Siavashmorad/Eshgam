import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

/// Local LAN peer transport used when the international Internet/relay is
/// unavailable. It never handles plaintext; callers send encrypted payloads.
class LocalPeer {
  final String pairId;
  final String deviceId;
  final String secretHash;
  final void Function(Map<String, dynamic>) onMessage;

  RawDatagramSocket? _udp;
  HttpServer? _server;
  WebSocket? _socket;
  Timer? _announceTimer;
  bool _running = false;
  int _port = 0;

  LocalPeer({
    required this.pairId,
    required this.deviceId,
    required this.secretHash,
    required this.onMessage,
  });

  bool get connected => _socket != null;

  Future<void> start() async {
    if (_running) return;
    _running = true;
    _server = await HttpServer.bind(InternetAddress.anyIPv4, 0);
    _port = _server!.port;
    _server!.listen(_handleRequest);

    _udp = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 40411,
        reuseAddress: true, reusePort: true);
    _udp!.broadcastEnabled = true;
    _udp!.listen(_handleDatagram);
    _announceTimer = Timer.periodic(const Duration(seconds: 2), (_) => _announce());
    _announce();
  }

  void _announce() {
    final socket = _udp;
    if (socket == null) return;
    final packet = utf8.encode(jsonEncode({
      'app': 'eshgam-lan-v1',
      'pair': pairId,
      'device': deviceId,
      'hash': secretHash,
      'port': _port,
    }));
    try {
      socket.send(packet, InternetAddress('255.255.255.255'), 40411);
    } catch (_) {}
  }

  void _handleDatagram(RawSocketEvent event) {
    if (event != RawSocketEvent.read) return;
    final socket = _udp;
    if (socket == null) return;
    Datagram? datagram;
    while ((datagram = socket.receive()) != null) {
      try {
        final data = jsonDecode(utf8.decode(datagram!.data)) as Map<String, dynamic>;
        if (data['app'] != 'eshgam-lan-v1' ||
            data['pair'] != pairId ||
            data['hash'] != secretHash ||
            data['device'] == deviceId) {
          continue;
        }
        final remoteDevice = data['device'] as String;
        // Deterministic tie-break prevents both devices opening connections.
        if (deviceId.compareTo(remoteDevice) <= 0 || connected) continue;
        final port = (data['port'] as num).toInt();
        _connect(datagram.address.address, port, remoteDevice);
      } catch (_) {}
    }
  }

  Future<void> _connect(String host, int port, String remoteDevice) async {
    if (connected || !_running) return;
    try {
      final ws = await WebSocket.connect(
        'ws://$host:$port/?pair=${Uri.encodeComponent(pairId)}&device=${Uri.encodeComponent(deviceId)}&hash=${Uri.encodeComponent(secretHash)}',
      ).timeout(const Duration(seconds: 4));
      _attach(ws);
    } catch (_) {}
  }

  Future<void> _handleRequest(HttpRequest request) async {
    if (request.uri.path != '/') {
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
      return;
    }
    final q = request.uri.queryParameters;
    if (q['pair'] != pairId || q['hash'] != secretHash || q['device'] == null || q['device'] == deviceId) {
      request.response.statusCode = HttpStatus.forbidden;
      await request.response.close();
      return;
    }
    final remote = q['device']!;
    if (deviceId.compareTo(remote) <= 0) {
      request.response.statusCode = HttpStatus.conflict;
      await request.response.close();
      return;
    }
    try {
      final ws = await WebSocketTransformer.upgrade(request);
      if (!connected) _attach(ws);
      else await ws.close();
    } catch (_) {
      try { await request.response.close(); } catch (_) {}
    }
  }

  void _attach(WebSocket ws) {
    if (_socket != null) {
      ws.close();
      return;
    }
    _socket = ws;
    ws.listen((raw) {
      try {
        final value = jsonDecode(raw.toString());
        if (value is Map<String, dynamic>) onMessage(value);
      } catch (_) {}
    }, onDone: () {
      if (identical(_socket, ws)) _socket = null;
    }, onError: (_) {
      if (identical(_socket, ws)) _socket = null;
    });
  }

  void send(Map<String, dynamic> value) {
    try { _socket?.add(jsonEncode(value)); } catch (_) {}
  }

  Future<void> stop() async {
    _announceTimer?.cancel();
    _announceTimer = null;
    try { await _socket?.close(); } catch (_) {}
    _socket = null;
    try { await _udp?.close(); } catch (_) {}
    _udp = null;
    try { await _server?.close(force: true); } catch (_) {}
    _server = null;
    _running = false;
  }
}
