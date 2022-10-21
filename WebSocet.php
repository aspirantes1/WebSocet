<?php
$host = 'yamal.shop';
$port = 9555;
$path = 'C:/xampp/htdocs/ver24/cert/';
$transport = 'tlsv1.3';
$ssl = ['ssl' => [
          'local_cert'  => $path . 'server.crt',       // SSL Certificate
          'local_pk'    => $path . 'server.key',    // SSL Keyfile
          'disable_compression' => true,             // TLS compression attack vulnerability
          'verify_peer'         => false,            // Set this to true if acting as an SSL client
          'ssltransport' => $transport,              // Transport Methods such as 'tlsv1.1', tlsv1.2'
        ] ];
$ssl_context = stream_context_create($ssl);
$server = stream_socket_server($transport . '://' . $host . ':' . $port, $errno, $errstr, STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $ssl_context);
if (!$server) {  die("$errstr ($errno)"); }
$clients = array($server);
$write  = NULL;
$except = NULL;
$buffer = NULL;
while (true) {
  $changed = $clients;
  stream_select($changed, $write, $except, 20000);
  if (in_array($server, $changed)) {
    $client = @stream_socket_accept($server);
    if (!$client){ continue; }
    $clients[] = $client;
    $ip = stream_socket_get_name($client, true);
    echo "Join $ip\n";

    stream_set_blocking($client, true);
    $headers = fread($client, 1500);
    handshake($client, $headers, $host, $port);
    stream_set_blocking($client, false);

    send_message($clients, mask("Join $ip\n"));

    $found_socket = array_search($server, $changed);
    unset($changed[$found_socket]);    
  }
  foreach ($changed as $changed_socket) {
    $ip = stream_socket_get_name($changed_socket, true);
    $buffer = stream_get_contents($changed_socket);
        if ($buffer == false) {
            echo "Client Disconnected from $ip\n";
            @fclose($changed_socket);
            $found_socket = array_search($changed_socket, $clients);
            unset($clients[$found_socket]);
        } else {
    $unmasked = unmask($buffer);
    if ($unmasked != '') { 
      echo "\nReceived a Message from $ip:\n\"$unmasked\" \n";
      $response = mask($unmasked."\n");
      send_message($clients, $response);
    } elseif ($unmasked == 'ping') {
        $response = mask("PONG\n");
        send_message($clients, $response);
    } else {
        echo "Client Disconnected from $ip\n";
        @fclose($changed_socket);
        $found_socket = array_search($changed_socket, $clients);
        unset($clients[$found_socket]);
      }
    }
  }
}
fclose($server);

function unmask($text) {
  $decodedData = '';
  $firstByteBinary = sprintf('%08b', ord($text[0]));
  $opcode = bindec(substr($firstByteBinary, 4, 4));

  switch ($opcode) {
    case '1':
        $decodedData = 'text';
        break;
    case '2':
        $decodedData = 'binary';
        break;
    case '8':
        $decodedData = 'close';
        return '';
        break;
    case '9':
        $decodedData = 'ping';
        return 'ping';
        break;
    case '10':
        $decodedData = 'pong';
        break;
    default:
        return '';
}

    $length = @ord($text[1]) & 127;
    if($length == 126) {    $masks = substr($text, 4, 4);    $data = substr($text, 8); }
    elseif($length == 127) {    $masks = substr($text, 10, 4); $data = substr($text, 14); }
    else { $masks = substr($text, 2, 4); $data = substr($text, 6); }
    $lengthExt = $length == 0x7F ? 8 : 2;
    $text = "";
    for ($i = 0; $i < strlen($data); ++$i) { 
        $msg->text .= $data[$i] ^ $masks[$i % 4];
        $msg->length += ord($text[0]) << ($lengthExt - $i - 1) * 8;
        }
    return $msg;
    echo $msg;
}

function mask($text) {
    $b1 = 0x80 | (0x1 & 0x0f);
    $length = strlen($text);
    if($length <= 125)
        $header = pack('CC', $b1, $length);
    elseif($length > 125 && $length < 65536)
        $header = pack('CCn', $b1, 126, $length);
    elseif($length >= 65536)
        $header = pack('CCNN', $b1, 127, $length);
    return $header.$text;
}
function handshake($client, $rcvd, $host, $port){
    $headers = array();
    $lines = preg_split("/\r\n/", $rcvd);
    foreach($lines as $line)
    {
        $line = rtrim($line);
        if(preg_match('/\A(\S+): (.*)\z/', $line, $matches)){
            $headers[$matches[1]] = $matches[2];
        }
    }
    $secKey = $headers['Sec-WebSocket-Key'];
    $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
    $upgrade  = "https/1.1 101 Web Socket Protocol Handshake\r\n" .
    "Upgrade: websocket\r\n" .
    "Connection: Upgrade\r\n" .
    "Origin: $host\r\n" .
    "WebSocket-Location: wss://$host:$port\r\n".
    "Sec-WebSocket-Accept:$secAccept\r\n\r\n";
  fwrite($client, $upgrade);
}
function send_message($clients, $msg){
    foreach($clients as $changed_socket){
    @fwrite($changed_socket, $msg);
    }
}
?>
