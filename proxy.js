// simple authenticated HTTP/HTTPS forward proxy (Node.js)
// Usage:
//   PROXY_USER=user PROXY_PASS=pass PORT=8080 WHITELIST_HOSTS=example.com,api.example.com node proxy.js

const http = require('http');
const net = require('net');
const url = require('url');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const PROXY_USER = process.env.PROXY_USER || 'proxyuser';
const PROXY_PASS = process.env.PROXY_PASS || 'proxypass';
const WHITELIST = (process.env.WHITELIST_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean); // empty = allow all

function unauthorized(res) {
  res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Proxy"' });
  res.end('Proxy authentication required');
}

function checkBasicAuth(header) {
  if (!header) return false;
  const m = header.match(/^Basic\s+(.+)$/i);
  if (!m) return false;
  try {
    const decoded = Buffer.from(m[1], 'base64').toString();
    const [user, pass] = decoded.split(':');
    return user === PROXY_USER && pass === PROXY_PASS;
  } catch (e) {
    return false;
  }
}

function hostAllowed(hostname) {
  if (WHITELIST.length === 0) return true;
  // strip port if present
  const hostOnly = hostname.split(':')[0];
  return WHITELIST.includes(hostOnly);
}

const server = http.createServer();

server.on('request', (req, res) => {
  // Standard HTTP request proxying (GET/POST/etc.)
  const proxyAuth = req.headers['proxy-authorization'];
  if (!checkBasicAuth(proxyAuth)) return unauthorized(res);

  // Build target URL
  // If client sends absolute-form (e.g., curl -x), req.url contains full URL
  let target;
  try {
    if (/^https?:\/\//i.test(req.url)) {
      target = new url.URL(req.url);
    } else {
      // relative path - use Host header
      const hostHeader = req.headers['host'];
      if (!hostHeader) {
        res.writeHead(400); res.end('Bad Request: missing Host header');
        return;
      }
      target = new url.URL(`http://${hostHeader}${req.url}`);
    }
  } catch (err) {
    res.writeHead(400); res.end('Bad Request: invalid URL');
    return;
  }

  if (!hostAllowed(target.hostname)) {
    res.writeHead(403); res.end('Forbidden: host not allowed by proxy whitelist');
    return;
  }

  // Prepare options for outgoing request
  const options = {
    method: req.method,
    headers: Object.assign({}, req.headers)
  };
  // Remove proxy-specific headers from forwarded request
  delete options.headers['proxy-authorization'];
  delete options.headers['proxy-connection'];
  delete options.headers['connection'];

  const upstream = http.request(target, options, upstreamRes => {
    // copy status & headers
    const headers = Object.assign({}, upstreamRes.headers);
    // remove hop-by-hop headers per RFC
    ['transfer-encoding','connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','upgrade'].forEach(h=>delete headers[h]);
    res.writeHead(upstreamRes.statusCode, headers);
    upstreamRes.pipe(res);
  });

  upstream.on('error', err => {
    console.error('Upstream request error:', err && err.message);
    res.writeHead(502); res.end('Bad Gateway');
  });

  req.pipe(upstream);
});

// Handle HTTPS CONNECT (tunneling)
server.on('connect', (req, clientSocket, head) => {
  // req.url is host:port
  const proxyAuth = req.headers['proxy-authorization'];
  if (!checkBasicAuth(proxyAuth)) {
    // need to send 407 on the socket
    clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n');
    clientSocket.destroy();
    return;
  }

  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;

  if (!hostAllowed(host)) {
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    clientSocket.destroy();
    return;
  }

  const serverSocket = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // Pipe any buffered data (head) then pipe sockets
    if (head && head.length) serverSocket.write(head);
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', (err) => {
    console.error('Tunnel error to', req.url, err && err.message);
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.destroy();
  });
});

server.on('clientError', (err, socket) => {
  console.error('Client error:', err && err.message);
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, () => {
  console.log(`Authenticated forward proxy listening on :${PORT}`);
  console.log(`User: ${PROXY_USER}  Pass: ${PROXY_PASS}`);
  if (WHITELIST.length) console.log('Whitelist:', WHITELIST.join(', '));
  else console.log('No whitelist - all hosts allowed (consider enabling WHITELIST_HOSTS)');
});
