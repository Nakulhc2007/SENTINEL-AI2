import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'dist');
const types = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2' };
http.createServer((req,res) => {
  const reqUrl = new URL(req.url, 'http://127.0.0.1');
  if (reqUrl.pathname.startsWith('/api/') || reqUrl.pathname.startsWith('/data/') || reqUrl.pathname.startsWith('/artifacts/')) {
    const upstream = http.request({ hostname:'127.0.0.1', port:8000, path:reqUrl.pathname + reqUrl.search, method:req.method, headers:{ ...req.headers, host:'127.0.0.1:8000' } }, upstream => { res.writeHead(upstream.statusCode || 502, upstream.headers); upstream.pipe(res); });
    upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('Backend unavailable'); });
    req.pipe(upstream); return;
  }
  let pathname; try { pathname = decodeURIComponent(reqUrl.pathname); } catch { res.writeHead(400); return res.end('Bad request'); }
  const file = path.resolve(root, '.' + pathname);
  if (!file.startsWith(root + path.sep) && file !== root && file !== path.join(root, 'index.html')) { res.writeHead(403); return res.end('Forbidden'); }
  const target = fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(root, 'index.html');
  res.writeHead(200, { 'Content-Type': types[path.extname(target)] || 'application/octet-stream', 'Cache-Control':'no-store' });
  fs.createReadStream(target).pipe(res);
}).listen(4174, '127.0.0.1', () => console.log('Fictional services portal at http://127.0.0.1:4174'));
