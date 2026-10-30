import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const PORT = Number(process.env.SENTINEL_PORTAL_PORT || 4174);
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.csv': 'text/csv; charset=utf-8'
};

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${PORT}`);
  if (!['GET', 'HEAD'].includes(request.method)) {
    response.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8', 'Allow': 'GET, HEAD' });
    response.end('Read-only local demo server');
    return;
  }
  if (url.pathname === '/') {
    response.writeHead(302, { Location: '/portal/' });
    response.end();
    return;
  }

  let decoded;
  try { decoded = decodeURIComponent(url.pathname); }
  catch { response.writeHead(400); response.end('Invalid path'); return; }
  const target = path.resolve(ROOT, `.${decoded}`);
  if (!target.startsWith(`${ROOT}${path.sep}`) && target !== ROOT) {
    response.writeHead(403); response.end('Forbidden'); return;
  }
  let file = target;
  try { if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html'); }
  catch { response.writeHead(404); response.end('Not found'); return; }
  fs.readFile(file, (error, content) => {
    if (error) { response.writeHead(404); response.end('Not found'); return; }
    response.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': content.length,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    });
    response.end(request.method === 'HEAD' ? undefined : content);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`SENTINEL fictional training portal: http://localhost:${PORT}/portal/`);
});
