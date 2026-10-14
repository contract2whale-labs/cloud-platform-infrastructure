"""New course fixture: isolated, deterministic and intentionally credential-free."""
import http.server, json, socket, sys, time
MODE=sys.argv[1] if len(sys.argv)>1 else 'normal'
if MODE=='crash':
    print('COURSE_FIXED_CRASH_EXIT_42',flush=True)
    raise SystemExit(42)
if MODE=='oom':
    blocks=[]
    while True:
        blocks.append(bytearray(8*1024*1024))
        time.sleep(0.1)
if MODE not in ('normal','dns'):raise SystemExit(64)
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        healthy=True
        if MODE=='dns':
            try:socket.getaddrinfo('kubernetes.default.svc',443)
            except socket.gaierror:healthy=False
        data=json.dumps({'fixture':'isolated-course-probe','mode':MODE,'dns_ok':healthy}).encode()
        self.send_response(200 if healthy else 503);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
