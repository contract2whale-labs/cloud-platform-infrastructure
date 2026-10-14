#!/usr/bin/env python3
"""Optional local GET transport: existing Service port-forward, no Pod creation."""
import argparse,contextlib,re,socket,subprocess,time,urllib.error,urllib.parse,urllib.request
SERVICES={'platform-tempo-active-query','platform-tempo-e2-query-frontend','platform-tempo-e2-querier','platform-tempo-e3-query-frontend','platform-tempo-e3-querier','platform-tempo-query-frontend','platform-tempo-querier'}
def coordinates(url):
 u=urllib.parse.urlparse(url)
 if u.scheme!='http' or u.username or u.password or u.fragment or u.port!=3200:raise ValueError('Only fixed in-cluster Tempo query Services are allowed')
 host=(u.hostname or '').split('.')
 if len(host)!=2 or host[0] not in SERVICES or host[1]!='monitoring':raise ValueError('Unregistered read-only query destination')
 if not re.fullmatch(r'/(api/traces|querier/api/traces)/[0-9a-f]{32}',u.path) or u.query not in ('','mode=blocks'):raise ValueError('Only exact trace-ID GET paths are allowed')
 return host[0],u.path+('?' + u.query if u.query else '')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,request,fp,code,msg,headers,newurl):return None

def fetch(context,url):
 service,path=coordinates(url)
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 process=subprocess.Popen(['kubectl','--context',context,'-n','monitoring','port-forward','service/'+service,f'{port}:3200','--address','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  for _ in range(100):
   if process.poll() is not None:raise RuntimeError('Read-only forwarding failed; inspect context/network permissions')
   try:
    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
   except OSError:time.sleep(.1)
  else:raise RuntimeError('Read-only forwarding timeout')
  request=urllib.request.Request(f'http://127.0.0.1:{port}'+path,method='GET')
  try:
   with urllib.request.build_opener(NoRedirect).open(request,timeout=30) as response:return response.read(),response.status
  except urllib.error.HTTPError as error:return error.read(),error.code
 finally:
  process.terminate()
  try:process.wait(timeout=5)
  except subprocess.TimeoutExpired:process.kill();process.wait()
def main():
 p=argparse.ArgumentParser();p.add_argument('--context',required=True);p.add_argument('--url',required=True);a=p.parse_args();body,status=fetch(a.context,a.url)
 import sys
 sys.stdout.buffer.write(body+b'\n'+str(status).encode()+b'\n')
if __name__=='__main__':main()
