"""Local fake kubectl only; no cluster, transport, or native curl validation."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
SOURCE=Path(__file__).resolve().parents[2]/'platform/environments/dev/queue/scripts/trace-probe.sh'
class Send(unittest.TestCase):
 def test_response_and_process_status(self):
  for mode,code in [('success',0),('partial-error',2),('http-error',1),('empty-error',2),('rejected',1),('warning',1),('malformed',2)]:
   with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); scripts=root/'queue/scripts'; scripts.mkdir(parents=True); script=scripts/'trace-probe.sh';shutil.copyfile(SOURCE,script)
    fake=root/'bin';fake.mkdir(); tool=fake/'kubectl'
    tool.write_text('#!'+sys.executable+'\nimport os,sys,json\na=sys.argv[1:]\nif len(a)<16 or a[:4]!=["--context","fixture","-n","observability"] or a[4]!="run" or "--rm" not in a or "-X" not in a or "POST" not in a: sys.exit(97)\nm=os.environ["TRACE_TEST_MODE"]\nbody={"partialSuccess":{"rejectedSpans":"1"}} if m=="rejected" else {"partialSuccess":{"errorMessage":"warning"}} if m=="warning" else {}\nprint("" if m=="empty-error" else ("not-json" if m=="malformed" else json.dumps(body))+"\\n"+("503" if m=="http-error" else "200"),end="")\nsys.exit(7 if m.endswith("error") and m!="http-error" else 0)\n');tool.chmod(0o755)
    env={'PATH':str(fake)+':/usr/bin:/bin','HOME':tmp,'TMPDIR':tmp,'KUBE_CONTEXT':'fixture','TRACE_TEST_MODE':mode}
    result=subprocess.run(['/bin/bash',str(script),'send','--endpoint','http://fixture:4318','--id','a'*32],env=env,capture_output=True,text=True,timeout=10)
    self.assertEqual(result.returncode,code,result.stdout+result.stderr)
    receipt=root/'queue/local-inputs'/('trace-probe-'+'a'*32+'.tsv')
    self.assertEqual(receipt.exists(),mode=='success')
    if mode!='success':self.assertNotIn('TRACE_SENT',result.stdout)
class Query(unittest.TestCase):
 def test_actual_trace_body(self):
  for mode,code in [('hex',0),('base64',0),('wrong-id',2),('empty',2),('malformed',2),('not-found',1),('transport',2)]:
   with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); scripts=root/'queue/scripts'; scripts.mkdir(parents=True); script=scripts/'trace-probe.sh';shutil.copyfile(SOURCE,script)
    fake=root/'bin';fake.mkdir(); tool=fake/'kubectl'
    tool.write_text('#!'+sys.executable+'\nimport os,sys,json,base64\na=sys.argv[1:]\nif a[:4]!=["--context","fixture","-n","observability"] or "--rm" not in a or "curl" not in a or "-X" in a:sys.exit(97)\nm=os.environ["TRACE_TEST_MODE"]\nt=base64.b64encode(bytes.fromhex("a"*32)).decode() if m=="base64" else "b"*32 if m=="wrong-id" else "a"*32\nbody={} if m=="empty" else {"batches":[{"scopeSpans":[{"spans":[{"traceId":t}]}]}]}\nprint(("not-json" if m=="malformed" else json.dumps(body))+"\\n"+("404" if m=="not-found" else "200"),end="")\nsys.exit(7 if m=="transport" else 0)\n');tool.chmod(0o755)
    env={'PATH':str(fake)+':/usr/bin:/bin','HOME':tmp,'TMPDIR':tmp,'KUBE_CONTEXT':'fixture','TRACE_TEST_MODE':mode}
    result=subprocess.run(['/bin/bash',str(script),'query','--endpoint','http://fixture:3200','--id','a'*32,'--timeout','0'],env=env,capture_output=True,text=True,timeout=10)
    self.assertEqual(result.returncode,code,result.stdout+result.stderr)
    receipt=root/'queue/local-inputs'/('trace-probe-'+'a'*32+'.tsv')
    self.assertEqual(receipt.exists(),code==0)
    if code:self.assertNotIn('TRACE_FOUND',result.stdout)
if __name__=='__main__':unittest.main()
