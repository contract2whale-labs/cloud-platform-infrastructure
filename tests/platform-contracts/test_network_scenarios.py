"""Bounded network scenarios: fake kubectl order and real stdlib verdict logic."""
import contextlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/"tests/e2e/core/scripts/check-network.sh"
FAKE=r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]; case=os.environ["NETWORK_CASE"]
with Path(os.environ["NETWORK_CALLS"]).open("a") as out:out.write(json.dumps(args)+"\n")
if "delete" in args:sys.exit(5 if case=="cleanup-failed" else 0)
if "create" in args:sys.exit(42 if case=="create-failed" else 0)
if "rollout" in args:sys.exit(9 if case=="rollout-failed" else 0)
if "get" in args:
 object=args[args.index("get")+1]
 if object.startswith(("deployment/","service/")):
  if case=="lookup-failed":print("fixture stale output");sys.exit(7)
  if case=="existing":print(object)
  sys.exit()
 name=args[args.index("get")+2]
 ports={"policy-server":[8080],"kubernetes":[443],"collection-gateway":[4317,4318,8888]}[name]
 if case=="missing-metrics-service-port" and name=="collection-gateway":ports.remove(8888)
 print(json.dumps({"spec":{"clusterIP":"10.100.12.34","ports":[{"port":x,"protocol":"TCP"} for x in ports]}}));sys.exit()
if "exec" in args:
 mode,host,port,label=args[-4:]
 if case=="cli-forbidden" and label=="gateway-metrics-control":print("Forbidden",file=sys.stderr);sys.exit(42)
 if case=="missing-verdict" and label=="gateway-metrics-denied":sys.exit()
 if case=="listener-refused" and label=="gateway-metrics-control" or case=="deny-refused" and label=="gateway-metrics-denied":print("PROBE_INCONCLUSIVE label="+label+" reason=ConnectionRefusedError");sys.exit(2)
 if case=="dns-failed" and mode=="dns":print("PROBE_INCONCLUSIVE label="+label+" reason=gaierror");sys.exit(2)
 if case=="negative-reached" and label=="gateway-metrics-denied":print("PROBE_FAILED label="+label+" reason=unexpected_connection");sys.exit(1)
 verdict={"dns":"DNS_ALLOWED","http":"HTTP_ALLOWED","allow":"TCP_ALLOWED","deny":"TCP_BLOCKED"}[mode]
 print(verdict+" label="+label+" fixture=true");sys.exit()
sys.exit(88)
'''
@unittest.skipUnless(HELPER.exists(), "Bounded core diagnostics have not been introduced yet")
class NetworkScenarioTests(unittest.TestCase):
 def run_case(self,scenario,case,want):
  with tempfile.TemporaryDirectory() as folder:
   work=Path(folder);binpath=work/"bin";binpath.mkdir();fake=binpath/"kubectl";fake.write_text(FAKE);fake.chmod(0o755)
   calls=work/"calls.jsonl"
   env=os.environ|{"PATH":str(binpath)+":"+os.environ["PATH"],"NETWORK_CASE":case,"NETWORK_CALLS":str(calls),"KUBE_CONTEXT":"fixture","PROBE_IMAGE":"fixture/python@sha256:"+"1"*64}
   run=subprocess.run(["bash",str(HELPER),"--scenario",scenario],env=env,capture_output=True,text=True)
   self.assertEqual(run.returncode,want,run.stdout+run.stderr)
   events=[json.loads(x) for x in calls.read_text().splitlines()]
   self.assertIn("delete",events[-1],events)
   deletes=[x for x in events if "delete" in x]
   self.assertEqual(len(deletes),1 if scenario=="core" else 2)
   run_selectors=[x[x.index("-l")+1] for x in deletes]
   self.assertEqual(len(set(run_selectors)),1)
   self.assertRegex(run_selectors[0],r"^platform[.]example/probe-run=[0-9a-f]{32}$")
   self.assertTrue(all("-f" not in x for x in deletes))
   self.assertEqual("NETWORK_SCENARIO_PASS" in run.stdout,want==0)
   labels=[x[-1] for x in events if "exec" in x]
   if want==0 and scenario=="collection-gateway":
    self.assertLess(labels.index("gateway-metrics-control"),labels.index("gateway-metrics-denied"))
    self.assertIn("gateway-4317",labels);self.assertIn("gateway-4318",labels)
   if want==0 and scenario=="api-egress":self.assertLess(labels.index("api-control"),labels.index("api-denied"))
 def test_three_successful_scenarios_cleanup_after_all_probes(self):
  for scenario in ("core","api-egress","collection-gateway"):
   with self.subTest(scenario=scenario):self.run_case(scenario,"valid",0)
 def test_each_failure_stops_and_still_cleans_up(self):
  for case,want in (("cli-forbidden",2),("missing-verdict",2),("listener-refused",2),("deny-refused",2),("dns-failed",2),("negative-reached",1),("missing-metrics-service-port",2),("create-failed",42),("rollout-failed",9),("cleanup-failed",2)):
   with self.subTest(case=case):self.run_case("collection-gateway",case,want)
 def test_existing_objects_and_failed_lookups_have_no_mutation_or_cleanup(self):
  for case in ["existing","lookup-failed"]:
   with self.subTest(case=case),tempfile.TemporaryDirectory() as folder:
    work=Path(folder);binpath=work/"bin";binpath.mkdir();fake=binpath/"kubectl";fake.write_text(FAKE);fake.chmod(0o700)
    calls=work/"calls.jsonl"
    env=os.environ|{"PATH":str(binpath)+":"+os.environ["PATH"],"NETWORK_CASE":case,"NETWORK_CALLS":str(calls),"KUBE_CONTEXT":"fixture","PROBE_IMAGE":"fixture/python@sha256:"+"1"*64}
    run=subprocess.run(["bash",str(HELPER)],env=env,capture_output=True,text=True)
    self.assertEqual(run.returncode,2,run.stdout+run.stderr)
    events=[json.loads(x) for x in calls.read_text().splitlines()]
    self.assertFalse(any("create" in x or "apply" in x or "delete" in x for x in events))
 def actual_probe(self,mode,side_effect):
  code=re.search(r"PROBE_CODE='(.*?)'\nprobe\(\)",HELPER.read_text(),re.S)[1]
  output=io.StringIO()
  address=(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",54321))
  with patch.object(sys,"argv",["probe",mode,"fixture.invalid","54321","verdict"]),patch("socket.getaddrinfo",return_value=[address]),patch("socket.socket") as factory,contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
   factory.return_value.connect.side_effect=side_effect
   try:exec(compile(code,"actual-network-probe","exec"),{})
   except SystemExit as error:return error.code,output.getvalue()
  return 0,output.getvalue()
 def test_timeout_is_the_only_accepted_negative_socket_result(self):
  for mode,error,exitcode,label in (("deny",TimeoutError(),0,"TCP_BLOCKED"),("deny",ConnectionRefusedError(),2,"PROBE_INCONCLUSIVE"),("deny",socket.gaierror(),2,"PROBE_INCONCLUSIVE"),("deny",None,1,"PROBE_FAILED"),("allow",TimeoutError(),1,"PROBE_FAILED"),("allow",None,0,"TCP_ALLOWED")):
   with self.subTest(mode=mode,error=type(error).__name__):
    rc,out=self.actual_probe(mode,error);self.assertEqual(rc,exitcode,out);self.assertIn(label,out)
 def test_dns_error_is_inconclusive(self):
  code=re.search(r"PROBE_CODE='(.*?)'\nprobe\(\)",HELPER.read_text(),re.S)[1]
  with patch.object(sys,"argv",["probe","dns","fixture.invalid","0","dns-verdict"]),patch("socket.getaddrinfo",side_effect=socket.gaierror()),contextlib.redirect_stderr(io.StringIO()):
   with self.assertRaises(SystemExit) as error:exec(compile(code,"actual-dns-probe","exec"),{})
   self.assertEqual(error.exception.code,2)
if __name__=="__main__":unittest.main()
