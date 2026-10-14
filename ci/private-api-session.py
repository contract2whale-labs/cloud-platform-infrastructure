#!/usr/bin/env python3
"""Same-job private API session. Never changes TLS identity or opens public API."""
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

class GuardError(RuntimeError): pass

def require(ok, message):
    if not ok: raise GuardError(message)

def command(argv, *, env=None):
    return subprocess.check_output(argv, env=env, stderr=subprocess.PIPE, timeout=180)

def aws(region, *args):
    return json.loads(command(['aws', *args, '--region', region, '--output', 'json', '--no-cli-pager']))

@contextlib.contextmanager
def private_api(cluster, relay, region, kubeconfig_path):
    """cluster and relay are fresh version-pinned Terraform outputs, never user argv."""
    info = aws(region, 'eks', 'describe-cluster', '--name', cluster)['cluster']
    require(info['name'] == cluster and info['status'] == 'ACTIVE', 'Cluster identity/readiness mismatch.')
    require(info['resourcesVpcConfig']['endpointPrivateAccess'] is True and info['resourcesVpcConfig']['endpointPublicAccess'] is False, 'Private-only API required.')
    rows = aws(region, 'ssm', 'describe-instance-information', '--filters', json.dumps([{'Key':'InstanceIds','Values':[relay]}]))['InstanceInformationList']
    require(len(rows) == 1 and rows[0]['InstanceId'] == relay and rows[0]['PingStatus'] == 'Online', 'Exact relay is not SSM Online.')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
    params = json.dumps({'portNumber':['3128'], 'localPortNumber':[str(port)]})
    # No stdout/stderr in public CI logs. Session token output is deliberately discarded.
    process = subprocess.Popen(['aws','ssm','start-session','--region',region,'--target',relay,'--document-name','AWS-StartPortForwardingSession','--parameters',params], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            require(process.poll() is None, 'SSM tunnel exited before readiness.')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=1): break
            except OSError: time.sleep(1)
        else: raise GuardError('SSM tunnel readiness timed out.')
        path = Path(kubeconfig_path)
        require(not path.exists(), 'Use a fresh private kubeconfig path.')
        command(['aws','eks','update-kubeconfig','--region',region,'--name',cluster,'--alias',cluster,'--kubeconfig',str(path),'--proxy-url',f'http://127.0.0.1:{port}'])
        path.chmod(0o600)
        env = {**os.environ, 'KUBECONFIG':str(path)}
        config = json.loads(command(['kubectl','config','view','--raw','-o','json'],env=env))
        require(len(config['clusters']) == 1, 'Unexpected kubeconfig clusters.')
        actual = config['clusters'][0]['cluster']
        require(actual['server'] == info['endpoint'] and actual['certificate-authority-data'] == info['certificateAuthority']['data'] and not actual.get('insecure-skip-tls-verify'), 'Endpoint/CA mismatch or TLS bypass.')
        require(command(['kubectl','--request-timeout=30s','get','--raw=/readyz'],env=env).strip() == b'ok', 'Private API /readyz failed.')
        yield env, info
    finally:
        process.terminate()
        try: process.wait(timeout=15)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
        Path(kubeconfig_path).unlink(missing_ok=True)
