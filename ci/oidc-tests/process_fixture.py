#!/usr/bin/env python3
"""OFFLINE TEST DOUBLE, install only under ci/oidc-tests, never as a production helper.

Runs the production parsing/validation with in-memory fake GitHub+STS replies.
Only the Terraform SDK-expiry test shortens the already-validated lifetime; this
is not a production option and does not contact any network destination.
"""
import datetime as dt
import json
from pathlib import Path
import sys
import time
from support import FakeTransport, environment, oidc

counter = Path(sys.argv[1])
mode = sys.argv[2]
count = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(count))
if 'failure' in mode and count > 1:
    sys.stderr.write('Deliberate offline credential failure.\n')
    sys.exit(1)
env = environment()
binding = oidc.make_binding(env, 'plan')
result = oidc.credentials(binding, env, FakeTransport(binding, count=count))
if mode.startswith('terraform'):
    result['Expiration'] = dt.datetime.fromtimestamp(time.time() + 2, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps(result))
