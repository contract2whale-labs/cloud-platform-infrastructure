#!/usr/bin/env python3
"""Read selected non-secret runtime fields from an actual ConfigMap JSON response."""
import argparse
import json
import re
import sys
from ruamel.yaml import YAML

FIELDS = {
    'storage.trace.s3.bucket', 'storage.trace.s3.prefix', 'ingest.kafka.topic',
    'ingest.kafka.address', 'ingest.kafka.sasl.username', 'ingest.kafka.consumer_group',
    'service.pipelines', 'service.pipelines.traces', 'exporters',
    'exporters.otlp_grpc/traces.endpoint', 'exporters.otlp/traces.endpoint',
    'exporters.otlp_http/logs.endpoint', 'exporters.otlphttp/logs.endpoint',
    'receivers.filelog.operators',
}

def inspect(response, key, fields):
    if response.get('kind') == 'ConfigMap':
        items = [response]
    elif response.get('kind') in ('ConfigMapList', 'List') and isinstance(response.get('items'), list):
        items = response['items']
    else:
        raise ValueError('expected a successful ConfigMap JSON response')
    matches = [item for item in items if item.get('kind') == 'ConfigMap' and key in item.get('data', {})]
    if len(matches) != 1:
        raise ValueError('expected exactly one ConfigMap with the requested configuration key')
    config = YAML(typ='safe').load(matches[0]['data'][key])
    if not isinstance(config, dict):
        raise ValueError('configuration is not a YAML mapping')
    result = []
    for field in fields:
        if field not in FIELDS:
            raise ValueError('field is outside the non-secret runtime inspection allowlist: ' + field)
        value = config
        for segment in field.split('.'):
            if not isinstance(value, dict) or segment not in value:
                raise ValueError('runtime configuration field is absent: ' + field)
            value = value[segment]
        if value is None:
            raise ValueError('runtime configuration field is null: ' + field)
        result.append(value)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', choices=['tempo.yaml', 'relay'], required=True)
    parser.add_argument('--field', nargs='+', required=True)
    args = parser.parse_args()
    try:
        values = inspect(json.load(sys.stdin), args.key, args.field)
        for value in values:
            print(value if isinstance(value, (str, int, float)) else json.dumps(value, ensure_ascii=False))
    except (ValueError, KeyError, TypeError) as exc:
        print('CONFIG_INSPECTION_FAILED: ' + str(exc), file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
