#!/usr/bin/env python3
"""Verify reviewed trace transitions through readonly AWS and Kubernetes queries."""
import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from read_diagnostic_context import read_context

class Difference(ValueError):
    pass

class Inconclusive(RuntimeError):
    pass

def expect(condition, field):
    if not condition:
        raise Difference(field + " does not match the approved transition")

def query(command, *, text=False):
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        return result.stdout.strip() if text else json.loads(result.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        raise Inconclusive("query failed: " + command[0] + " (" + type(error).__name__ + ")") from None

def environment():
    values = {name: os.environ.get(name, "") for name in [
        "ENVIRONMENT", "EXPECTED_ACCOUNT_ID", "AWS_REGION", "QUEUE_EKS_CLUSTER", "KUBE_CONTEXT"]}
    if values["ENVIRONMENT"] not in {"dev", "prod"}:
        raise Inconclusive("ENVIRONMENT must be dev or prod")
    if not re.fullmatch(r"[0-9]{12}", values["EXPECTED_ACCOUNT_ID"]):
        raise Inconclusive("EXPECTED_ACCOUNT_ID is required")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", values["AWS_REGION"]):
        raise Inconclusive("AWS_REGION is required")
    if not values["QUEUE_EKS_CLUSTER"] or not values["KUBE_CONTEXT"]:
        raise Inconclusive("queue cluster and explicit kube context are required")
    account = query(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], text=True)
    expect(account == values["EXPECTED_ACCOUNT_ID"], "AWS account")
    endpoint = query(["aws", "eks", "describe-cluster", "--region", values["AWS_REGION"], "--name",
                      values["QUEUE_EKS_CLUSTER"], "--query", "cluster.endpoint", "--output", "text"], text=True)
    kube = ["kubectl", "--context", values["KUBE_CONTEXT"]]
    current = query(["kubectl", "config", "view", "--context", values["KUBE_CONTEXT"], "--minify",
                     "-o", "jsonpath={.clusters[0].cluster.server}"], text=True)
    expect(endpoint.startswith("https://") and endpoint == current, "EKS API context")
    return values, kube

def verify_application(app, revision, env, namespace):
    expect(bool(re.fullmatch(r"[0-9a-f]{40}", revision)), "approved Git revision")
    expect(app.get("spec", {}).get("destination", {}).get("namespace") == namespace, "Application destination namespace")
    expect(app["spec"]["destination"].get("server") == "https://kubernetes.default.svc", "Application destination server")
    sources = app["spec"].get("sources", [])
    expect(isinstance(sources, list) and len(sources) == 2
           and all(isinstance(source, dict) for source in sources), "Application source set")
    git_sources = [i for i, source in enumerate(sources) if source.get("ref") == "values"]
    chart_sources = [i for i, source in enumerate(sources) if source.get("chart") == "opentelemetry-collector"]
    expect(len(git_sources) == 1 and len(chart_sources) == 1
           and git_sources[0] != chart_sources[0], "Application chart and Git sources")
    expect(sources[chart_sources[0]].get("targetRevision") == "0.173.1", "Application chart version")
    # Argo records revisions in spec.sources order, including the chart source.
    expected_revisions = [revision if i == git_sources[0] else "0.173.1" for i in range(2)]
    status = app.get("status", {})
    expect(status.get("sync", {}).get("status") == "Synced", "Application sync")
    revisions = status.get("sync", {}).get("revisions", [])
    expect(revisions == expected_revisions, "Application complete source revisions")
    operation = status.get("operationState", {})
    expect(operation.get("phase") == "Succeeded", "Application operation")
    completed = operation.get("syncResult", {}).get("revisions", [])
    expect(completed == expected_revisions, "Application completed operation source revisions")
    expect(bool(operation.get("startedAt")) and bool(operation.get("finishedAt")), "Application operation timestamps")
    return sources, operation

def parse_config(text, label):
    try:
        config = YAML(typ="safe").load(text)
        if not isinstance(config, dict):
            raise ValueError("not a mapping")
        return config
    except (YAMLError, ValueError) as error:
        raise Inconclusive(label + " configuration is malformed") from None

def verify_collection(app, config, deployments, mode, revision, env):
    sources, operation = verify_application(app, revision, env, "observability")
    charts = [source for source in sources if source.get("chart") == "opentelemetry-collector"]
    expect(len(charts) == 1 and charts[0].get("targetRevision") == "0.173.1" and charts[0].get("helm", {}).get("releaseName") == "collection-gateway", "Collector release name")
    files = charts[0]["helm"].get("valueFiles", [])
    base = "$values/gitops/platform/collection-gateway/values/" + env
    suffix = {"pause": "-paused.yaml", "resume-e2": "-e2.yaml", "resume-e3": "-e3.yaml"}[mode]
    choices = [[base + ".yaml", base + suffix]]
    # A reviewed edit of the shared traces source is also supported; live fields still must match.
    choices.append([base + ".yaml", base + "-traces.yaml"])
    expect(files in choices, "Collector values selection")
    pipelines = {name: value for name, value in config.get("service", {}).get("pipelines", {}).items() if value is not None}
    expect(set(pipelines) == ({"logs", "metrics"} if mode == "pause" else {"logs", "metrics", "traces"}), "Collector pipelines")
    log_exports = pipelines["logs"].get("exporters", [])
    expect(len(log_exports) == 1 and log_exports[0] in {"otlp_http/logs", "otlphttp/logs"}, "Collector logs exporter binding")
    expect(pipelines["metrics"].get("exporters") == ["prometheus"], "Collector metrics exporter binding")
    logs = config.get("exporters", {}).get(log_exports[0], {})
    expect(logs.get("endpoint") == "http://platform-loki-gateway.logging.svc.cluster.local/otlp", "Collector logs destination")
    expect(config.get("exporters", {}).get("prometheus", {}).get("endpoint") == "0.0.0.0:8889", "Collector metrics endpoint")
    if mode == "pause":
        traces = config.get("exporters", {}).get("otlp_grpc/traces", config.get("exporters", {}).get("otlp/traces", {}))
    else:
        trace_exports = pipelines["traces"].get("exporters", [])
        expect(len(trace_exports) == 1 and trace_exports[0] in {"otlp_grpc/traces", "otlp/traces"}, "Collector traces exporter binding")
        traces = config.get("exporters", {}).get(trace_exports[0], {})
    expected_endpoint = "" if mode == "pause" else "platform-tempo-" + mode.split("-")[-1] + "-distributor.monitoring.svc.cluster.local:4317"
    expect(traces.get("endpoint", "") == expected_endpoint, "Collector traces destination")
    items = deployments.get("items", [])
    expect(len(items) == 1, "Collector Deployment selection")
    deployment = items[0]; desired = deployment.get("spec", {}).get("replicas", 1); state = deployment.get("status", {})
    expect(desired > 0 and state.get("observedGeneration") == deployment["metadata"].get("generation")
           and state.get("updatedReplicas", 0) == desired and state.get("readyReplicas", 0) == desired
           and state.get("availableReplicas", 0) == desired, "Collector rollout readiness")
    return operation, sorted(pipelines), expected_endpoint

def collector_state(kube, revision, env, mode):
    app = query(kube + ["-n", "argocd", "get", "application", "platform-collection-gateway-" + env, "-o", "json"])
    configmap = query(kube + ["-n", "observability", "get", "configmap", "collection-gateway-opentelemetry-collector", "-o", "json"])
    try:
        config = parse_config(configmap["data"]["relay"], "Collector")
    except (KeyError, ValueError) as error:
        raise Inconclusive("Collector relay is missing or malformed") from None
    deployments = query(kube + ["-n", "observability", "get", "deployment", "-l", "app.kubernetes.io/instance=collection-gateway", "-o", "json"])
    return verify_collection(app, config, deployments, mode, revision, env)

def verify_contracts(before, after, values, backend, epoch):
    required = {"OBSERVABILITY_ACCOUNT": values["EXPECTED_ACCOUNT_ID"], "OBSERVABILITY_REGION": values["AWS_REGION"],
                "OBSERVABILITY_ENVIRONMENT": values["ENVIRONMENT"], "OBSERVABILITY_CLUSTER": values["QUEUE_EKS_CLUSTER"]}
    for name, value in required.items():
        expect(before.get(name) == value and after.get(name) == value, name)
    expect(before.keys() == after.keys(), "diagnostic contract fields")
    mutable = {"OBSERVABILITY_ACTIVE_TRACE_BACKEND", "OBSERVABILITY_STORAGE_EPOCH", "OBSERVABILITY_POLICY_HASH"}
    changed = {name for name in before if before[name] != after[name]}
    expect(changed <= mutable, "unchanged storage and identity coordinates")
    expect(after.get("OBSERVABILITY_ACTIVE_TRACE_BACKEND") == backend, "contract active trace backend")
    expect(after.get("OBSERVABILITY_STORAGE_EPOCH") == str(epoch), "contract storage epoch")
    expect(bool(re.fullmatch(r"[0-9a-f]{64}", after.get("OBSERVABILITY_POLICY_HASH", ""))), "contract policy hash")
    expect(after.get("OBSERVABILITY_TEMPO_ENDPOINT") == "http://platform-tempo-active-query.monitoring.svc.cluster.local:3200", "stable query endpoint")
    prefix = after.get("OBSERVABILITY_TRACES_PREFIX", "")
    expect(prefix == values["ENVIRONMENT"] + "/", "trace environment prefix")
    return prefix + "traces-epoch-" + str(epoch)

def verify_query_application(app, revision, env):
    spec = app.get("spec", {}); status = app.get("status", {})
    expect(spec.get("destination", {}).get("namespace") == "monitoring"
           and spec["destination"].get("server") == "https://kubernetes.default.svc", "query Application destination")
    expect(spec.get("source", {}).get("path") == "gitops/platform/tempo-active-query/overlays/" + env, "query Application source")
    expect(status.get("sync", {}).get("status") == "Synced" and status["sync"].get("revision") == revision, "query Application approved revision")
    operation = status.get("operationState", {})
    expect(operation.get("phase") == "Succeeded" and operation.get("syncResult", {}).get("revision") == revision, "query Application completed operation")

def verify_query(service, slices, release, backend):
    expect(service.get("metadata", {}).get("labels", {}).get("platform.example/active-trace-backend") == backend, "query Service backend label")
    selector = service.get("spec", {}).get("selector", {})
    expect(selector.get("app.kubernetes.io/instance") == release and selector.get("app.kubernetes.io/component") == "query-frontend", "query Service selector")
    endpoints = [endpoint for item in slices.get("items", []) for endpoint in item.get("endpoints", []) if endpoint.get("conditions", {}).get("ready") is True]
    expect(bool(endpoints), "query Ready EndpointSlice")
    expect(all(endpoint.get("targetRef", {}).get("kind") == "Pod" and endpoint["targetRef"].get("name", "").startswith(release + "-query-frontend-") for endpoint in endpoints), "query Ready target identity")

def verify_tempo(configmaps, bucket, prefix):
    configs = [parse_config(item["data"]["tempo.yaml"], "Tempo") for item in configmaps.get("items", []) if "tempo.yaml" in item.get("data", {})]
    expect(len(configs) == 1, "Tempo ConfigMap selection")
    s3 = configs[0].get("storage", {}).get("trace", {}).get("s3", {})
    expect(s3.get("bucket") == bucket and s3.get("prefix") == prefix, "Tempo object storage coordinates")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default=os.environ.get("APPROVED_GIT_REVISION", ""))
    commands = parser.add_subparsers(dest="command", required=True)
    collection = commands.add_parser("collection"); collection.add_argument("mode", choices=["pause", "resume-e2", "resume-e3"])
    switch = commands.add_parser("switch")
    switch.add_argument("--before", type=Path, required=True); switch.add_argument("--after", type=Path, required=True)
    switch.add_argument("--release", choices=["platform-tempo-e2", "platform-tempo-e3"], required=True)
    switch.add_argument("--backend", choices=["managed", "self-managed"], required=True)
    switch.add_argument("--epoch", type=int, choices=[2, 3], required=True)
    switch.add_argument("--skip-s3", action="store_true")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
            raise Inconclusive("APPROVED_GIT_REVISION must be the reviewed merge commit")
        values, kube = environment(); env = values["ENVIRONMENT"]
        if args.command == "collection":
            operation, pipelines, endpoint = collector_state(kube, args.revision, env, args.mode)
            directory = Path(__file__).resolve().parents[1] / "platform/environments" / env / "queue/local-inputs"
            directory.mkdir(parents=True, exist_ok=True); report = directory / "collection-switch.tsv"
            if report.is_symlink():
                raise Inconclusive("transition report cannot be a symlink")
            with report.open("a") as file:
                file.write(operation["startedAt"] + "\t" + args.mode + "\trequested\trevision=" + args.revision + "\n")
                file.write(operation["finishedAt"] + "\t" + args.mode + "\tready\trevision=" + args.revision + "\n")
            report.chmod(0o600)
            print("COLLECTION_" + args.mode.upper() + "_READY pipelines=" + json.dumps(pipelines, separators=(",", ":"))
                  + " traces_endpoint=" + (endpoint or "none") + " log=" + str(report))
            print("READ_ONLY_VERIFIED; timestamps are Argo operation evidence; trace delivery and losslessness are not proven")
        else:
            expect((args.release, args.backend, args.epoch) in {("platform-tempo-e2", "managed", 2), ("platform-tempo-e3", "self-managed", 3)}, "epoch/backend/release relation")
            before = read_context(args.before, component="observability"); after = read_context(args.after, component="observability")
            prefix = verify_contracts(before, after, values, args.backend, args.epoch)
            collector_state(kube, args.revision, env, "resume-e" + str(args.epoch))
            query_app = query(kube + ["-n", "argocd", "get", "application", "platform-tempo-active-query-" + env, "-o", "json"])
            verify_query_application(query_app, args.revision, env)
            service = query(kube + ["-n", "monitoring", "get", "service", "platform-tempo-active-query", "-o", "json"])
            slices = query(kube + ["-n", "monitoring", "get", "endpointslice", "-l", "kubernetes.io/service-name=platform-tempo-active-query", "-o", "json"])
            verify_query(service, slices, args.release, args.backend)
            configmaps = query(kube + ["-n", "monitoring", "get", "configmap", "-l", "app.kubernetes.io/instance=" + args.release, "-o", "json"])
            bucket = after.get("OBSERVABILITY_TRACES_BUCKET", ""); verify_tempo(configmaps, bucket, prefix)
            if args.skip_s3:
                raise Inconclusive("S3 observation was explicitly skipped")
            objects = query(["aws", "s3api", "list-objects-v2", "--region", values["AWS_REGION"], "--bucket", bucket, "--prefix", prefix + "/", "--max-keys", "20", "--output", "json"])
            expect(any(item.get("Key", "").startswith(prefix + "/") for item in objects.get("Contents", [])), "observed S3 epoch objects")
            print("PASS transition_contract_and_live_targets_match")
            print("OBSERVED_EPOCH_SWITCH backend=" + args.backend + " epoch=" + str(args.epoch) + " release=" + args.release + "; lossless_delivery_proven=false")
    except Difference as error:
        parser.exit(1, "FAIL " + str(error) + "\n")
    except (Inconclusive, ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(2, "INCONCLUSIVE " + str(error) + "\n")

if __name__ == "__main__":
    main()
