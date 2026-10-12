import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "automation"))
import read_diagnostic_context as reader
import verify_trace_transition as verify
import export_diagnostic_context as writer

SHA = "a" * 40
ENV = {"ENVIRONMENT": "dev", "EXPECTED_ACCOUNT_ID": "111111111111", "AWS_REGION": "ap-northeast-2", "QUEUE_EKS_CLUSTER": "dev-cluster", "KUBE_CONTEXT": "dev-context"}

def collection_fixture(mode="resume-e2"):
    overlay = "-paused" if mode == "pause" else "-e" + mode[-1]
    app = {"spec": {"destination": {"namespace": "observability", "server": "https://kubernetes.default.svc"}, "sources": [
        {"chart": "opentelemetry-collector", "targetRevision": "0.173.1", "helm": {"releaseName": "collection-gateway", "valueFiles": ["$values/gitops/platform/collection-gateway/values/dev.yaml", "$values/gitops/platform/collection-gateway/values/dev" + overlay + ".yaml"]}},
        {"ref": "values"}]}, "status": {"sync": {"status": "Synced", "revisions": ["0.173.1", SHA]}, "operationState": {"phase": "Succeeded", "syncResult": {"revisions": ["0.173.1", SHA]}, "startedAt": "2026-10-07T00:00:00Z", "finishedAt": "2026-10-07T00:01:00Z"}}}
    config = {"service": {"pipelines": {"logs": {"exporters": ["otlp_http/logs"]}, "metrics": {"exporters": ["prometheus"]}}}, "exporters": {
        "otlp_http/logs": {"endpoint": "http://platform-loki-gateway.logging.svc.cluster.local/otlp"}, "prometheus": {"endpoint": "0.0.0.0:8889"}}}
    if mode != "pause":
        config["service"]["pipelines"]["traces"] = {"exporters": ["otlp_grpc/traces"]}
        config["exporters"]["otlp_grpc/traces"] = {"endpoint": "platform-tempo-e" + mode[-1] + "-distributor.monitoring.svc.cluster.local:4317"}
    deployment = {"items": [{"metadata": {"generation": 2}, "spec": {"replicas": 3}, "status": {"observedGeneration": 2, "updatedReplicas": 3, "readyReplicas": 3, "availableReplicas": 3}}]}
    return app, config, deployment

def contracts():
    before = {"OBSERVABILITY_ACCOUNT": ENV["EXPECTED_ACCOUNT_ID"], "OBSERVABILITY_REGION": ENV["AWS_REGION"], "OBSERVABILITY_ENVIRONMENT": "dev", "OBSERVABILITY_CLUSTER": ENV["QUEUE_EKS_CLUSTER"], "OBSERVABILITY_ACTIVE_TRACE_BACKEND": "self-managed", "OBSERVABILITY_STORAGE_EPOCH": "3", "OBSERVABILITY_POLICY_HASH": "b" * 64, "OBSERVABILITY_TEMPO_ENDPOINT": "http://platform-tempo-active-query.monitoring.svc.cluster.local:3200", "OBSERVABILITY_TRACES_BUCKET": "dev-traces-bucket", "OBSERVABILITY_TRACES_PREFIX": "dev/"}
    after = dict(before, OBSERVABILITY_ACTIVE_TRACE_BACKEND="managed", OBSERVABILITY_STORAGE_EPOCH="2", OBSERVABILITY_POLICY_HASH="c" * 64)
    return before, after

class DiagnosticContextReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "coordinates.env"

    def test_actual_writer_quoted_empty_and_plain_values_round_trip(self):
        values = {"OBSERVABILITY_ACCOUNT": "111111111111", "OBSERVABILITY_TRACES_PREFIX": "dev/", "GATEWAY_DNS_ZONE_NAME": "dev.example.test", "DATA_REDIS_ADDRESS": ""}
        writer.write_context(self.path, values)
        self.assertTrue(self.path.read_text().splitlines()[1].startswith("export "))
        self.assertEqual(reader.read_context(self.path), values)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_duplicate_field_is_rejected(self):
        self.path.write_text("OBSERVABILITY_ACCOUNT=111111111111\nexport OBSERVABILITY_ACCOUNT=111111111111\n")
        with self.assertRaisesRegex(ValueError, "duplicate"): reader.read_context(self.path)

    def test_unknown_or_secret_field_is_rejected_without_echoing_value(self):
        for line in ["OTHER_COORDINATE=private-value", "QUEUE_PASSWORD=private-value"]:
            self.path.write_text(line)
            with self.assertRaises(ValueError) as caught: reader.read_context(self.path)
            self.assertNotIn("private-value", str(caught.exception))

    def test_shell_substitution_never_executes(self):
        marker = Path(self.temp.name) / "marker"
        self.path.write_text("OBSERVABILITY_CLUSTER=$(touch " + str(marker) + ")")
        with self.assertRaisesRegex(ValueError, "literal"): reader.read_context(self.path)
        self.assertFalse(marker.exists())

    def test_malformed_and_credential_shaped_values_rejected(self):
        for line in ["export OBSERVABILITY_CLUSTER='unclosed", "OBSERVABILITY_CLUSTER=one two", "OBSERVABILITY_CLUSTER='-----BEGIN PRIVATE KEY-----'", "OBSERVABILITY_CLUSTER=AKIAABCDEFGHIJKLMNOP"]:
            self.path.write_text(line)
            with self.assertRaises(ValueError): reader.read_context(self.path)

    def test_component_boundary_and_symlink_are_rejected(self):
        writer.write_context(self.path, {"GATEWAY_DNS_ZONE_NAME": "dev.example.test"})
        with self.assertRaises(ValueError): reader.read_context(self.path, component="observability")
        link = Path(self.temp.name) / "link.env"; link.symlink_to(self.path)
        with self.assertRaises(ValueError): reader.read_context(link)

    def test_cli_reads_export_prefix_actual_writer(self):
        writer.write_context(self.path, {"OBSERVABILITY_TRACES_PREFIX": "dev/"})
        output = io.StringIO()
        with patch.object(sys, "argv", ["read_diagnostic_context.py", "--file", str(self.path), "--field", "OBSERVABILITY_TRACES_PREFIX"]), redirect_stdout(output): reader.main()
        self.assertEqual(output.getvalue(), "dev/\n")

class TraceTransitionVerifierTests(unittest.TestCase):
    def test_paused_and_both_epochs_are_verified(self):
        for mode in ["pause", "resume-e2", "resume-e3"]:
            app, config, deployment = collection_fixture(mode)
            verify.verify_collection(app, config, deployment, mode, SHA, "dev")

    def test_shared_traces_source_allowed_only_with_matching_live_mode(self):
        app, config, deployment = collection_fixture("resume-e2")
        app["spec"]["sources"][0]["helm"]["valueFiles"][1] = "$values/gitops/platform/collection-gateway/values/dev-traces.yaml"
        verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")
        with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "pause", SHA, "dev")

    def test_wrong_source_revision_or_partial_operation_is_rejected(self):
        for field in ["revision", "operation", "destination", "source"]:
            app, config, deployment = collection_fixture()
            if field == "revision": app["status"]["sync"]["revisions"][1] = "d" * 40
            if field == "operation": app["status"]["operationState"]["phase"] = "Running"
            if field == "destination": app["spec"]["destination"]["namespace"] = "other"
            if field == "source": app["spec"]["sources"][0]["helm"]["valueFiles"].append("$values/gitops/platform/collection-gateway/values/dev-e3.yaml")
            with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_stale_generation_or_partial_rollout_is_rejected(self):
        for field in ["observedGeneration", "updatedReplicas", "readyReplicas", "availableReplicas"]:
            app, config, deployment = collection_fixture(); deployment["items"][0]["status"][field] = 1
            with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_every_current_and_completed_source_revision_must_match(self):
        bad_arrays = [["0.173.0", SHA], [SHA], ["0.173.1", SHA, SHA],
                      [SHA, "0.173.1"], ["0.173.1", "d" * 40], None,
                      {"0": "0.173.1", "1": SHA}]
        for location in ["current", "completed"]:
            for revisions in bad_arrays:
                with self.subTest(location=location, revisions=revisions):
                    app, config, deployment = collection_fixture()
                    target = app["status"]["sync"] if location == "current" else app["status"]["operationState"]["syncResult"]
                    target["revisions"] = revisions
                    with self.assertRaises(verify.Difference):
                        verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_source_order_is_used_for_both_revision_arrays(self):
        app, config, deployment = collection_fixture()
        app["spec"]["sources"].reverse()
        app["status"]["sync"]["revisions"] = [SHA, "0.173.1"]
        app["status"]["operationState"]["syncResult"]["revisions"] = [SHA, "0.173.1"]
        verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")
        app["status"]["operationState"]["syncResult"]["revisions"] = ["0.173.1", SHA]
        with self.assertRaises(verify.Difference):
            verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_previous_success_does_not_authorize_new_out_of_sync_desired_state(self):
        app, config, deployment = collection_fixture()
        app["status"]["sync"]["status"] = "OutOfSync"
        # The previous approved operation still succeeded; the next transition is held.
        with self.assertRaises(verify.Difference):
            verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_unapproved_chart_source_set_and_failed_operation_are_rejected(self):
        for case in ["chart", "extra-source", "missing-source", "malformed-source", "failed", "error", "running"]:
            with self.subTest(case=case):
                app, config, deployment = collection_fixture()
                if case == "chart": app["spec"]["sources"][0]["targetRevision"] = "0.173.0"
                if case == "extra-source": app["spec"]["sources"].append({"ref": "other"})
                if case == "missing-source": app["spec"]["sources"].pop(0)
                if case == "malformed-source": app["spec"]["sources"][0] = None
                if case in {"failed", "error", "running"}: app["status"]["operationState"]["phase"] = case.title()
                with self.assertRaises(verify.Difference):
                    verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_wrong_trace_endpoint_or_lost_nontrace_pipeline_is_rejected(self):
        app, config, deployment = collection_fixture(); config["exporters"]["otlp_grpc/traces"]["endpoint"] = "platform-tempo-e3-distributor.monitoring.svc.cluster.local:4317"
        with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")
        app, config, deployment = collection_fixture(); del config["service"]["pipelines"]["logs"]
        with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")

    def test_contract_actual_environment_prefix_and_immutable_coordinates(self):
        before, after = contracts()
        self.assertEqual(verify.verify_contracts(before, after, ENV, "managed", 2), "dev/traces-epoch-2")
        for field, value in [("OBSERVABILITY_TRACES_BUCKET", "prod-bucket"), ("OBSERVABILITY_TRACES_PREFIX", "dev/traces"), ("OBSERVABILITY_ACCOUNT", "222222222222")]:
            bad = dict(after); bad[field] = value
            with self.assertRaises(verify.Difference): verify.verify_contracts(before, bad, ENV, "managed", 2)

    def test_ready_query_target_must_belong_to_selected_epoch(self):
        service = {"metadata": {"labels": {"platform.example/active-trace-backend": "managed"}}, "spec": {"selector": {"app.kubernetes.io/instance": "platform-tempo-e2", "app.kubernetes.io/component": "query-frontend"}}}
        slices = {"items": [{"endpoints": [{"conditions": {"ready": True}, "targetRef": {"kind": "Pod", "name": "platform-tempo-e2-query-frontend-abc"}}]}]}
        verify.verify_query(service, slices, "platform-tempo-e2", "managed")
        slices["items"][0]["endpoints"][0]["targetRef"]["name"] = "platform-tempo-e3-query-frontend-abc"
        with self.assertRaises(verify.Difference): verify.verify_query(service, slices, "platform-tempo-e2", "managed")
        slices["items"][0]["endpoints"] = []
        with self.assertRaises(verify.Difference): verify.verify_query(service, slices, "platform-tempo-e2", "managed")

    def test_tempo_storage_does_not_follow_an_incorrect_epoch(self):
        configmaps = {"items": [{"data": {"tempo.yaml": "storage:\n  trace:\n    s3:\n      bucket: dev-traces-bucket\n      prefix: dev/traces-epoch-2\n"}}]}
        verify.verify_tempo(configmaps, "dev-traces-bucket", "dev/traces-epoch-2")
        with self.assertRaises(verify.Difference): verify.verify_tempo(configmaps, "dev-traces-bucket", "dev/traces-epoch-3")

    def test_exporter_binding_and_malformed_config_never_pass(self):
        app, config, deployment = collection_fixture()
        config["service"]["pipelines"]["logs"]["exporters"] = ["otlp_grpc/traces"]
        with self.assertRaises(verify.Difference): verify.verify_collection(app, config, deployment, "resume-e2", SHA, "dev")
        with self.assertRaises(verify.Inconclusive) as caught: verify.parse_config("credentials: [private-value", "Tempo")
        self.assertNotIn("private-value", str(caught.exception))

    def test_api_failure_is_inconclusive_and_response_not_logged(self):
        failure = __import__("subprocess").CalledProcessError(1, ["aws"], output="credential-sensitive-output", stderr="credential-sensitive-output")
        with patch.object(verify.subprocess, "run", side_effect=failure):
            with self.assertRaises(verify.Inconclusive) as caught: verify.query(["aws", "s3api", "list-objects-v2"])
        self.assertNotIn("credential-sensitive-output", str(caught.exception))

    def test_wrong_account_stops_before_cluster_lookup(self):
        calls = []
        def fake(command, **kwargs): calls.append(command); return "222222222222"
        with patch.dict(os.environ, ENV), patch.object(verify, "query", side_effect=fake):
            with self.assertRaises(verify.Difference): verify.environment()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["aws", "sts", "get-caller-identity"])

    def test_cluster_endpoint_query_uses_native_response_field(self):
        calls = []
        def fake(command, **kwargs):
            calls.append(command)
            if command[:3] == ["aws", "sts", "get-caller-identity"]: return "111111111111"
            if command[:3] == ["aws", "eks", "describe-cluster"]:
                self.assertEqual(command[command.index("--query") + 1], "cluster.endpoint")
                return "https://approved-api"
            self.assertEqual(command[:3], ["kubectl", "config", "view"])
            return "https://approved-api"
        with patch.dict(os.environ, ENV), patch.object(verify, "query", side_effect=fake):
            verify.environment()
        self.assertEqual(len(calls), 3)

    def test_context_mismatch_is_rejected(self):
        with patch.dict(os.environ, ENV), patch.object(verify, "query", side_effect=["111111111111", "https://approved-api", "https://other-api"]):
            with self.assertRaises(verify.Difference): verify.environment()

    def test_query_application_must_match_the_same_reviewed_revision(self):
        app = {"spec": {"destination": {"namespace": "monitoring", "server": "https://kubernetes.default.svc"}, "source": {"path": "gitops/platform/tempo-active-query/overlays/dev"}}, "status": {"sync": {"status": "Synced", "revision": SHA}, "operationState": {"phase": "Succeeded", "syncResult": {"revision": SHA}}}}
        verify.verify_query_application(app, SHA, "dev")
        app["status"]["sync"]["revision"] = "d" * 40
        with self.assertRaises(verify.Difference): verify.verify_query_application(app, SHA, "dev")

    def test_full_switch_cli_success_and_skipped_storage_are_distinct(self):
        before, after = contracts()
        app = {"spec": {"destination": {"namespace": "monitoring", "server": "https://kubernetes.default.svc"}, "source": {"path": "gitops/platform/tempo-active-query/overlays/dev"}}, "status": {"sync": {"status": "Synced", "revision": SHA}, "operationState": {"phase": "Succeeded", "syncResult": {"revision": SHA}}}}
        service = {"metadata": {"labels": {"platform.example/active-trace-backend": "managed"}}, "spec": {"selector": {"app.kubernetes.io/instance": "platform-tempo-e2", "app.kubernetes.io/component": "query-frontend"}}}
        slices = {"items": [{"endpoints": [{"conditions": {"ready": True}, "targetRef": {"kind": "Pod", "name": "platform-tempo-e2-query-frontend-abc"}}]}]}
        configs = {"items": [{"data": {"tempo.yaml": "storage:\n  trace:\n    s3:\n      bucket: dev-traces-bucket\n      prefix: dev/traces-epoch-2\n"}}]}
        with tempfile.TemporaryDirectory() as directory:
            b = Path(directory) / "before.env"; a = Path(directory) / "after.env"
            writer.write_context(b, before); writer.write_context(a, after)
            args = ["verify_trace_transition.py", "--revision", SHA, "switch", "--before", str(b), "--after", str(a), "--release", "platform-tempo-e2", "--backend", "managed", "--epoch", "2"]
            for skipped in [False, True]:
                output = io.StringIO(); responses = [app, service, slices, configs, {"Contents": [{"Key": "dev/traces-epoch-2/block/meta.json"}]}]
                with patch.object(sys, "argv", args + (["--skip-s3"] if skipped else [])), patch.object(verify, "environment", return_value=(ENV, ["kubectl"])), patch.object(verify, "collector_state"), patch.object(verify, "query", side_effect=responses) as queries, redirect_stdout(output), redirect_stderr(io.StringIO()):
                    if skipped:
                        with self.assertRaises(SystemExit) as caught: verify.main()
                        self.assertEqual(caught.exception.code, 2); self.assertNotIn("PASS", output.getvalue())
                    else:
                        verify.main(); self.assertIn("PASS transition_contract_and_live_targets_match", output.getvalue())
                        self.assertIn("lossless_delivery_proven=false", output.getvalue())
                for call in queries.call_args_list:
                    command = call.args[0]
                    self.assertFalse(any(word in command for word in ["apply", "patch", "delete", "upgrade", "sync"]))

    def test_missing_approved_revision_stops_before_all_external_queries(self):
        with patch.object(sys, "argv", ["verify_trace_transition.py", "collection", "pause"]), patch.dict(os.environ, {"APPROVED_GIT_REVISION": ""}), patch.object(verify, "query") as query, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught: verify.main()
        self.assertEqual(caught.exception.code, 2); query.assert_not_called()

if __name__ == "__main__": unittest.main()
