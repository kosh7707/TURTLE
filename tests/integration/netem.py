#!/usr/bin/env python3
"""Environment-safe integration checks for the netem coordinator."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_runner(path):
    spec = importlib.util.spec_from_file_location("turtle_netem_study", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_turtle(path):
    path.write_text("""#!/usr/bin/env python3
import json,os,socket,sys
args=sys.argv[1:]
manifest=json.load(open(args[args.index('--network-manifest')+1]))
assert set(manifest['namespace_fds']) in ({'client','server'},{'client','server','ca'})
expected=list(manifest['namespace_fds'].values())+[manifest['phase_control_fd']]
for fd in expected: os.fstat(fd)
assert len(set(expected)) == len(expected)
sock=socket.socket(fileno=manifest['phase_control_fd'])
for phase,edge in [('setup','begin'),('setup','end'),('scenario','begin'),('scenario','end'),('cleanup','begin'),('cleanup','end')]:
    row={'type':'phase','schema':1,'attempt':1,'phase':phase,'edge':edge}
    sock.sendall(json.dumps(row,separators=(',',':')).encode()+b'\\n')
    data=b''
    while not data.endswith(b'\\n'): data += sock.recv(4096)
    ack=json.loads(data)
    assert ack == {**row,'type':'ack','observation_id':f'1:{phase}:{edge}'}
""")
    path.chmod(0o755)


def fake_hanging_turtle(path, close_phase):
    path.write_text(f"""#!/usr/bin/env python3
import json,os,pathlib,socket,subprocess,sys,time
args=sys.argv[1:]; out=pathlib.Path(args[args.index('--output')+1])
manifest=json.load(open(args[args.index('--network-manifest')+1]))
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
(out/'owned-descendant.pid').write_text(str(child.pid))
fd=manifest['phase_control_fd']
{'os.close(fd)' if close_phase else 'hold=socket.socket(fileno=fd)'}
time.sleep(60)
""")
    path.chmod(0o755)


def fake_partial_timeout_turtle(path):
    path.write_text("""#!/usr/bin/env python3
import json,socket,sys
args=sys.argv[1:]; manifest=json.load(open(args[args.index('--network-manifest')+1]))
sock=socket.socket(fileno=manifest['phase_control_fd'])
for phase,edge in [('setup','begin'),('cleanup','begin')]:
    row={'type':'phase','schema':1,'attempt':1,'phase':phase,'edge':edge}
    sock.sendall(json.dumps(row,separators=(',',':')).encode()+b'\\n')
    data=b''
    while not data.endswith(b'\\n'): data += sock.recv(4096)
sock.close(); raise SystemExit(1)
""")
    path.chmod(0o755)


def main():
    script = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).parents[2] / "scripts/netem-study.py"
    runner = load_runner(script)
    with tempfile.TemporaryDirectory(prefix="turtle-netem-test-") as temporary:
        root = Path(temporary)
        object_file = root / "object.pem"; object_file.write_bytes(b"line one\nline two\n")
        snapshot = runner.make_snapshot(object_file)
        check(snapshot == {"type": "turtle-lookup-cache", "schema": 1,
                           "object_id": runner.fnv1a64(object_file.read_bytes()),
                           "object_size": 18,
                           "object_hex": "6c696e65206f6e650a6c696e652074776f0a"},
              "snapshot schema or raw-byte identity changed")
        snapshot_file = root / "snapshot.json"
        subprocess.run([sys.executable, script, "snapshot", "--object", object_file,
                        "--output", snapshot_file], check=True)
        duplicate = subprocess.run([sys.executable, script, "snapshot", "--object", object_file,
                                    "--output", snapshot_file], capture_output=True)
        check(duplicate.returncode != 0, "snapshot overwrote an existing artifact")

        profile = runner.default_net_profile()
        check(runner.validate_net_profile(profile) == profile, "valid fixed profile changed")
        bad = json.loads(json.dumps(profile)); bad["paths"].pop("tls_s2c")
        try: runner.validate_net_profile(bad)
        except ValueError: pass
        else: raise RuntimeError("missing directional path was accepted")
        tls_profile = json.loads(json.dumps(profile))
        tls_profile["paths"] = {name: tls_profile["paths"][name]
                                for name in ("tls_c2s", "tls_s2c")}
        check(runner.validate_net_profile(tls_profile) == tls_profile,
              "valid TLS-only profile was rejected")
        legacy_profile = json.loads(json.dumps(profile))
        legacy_profile["paths"]["ca_c2s"]["delay_ms"] = 777
        legacy_profile["paths"]["ca_s2c"]["loss_percent"] = 99.0
        check(runner.active_net_profile(runner.validate_net_profile(legacy_profile), False) == tls_profile,
              "inactive legacy CA settings entered the pure TLS condition identity")
        try: runner.validate_net_profile(tls_profile, True)
        except ValueError: pass
        else: raise RuntimeError("lookup topology accepted a TLS-only network profile")
        for malformed_lookup in ({"lookup": {"enabled": 1}}, {"lookup": {"enabled": "false"}},
                                 {"lookup": False}, {"lookup": None}):
            try: runner.profile_lookup_enabled(malformed_lookup)
            except ValueError: pass
            else: raise RuntimeError("non-boolean lookup.enabled was accepted")
        check(not runner.profile_lookup_enabled({}) and
              not runner.profile_lookup_enabled({"lookup": {"enabled": False}}) and
              runner.profile_lookup_enabled({"lookup": {"enabled": True}}),
              "lookup.enabled default or boolean parsing changed")
        seeded = json.loads(json.dumps(profile)); seeded["loss_seed"] = 7
        try: runner.validate_net_profile(seeded)
        except runner.SetupUnsupported: pass
        else: raise RuntimeError("unsupported loss seed was silently accepted")
        check(runner.resolve_samples({}, None) == 1000, "runner no longer matches the core sample default")
        check(runner.resolve_samples({"measurement": {"samples": 17}}, None) == 17,
              "profile sample count was not used")
        check(runner.resolve_samples({"measurement": {"samples": 17}}, 3) == 3,
              "explicit sample override lost precedence")

        failed_command = subprocess.CompletedProcess(["ip"], 1, "", "denied")
        with mock.patch.object(runner.subprocess, "run", return_value=failed_command):
            unobserved = runner.host_network_identity()
        check(not unobserved["supported"] and unobserved["errors"],
              "host observation command failure lost its reason")
        check(runner.compare_host_identity(unobserved, unobserved) is None,
              "two unsupported host observations were claimed unchanged")

        # Opening /proc/<pid>/ns/net before unshare+exec completes captures the
        # coordinator namespace. Under parallel load that made the observer
        # enter a namespace without rctls. The child readiness byte is the
        # ordering boundary; a fixed sleep is not.
        delayed = runner.OwnedTopology.__new__(runner.OwnedTopology)
        delayed.helpers = {}; delayed.ns_fds = {}
        delayed.provenance = {"lifecycle": {"helpers": {}}}
        ready = threading.Event(); writers = []
        class DelayedChild:
            pid = os.getpid()
            stderr = None
            returncode = None
            @staticmethod
            def poll(): return None
        def delayed_popen(*_args, **kwargs):
            write_fd = os.dup(kwargs["pass_fds"][0])
            def signal_ready():
                time.sleep(.05); ready.set(); os.write(write_fd, b"R"); os.close(write_fd)
            writer = threading.Thread(target=signal_ready); writer.start(); writers.append(writer)
            return DelayedChild()
        real_open = os.open
        def ordered_open(path, flags):
            check(ready.is_set(), "namespace fd opened before helper readiness")
            return real_open(path, flags)
        with mock.patch.object(runner.subprocess, "Popen", side_effect=delayed_popen), \
             mock.patch.object(runner.os, "open", side_effect=ordered_open):
            delayed._start_namespace_helper("delayed", os.stat("/proc/self/ns/user").st_ino)
        for writer in writers: writer.join()
        os.close(delayed.ns_fds["delayed"])
        check(set(delayed.provenance["lifecycle"]["helpers"]) == {"delayed"},
              "ready helper was not recorded after its namespace fd opened")

        # Cleanup continues after one fd-close failure and promotes an otherwise
        # successful run to cleanup-failed. No host resource is modified.
        cleanup_dir = root / "cleanup-fixture"; cleanup_dir.mkdir()
        topology = runner.OwnedTopology.__new__(runner.OwnedTopology)
        topology.output = cleanup_dir; topology.marker = None; topology.observer = None
        topology.helpers = {}; first_fd, first_write = os.pipe(); second_fd, second_write = os.pipe()
        topology.ns_fds = {"first": first_fd, "second": second_fd}
        topology.provenance = {"type": "turtle-network-provenance", "schema": 1,
                               "status": "complete", "reason": None,
                               "cleanup": [], "lifecycle": {}}
        real_close = os.close; closed = []
        def close_boundary(fd):
            if fd == first_fd: raise OSError("injected close failure")
            closed.append(fd); real_close(fd)
        with mock.patch.object(runner.os, "close", side_effect=close_boundary):
            failures = topology.cleanup()
        check(failures and second_fd in closed, "cleanup stopped after the first fd-close failure")
        check(topology.provenance["status"] == "cleanup-failed" and
              not topology.provenance["lifecycle"]["namespace_fds_closed"],
              "fd-close failure was masked as successful cleanup")
        real_close(first_fd); real_close(first_write); real_close(second_write)

        save_topology = runner.OwnedTopology.__new__(runner.OwnedTopology)
        save_topology.output = cleanup_dir; save_topology.marker = None; save_topology.observer = None
        save_topology.helpers = {}; save_topology.ns_fds = {}
        save_topology.provenance = {"type": "turtle-network-provenance", "schema": 1,
                                    "status": "complete", "reason": None,
                                    "cleanup": [], "lifecycle": {}}
        save_topology.save = lambda: (_ for _ in ()).throw(OSError("injected save failure"))
        save_failures = save_topology.cleanup()
        check(any("provenance save failed" in item for item in save_failures) and
              save_topology.provenance["status"] == "cleanup-failed",
              "final provenance failure was masked")
        check((cleanup_dir / "network-cleanup-errors.json").is_file(),
              "independent cleanup failure evidence was not attempted")
        check((cleanup_dir / "network-provenance.partial.json").is_file(),
              "first terminal cause was not preserved after provenance save failure")

        def write_integrity_provenance(directory, *, unchanged=True, cleanup_failed=False):
            directory.mkdir()
            value = {"type": "turtle-network-provenance", "schema": 1,
                     "status": "cleanup-failed" if cleanup_failed else "complete",
                     "reason": "cleanup failed" if cleanup_failed else None,
                     "director": {"returncode": 0},
                     "host_network_identity": {
                         "before": {"supported": True}, "after": {"supported": True},
                         "unchanged": unchanged},
                     "lifecycle": {"namespace_fds_closed": not cleanup_failed,
                                   "owned_pipe_fds_closed": True},
                     "cleanup": [],
                     "secondary_cleanup_failures": ["injected"] if cleanup_failed else []}
            (directory / "network-provenance.json").write_text(json.dumps(value))

        host_changed = root / "host-changed"; write_integrity_provenance(host_changed, unchanged=False)
        ok, integrity_reasons = runner.evaluate_run_integrity(
            {"output": str(host_changed), "returncode": 0, "gate": "diagnostic"})
        check(not ok and any("host network identity" in reason for reason in integrity_reasons),
              "positive artifacts with changed host identity passed integrity")
        cleanup_failed = root / "cleanup-failed"; write_integrity_provenance(cleanup_failed, cleanup_failed=True)
        ok, integrity_reasons = runner.evaluate_run_integrity(
            {"output": str(cleanup_failed), "returncode": 0, "gate": "diagnostic"})
        check(not ok and any("cleanup" in reason for reason in integrity_reasons),
              "positive artifacts with failed cleanup passed integrity")

        null_qdisc = root / "null-qdisc"; null_qdisc.mkdir()
        ledger_rows = [
            {"record_kind": "run_config", "requested_count": 1},
            {"record_kind": "attempt_started", "attempt_id": 1},
            {"record_kind": "attempt_final", "attempt_id": 1, "final_status": "success",
             "failure_phase": "exit"},
            {"record_kind": "run_summary", "requested": 1, "started": 1},
        ]
        (null_qdisc / "attempts.jsonl").write_text("".join(json.dumps(row) + "\n" for row in ledger_rows))
        observation_rows = [
            {"phase": "scenario", "edge": "begin", "attempt": 1, "qdiscs": None},
            {"phase": "scenario", "edge": "end", "attempt": 1, "qdiscs": None},
        ]
        (null_qdisc / "network-observations.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in observation_rows))
        (null_qdisc / "packets.jsonl").write_text(json.dumps({
            "record_kind": "packet", "logical_path": "ca_s2c",
            "flow": {"source": runner.ADDRESSES["ca"], "destination": runner.ADDRESSES["client_ca"]},
            "tcp": {"payload_length": 100}}) + "\n")
        (null_qdisc / "network-provenance.json").write_text(json.dumps({
            "condition_identity": {"topology": {"addresses": runner.ADDRESSES}}}))
        sample = null_qdisc / "sample-000001"; sample.mkdir()
        (sample / "ca.jsonl").write_text(json.dumps({
            "record_kind": "connection_summary", "tcp_start": {"total_retrans": 0},
            "tcp_end": {"total_retrans": 1}}) + "\n")
        proven, loss_reasons = runner.evaluate_loss_gate(null_qdisc, 1)
        check(not proven and any("qdisc window missing" in reason for reason in loss_reasons),
              "null qdisc observation crashed or passed the loss gate")
        ledger_rows[2].update(final_status="timeout", failure_phase="listener")
        (null_qdisc / "attempts.jsonl").write_text("".join(json.dumps(row) + "\n" for row in ledger_rows))
        _, _, window_details = runner.evaluate_loss_gate_with_details(null_qdisc, 1)
        check(window_details == [{"attempt": 1, "status": "not-applicable-before-scenario",
                                  "failure_phase": "listener"}],
              "pre-scenario setup timeout was treated as a zero or missing scenario measurement")

        build = root / "build"; build.mkdir(); fake_turtle(build / "turtle")
        profile_file = root / "profile.json"; profile_file.write_text(json.dumps({
            "measurement": {"samples": 1}, "lookup": {"enabled": True}}))
        net_file = root / "net.json"; net_file.write_text(json.dumps(profile))
        output = root / "run"
        result = subprocess.run([sys.executable, script, "run", "--build", build,
                                 "--profile", profile_file, "--net-profile", net_file,
                                 "--samples", "1", "--output", output])
        check(result.returncode == 0, f"owned isolated run failed: {result.returncode}")
        provenance = json.loads((output / "network-provenance.json").read_text())
        check(provenance["status"] == "complete", "coordinator did not complete")
        check(provenance["host_network_identity"]["unchanged"], "host network identity changed")
        integrity_ok, integrity_reasons = runner.evaluate_run_integrity(
            {"output": str(output), "returncode": 0, "gate": "diagnostic"})
        check(integrity_ok, f"complete owned run failed integrity: {integrity_reasons}")
        check(provenance["director"]["pass_fds"] == [
            provenance["lifecycle"]["helpers"][x]["fd"] for x in ("client", "server", "ca")
        ] + [json.loads((output / "network-manifest.json").read_text())["phase_control_fd"]],
              "pass_fds and manifest integer identities differ")
        check(not provenance["director"]["router_fd_passed"], "router namespace fd leaked to director")
        check(provenance["lifecycle"]["namespace_fds_closed"], "namespace fds were not closed")
        text = json.dumps(provenance["condition_identity"])
        check(all(field not in text for field in ('"handle"', '"drops"', '"packets"', '"pid"', '"fd"')),
              "stable condition identity contains ephemeral or outcome fields")
        observations = [json.loads(line) for line in (output / "network-observations.jsonl").read_text().splitlines()]
        check([row["observation_id"] for row in observations] == [
            "1:setup:begin", "1:setup:end", "1:scenario:begin", "1:scenario:end",
            "1:cleanup:begin", "1:cleanup:end"],
              "phase observation order or identities changed")
        packets = [json.loads(line) for line in (output / "packets.jsonl").read_text().splitlines()]
        check(packets[0]["packet_unit"] == "observed-skb-not-physical-wire", "packet provenance overclaims")
        check(packets[-1]["record_kind"] == "footer", "capture drop-count footer missing")
        before_duplicate = {path.relative_to(output): path.read_bytes()
                            for path in output.rglob("*") if path.is_file()}
        duplicate_run = subprocess.run([sys.executable, script, "run", "--build", build,
                                        "--profile", profile_file, "--net-profile", net_file,
                                        "--samples", "1", "--output", output], capture_output=True)
        after_duplicate = {path.relative_to(output): path.read_bytes()
                           for path in output.rglob("*") if path.is_file()}
        check(duplicate_run.returncode == 2 and before_duplicate == after_duplicate,
              "rejected duplicate run modified prior output artifacts")

        pure_profile_file = root / "pure-profile.json"
        pure_profile_file.write_text(json.dumps({"measurement": {"samples": 1},
                                                 "lookup": {"enabled": False}}))
        pure_net_file = root / "pure-net.json"; pure_net_file.write_text(json.dumps(tls_profile))
        pure_output = root / "pure-run"
        pure_result = subprocess.run([sys.executable, script, "run", "--build", build,
                                      "--profile", pure_profile_file, "--net-profile", pure_net_file,
                                      "--samples", "1", "--output", pure_output])
        check(pure_result.returncode == 0, f"pure TLS isolated run failed: {pure_result.returncode}")
        pure_provenance = json.loads((pure_output / "network-provenance.json").read_text())
        pure_manifest = json.loads((pure_output / "network-manifest.json").read_text())
        check(pure_provenance["condition_identity"]["topology"] == {
                  "kind": "three-netns-receiver-facing-router-egress",
                  "addresses": runner.TLS_ADDRESSES, "interfaces": runner.TLS_INTERFACES},
              "pure TLS topology identity is not the fixed three-namespace inventory")
        check(set(pure_provenance["lifecycle"]["helpers"]) == {"client", "server", "router"},
              "pure TLS created a CA namespace helper")
        check(set(pure_manifest["namespace_fds"]) == {"client", "server"} and
              set(pure_manifest["addresses"]) == set(runner.TLS_ADDRESSES) and
              set(pure_manifest["interfaces"]) == set(runner.TLS_INTERFACES),
              "pure TLS manifest retained CA fields")
        check(set(pure_manifest["net_profile"]["paths"]) == set(runner.TLS_PATHS) and
              set(pure_provenance["condition_identity"]["actual"]["paths"]) == set(runner.TLS_PATHS) and
              set(pure_provenance["applied_qdisc_readback"]) == set(runner.TLS_PATHS),
              "pure TLS applied or claimed inactive CA qdiscs")
        pure_commands = [entry.get("argv", []) for entry in pure_provenance["commands"]]
        command_text = json.dumps(pure_commands)
        check(all(name not in command_text for name in ("cca", "rcca", "ca0", "rca0", "10.203.3", "10.203.4")),
              "pure TLS issued a CA link, route, offload, MTU, or qdisc command")
        check(pure_provenance["director"]["pass_fds"] == [
                  pure_provenance["lifecycle"]["helpers"][x]["fd"] for x in ("client", "server")
              ] + [pure_manifest["phase_control_fd"]],
              "pure TLS passed an unexpected namespace fd")
        check([row["observation_id"] for row in
               map(json.loads, (pure_output / "network-observations.jsonl").read_text().splitlines())] == [
                  "1:setup:begin", "1:setup:end", "1:scenario:begin", "1:scenario:end",
                  "1:cleanup:begin", "1:cleanup:end"],
              "pure TLS changed the canonical six phase observations")

        unsupported = json.loads(json.dumps(profile)); unsupported["loss_seed"] = 9
        unsupported_file = root / "unsupported.json"; unsupported_file.write_text(json.dumps(unsupported))
        unsupported_output = root / "unsupported-run"
        unsupported_result = subprocess.run([sys.executable, script, "run", "--build", build,
                                             "--profile", profile_file, "--net-profile", unsupported_file,
                                             "--samples", "1", "--output", unsupported_output])
        check(unsupported_result.returncode == 2, "unsupported explicit loss seed did not exit 2")
        unsupported_provenance = json.loads((unsupported_output / "network-provenance.json").read_text())
        check(unsupported_provenance["status"] == "unsupported", "unsupported setup provenance missing")

        # A failed director may close the phase fd immediately before exit.
        # Preserve skipped/trailing windows, but do not misclassify prompt exit
        # as an observer protocol failure.
        partial_build = root / "partial-build"; partial_build.mkdir()
        fake_partial_timeout_turtle(partial_build / "turtle")
        partial_output = root / "partial-run"
        partial_result = subprocess.run([sys.executable, script, "run", "--build", partial_build,
                                         "--profile", profile_file, "--net-profile", net_file,
                                         "--samples", "1", "--output", partial_output])
        check(partial_result.returncode == 1, "failed director return code was not retained")
        partial_provenance = json.loads((partial_output / "network-provenance.json").read_text())
        check(partial_provenance["status"] == "director-failed" and partial_provenance["reason"] is None,
              "prompt EOF/exit race was misclassified as runner error")
        check(partial_provenance["partial_phase_windows"] == [
            "1:setup:end:missing", "1:scenario:begin:missing", "1:scenario:end:missing",
            "1:cleanup:end:missing"], "partial phase windows were not preserved")
        check(partial_provenance["lifecycle"]["namespace_fds_closed"], "partial exit leaked namespace FDs")

        # EOF while an owned descendant is alive must kill the director group.
        eof_build = root / "eof-build"; eof_build.mkdir(); fake_hanging_turtle(eof_build / "turtle", True)
        eof_output = root / "eof-run"
        started = __import__('time').monotonic()
        eof_result = subprocess.run([sys.executable, script, "run", "--build", eof_build,
                                     "--profile", profile_file, "--net-profile", net_file,
                                     "--samples", "1", "--output", eof_output])
        check(eof_result.returncode != 0 and __import__('time').monotonic() - started < 5,
              "phase EOF cleanup was not bounded")
        descendant = int((eof_output / "owned-descendant.pid").read_text())
        check(not Path(f"/proc/{descendant}").exists(), "owned descendant survived phase EOF")

        # Direct SIGINT to the coordinator exercises the same bounded cleanup.
        sig_build = root / "sig-build"; sig_build.mkdir(); fake_hanging_turtle(sig_build / "turtle", False)
        sig_output = root / "sig-run"
        command = ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
                   str(script), "_coordinator", "run", "--build", str(sig_build),
                   "--profile", str(profile_file), "--net-profile", str(net_file),
                   "--samples", "1", "--output", str(sig_output)]
        process = subprocess.Popen(command)
        for _ in range(100):
            if (sig_output / "owned-descendant.pid").is_file(): break
            __import__('time').sleep(.02)
        check((sig_output / "owned-descendant.pid").is_file(), "SIGINT fixture did not start")
        os.kill(process.pid, signal.SIGINT)
        process.wait(timeout=5)
        descendant = int((sig_output / "owned-descendant.pid").read_text())
        check(not Path(f"/proc/{descendant}").exists(), "owned descendant survived SIGINT")
        sig_provenance = json.loads((sig_output / "network-provenance.json").read_text())
        check(sig_provenance["lifecycle"]["namespace_fds_closed"], "SIGINT leaked namespace FDs")
    print("PASS netem: snapshot, strict profile, exact fd handoff, phase observations, owned cleanup")


if __name__ == "__main__":
    main()
