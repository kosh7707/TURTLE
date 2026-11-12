#!/usr/bin/env python3
"""Socket-free contracts for the randomized study runner."""

from profiles import experiment_profile, flatten_experiment
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_program(path, body):
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o755)


def make_stubs(root):
    build = root / "build"
    adapters = build / "adapters"
    adapters.mkdir(parents=True)
    for library in ("openssl", "mbedtls"):
        (adapters / f"{library}.so").write_bytes(b"")
    common = """import json, os, pathlib, sys
log = pathlib.Path(os.environ['STUDY_STUB_LOG'])
def record(program):
    with log.open('a') as stream:
        stream.write(json.dumps({'program': program, 'args': sys.argv[1:]}) + '\\n')
"""
    write_program(build / "turtle-local", common + """record('turtle')
if os.environ.get('STUDY_STUB_FAIL') == 'turtle':
    print('injected turtle failure', file=sys.stderr)
    raise SystemExit(23)
args = sys.argv[1:]
output = pathlib.Path(args[args.index('--output') + 1])
sample = output / 'sample-000001'
sample.mkdir(parents=True)
for role in ('client', 'server'):
    (sample / f'{role}.jsonl').write_text('{}\\n')
""")
    write_program(build / "turtle-interpret", common + """record('interpret')
pathlib.Path(sys.argv[2]).write_text('{}\\n')
""")
    write_program(build / "turtle-report", common + "record('report')\n")
    return build


def invoke(script, root, *arguments):
    log = root / "commands.jsonl"
    environment = dict(os.environ, STUDY_STUB_LOG=str(log), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-B", script, "--build", root / "build", "--pki", root / "pki",
         *arguments],
        text=True,
        capture_output=True,
        env=environment,
    )
    rows = [] if not log.exists() else [json.loads(line) for line in log.read_text().splitlines()]
    return result, rows


def option_value(command, option):
    return command[command.index(option) + 1]


def turtle_pairs(rows):
    return {
        (option_value(row["args"], "--client"), option_value(row["args"], "--server"))
        for row in rows if row["program"] == "turtle"
    }


def assert_success(result):
    check(result.returncode == 0, f"runner failed:\nstdout={result.stdout}\nstderr={result.stderr}")


def main():
    script = (Path(sys.argv[1]) if len(sys.argv) > 1
              else Path(__file__).parents[2] / "scripts/run-study.py").resolve()
    repository = script.parent.parent
    with tempfile.TemporaryDirectory(prefix="turtle-study-test-") as temporary:
        root = Path(temporary)
        make_stubs(root)
        profile = root / "profile.json"
        profile.write_text(json.dumps(experiment_profile(measurement={"connections": 7})))

        default_output = root / "default"
        result, rows = invoke(
            script, root, "--output", default_output, "--profile", profile,
            "--libraries", "openssl,mbedtls", "--modes", "timing", "--auth", "server",
            "--samples", "2", "--batches", "1", "--seed", "19",
        )
        assert_success(result)
        turtle_rows = [row for row in rows if row["program"] == "turtle"]
        check(turtle_pairs(rows) == {("openssl", "openssl"), ("mbedtls", "mbedtls")},
              "the default pilot did not keep self-pairs")
        check(all("--connections" not in row["args"] for row in turtle_rows),
              "an unspecified connection count overrode the profile")
        check(all(option_value(row["args"], "--warmups") == "0" for row in turtle_rows),
              "the explicit zero warm-up policy was not forwarded")
        report = [row for row in rows if row["program"] == "report"]
        check(len(report) == 1 and "--repeated-context" not in report[0]["args"],
              "the default reporter command changed")
        manifest = json.loads((default_output / "study.json").read_text())
        policy = manifest["requested_policy"]
        check(policy["connections"] is None and policy["warmups"] == 0 and
              policy["samples_per_run"] == 2 and policy["batches"] == 1 and
              policy["pairing"] == "self" and not policy["repeated_context"],
              "the default requested policy was not recorded")
        check([entry["order"] for entry in manifest["runs"]] == [1, 2] and
              [entry["command"][1:] for entry in manifest["runs"]] ==
              [row["args"] for row in turtle_rows],
              "manifest order or executed commands diverged")
        check(manifest["seed"] == 19 and all(entry["status"] == "complete"
                                              for entry in manifest["runs"]),
              "seed or completed run state was not preserved")

        cross_root = root / "cross-fixture"
        make_stubs(cross_root)
        cross_output = cross_root / "output"
        result, rows = invoke(
            script, cross_root, "--output", cross_output, "--profile", profile,
            "--libraries", "openssl,mbedtls", "--modes", "timing", "--auth", "server",
            "--cross", "--connections", "16", "--repeated-context", "--samples", "1",
            "--batches", "1", "--seed", "7",
        )
        assert_success(result)
        check(turtle_pairs(rows) == {
            ("openssl", "openssl"), ("openssl", "mbedtls"),
            ("mbedtls", "openssl"), ("mbedtls", "mbedtls")},
            "the cross pilot did not create OO/OM/MO/MM")
        cross_turtle = [row for row in rows if row["program"] == "turtle"]
        check(all(option_value(row["args"], "--connections") == "16"
                  for row in cross_turtle), "the explicit connection count was not forwarded")
        cross_report = [row for row in rows if row["program"] == "report"]
        check(len(cross_report) == 1 and cross_report[0]["args"][-1] == "--repeated-context",
              "the reporter opt-in was not a trailing flag")
        cross_manifest = json.loads((cross_output / "study.json").read_text())
        check(cross_manifest["requested_policy"]["connections"] == 16 and
              cross_manifest["requested_policy"]["pairing"] == "cross" and
              cross_manifest["requested_policy"]["repeated_context"],
              "the cross pilot request was not recorded")
        check([entry["order"] for entry in cross_manifest["runs"]] == [1, 2, 3, 4] and
              [entry["command"][1:] for entry in cross_manifest["runs"]] ==
              [row["args"] for row in cross_turtle],
              "randomized cross-run commands were not recorded in execution order")

        for index, options in enumerate((
                ("--connections", "0"), ("--connections", "-1"),
                ("--connections", "1026"), ("--warmups", "-1"),
                ("--warmups", "1024", "--connections", "2"))):
            invalid_root = root / f"invalid-{index}"
            make_stubs(invalid_root)
            invalid_output = invalid_root / "output"
            result, rows = invoke(
                script, invalid_root, "--output", invalid_output, "--libraries", "openssl",
                "--modes", "timing", "--auth", "server", *options,
            )
            check(result.returncode != 0 and not rows and not invalid_output.exists(),
                  f"invalid explicit counts reached execution: {options}")

        failed_root = root / "failed-fixture"
        make_stubs(failed_root)
        failed_output = failed_root / "output"
        environment = dict(os.environ, STUDY_STUB_LOG=str(failed_root / "commands.jsonl"),
                           STUDY_STUB_FAIL="turtle", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-B", script, "--build", failed_root / "build",
             "--pki", failed_root / "pki", "--output", failed_output,
             "--libraries", "openssl,mbedtls", "--modes", "timing", "--auth", "server"],
            text=True, capture_output=True, env=environment)
        failed_rows = [json.loads(line) for line in
                       (failed_root / "commands.jsonl").read_text().splitlines()]
        check(result.returncode != 0 and len(failed_rows) == 1 and
              failed_rows[0]["program"] == "turtle",
              "a failed run was retried or followed by another run, decode, or report")
        failed_manifest = json.loads((failed_output / "study.json").read_text())
        check(len(failed_manifest["runs"]) == 1 and
              failed_manifest["runs"][0]["status"] == "invalid" and
              failed_manifest["runs"][0]["returncode"] == 23,
              "the failed attempt was not durably recorded")

        example = flatten_experiment(json.loads((repository / "examples/profiles/repeated-context.json").read_text()))
        baseline = flatten_experiment(json.loads((repository / "examples/profiles/server-auth.json").read_text()))
        for key in ("pki", "tls", "socket", "technique"):
            check(example[key] == baseline[key], f"repeated-context profile changed {key}")
        check(example["measurement"] == {
            "connections": 16, "warmups": 0, "timeout_ms": 30000},
            "repeated-context measurement policy changed")

    print("study runner contracts: PASS")


if __name__ == "__main__":
    main()
