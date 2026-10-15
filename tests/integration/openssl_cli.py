#!/usr/bin/env python3
"""Exercise one public TURTLE adapter role against an unmodified OpenSSL CLI."""

import argparse
import json
import os
import selectors
import socket
import subprocess
import sys
import time
from pathlib import Path


CLIENT_PING = b"turtle-client-ping\n"
SERVER_PONG = b"openssl-server-pong\n"
OPENSSL_PING = b"openssl-client-ping\n"
TURTLE_PONG = b"turtle-server-pong\n"

RUNTIME_QUERY = "adapter runtime query"
FIXED_MBED_CONFIG = "inferred from the adapter's fixed configuration; no runtime query"
EXPECTED_NEGOTIATED_EVIDENCE = {
    "openssl": {
        "sources": {
            "version": "observed", "cipher": "observed", "group": "observed",
            "signature": "unobserved", "resumed": "observed",
            "hello_retry_request": "observed", "peer_certificate_present": "observed",
        },
        "bases": {
            "version": RUNTIME_QUERY, "cipher": RUNTIME_QUERY,
            "group": "SSL_get_negotiated_group",
            "signature": "OpenSSL adapter does not expose the negotiated signature",
            "resumed": "SSL_session_reused", "hello_retry_request": "TLS message callback",
            "peer_certificate_present": RUNTIME_QUERY,
        },
    },
    "wolfssl": {
        "sources": {
            "version": "observed", "cipher": "observed", "group": "observed",
            "signature": "observed", "resumed": "observed",
            "hello_retry_request": "inferred", "peer_certificate_present": "observed",
        },
        "bases": {
            "version": RUNTIME_QUERY, "cipher": RUNTIME_QUERY,
            "group": "wolfSSL_get_curve_name", "signature": "wolfSSL signature NID queries",
            "resumed": "wolfSSL_session_reused",
            "hello_retry_request": (
                "inferred from the adapter's single permitted group; no runtime HRR query"
            ),
            "peer_certificate_present": RUNTIME_QUERY,
        },
    },
    "Mbed TLS": {
        "sources": {
            "version": "observed", "cipher": "observed", "group": "inferred",
            "signature": "inferred", "resumed": "inferred",
            "hello_retry_request": "inferred", "peer_certificate_present": "observed",
        },
        "bases": {
            "version": RUNTIME_QUERY, "cipher": RUNTIME_QUERY,
            "group": FIXED_MBED_CONFIG, "signature": FIXED_MBED_CONFIG,
            "resumed": FIXED_MBED_CONFIG, "hello_retry_request": FIXED_MBED_CONFIG,
            "peer_certificate_present": RUNTIME_QUERY,
        },
    },
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--pki", required=True)
    parser.add_argument("--role", required=True, choices=("client", "server"))
    parser.add_argument("--auth", required=True, choices=("server", "mutual"))
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def unique_run_directory(root, role, auth, adapter):
    root.mkdir(parents=True, exist_ok=True)
    stem = f"{Path(adapter).stem}-{role}-{auth}-{time.time_ns()}-{os.getpid()}"
    for suffix in range(100):
        candidate = root / (stem if suffix == 0 else f"{stem}-{suffix}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            pass
    raise RuntimeError("could not allocate a unique retained result directory")


def run_metadata(argv):
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=5, check=False)
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace"),
        "stderr": completed.stderr.decode("utf-8", "replace"),
    }


def require_help_options(help_record, options, command):
    if help_record["exit_code"] != 0:
        raise RuntimeError(f"openssl {command} -help exited {help_record['exit_code']}")
    text = help_record["stdout"] + help_record["stderr"]
    missing = [option for option in options if option not in text]
    if missing:
        raise RuntimeError(f"openssl {command} lacks required options: {', '.join(missing)}")


def validate_negotiated_evidence(endpoint_result):
    adapter_name = endpoint_result["adapter"]["name"]
    expected = EXPECTED_NEGOTIATED_EVIDENCE.get(adapter_name)
    if expected is None:
        raise RuntimeError(f"no negotiated-evidence contract for adapter {adapter_name!r}")
    actual_sources = endpoint_result.get("negotiated_sources")
    if actual_sources != expected["sources"]:
        raise RuntimeError(
            f"{adapter_name} negotiated source categories mismatch: "
            f"{actual_sources!r} != {expected['sources']!r}"
        )
    actual_bases = endpoint_result.get("negotiated_source_basis")
    if actual_bases != expected["bases"]:
        raise RuntimeError(
            f"{adapter_name} negotiated source bases mismatch: "
            f"{actual_bases!r} != {expected['bases']!r}"
        )


def write_intermediate_chain(source, destination):
    data = source.read_bytes()
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    certificates = []
    offset = 0
    while True:
        start = data.find(begin, offset)
        if start < 0:
            break
        finish = data.find(end, start)
        if finish < 0:
            raise RuntimeError(f"unterminated certificate in {source}")
        finish += len(end)
        certificates.append(data[start:finish] + b"\n")
        offset = finish
    if len(certificates) < 2:
        raise RuntimeError(f"{source} does not contain a leaf and intermediate chain")
    destination.write_bytes(b"".join(certificates[1:]))


def reserve_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", 0))
        return holder.getsockname()[1]


class Child:
    def __init__(self, name, argv, selector):
        self.name = name
        self.argv = argv
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.cleanup = []
        self.reaped = False
        for stream_name, stream in (("stdout", self.process.stdout),
                                    ("stderr", self.process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (self, stream_name))

    def write(self, value):
        if self.process.stdin is None or self.process.stdin.closed:
            raise RuntimeError(f"{self.name} stdin closed before application exchange")
        self.process.stdin.write(value)
        self.process.stdin.flush()

    def record(self):
        return {
            "argv": self.argv,
            "stdout": bytes(self.stdout).decode("utf-8", "replace"),
            "stdout_hex": bytes(self.stdout).hex(),
            "stderr": bytes(self.stderr).decode("utf-8", "replace"),
            "exit_code": self.process.returncode,
            "cleanup": self.cleanup,
            "reaped": self.reaped,
        }


def drain_events(selector, timeout):
    for key, _ in selector.select(timeout):
        child, stream_name = key.data
        try:
            chunk = os.read(key.fileobj.fileno(), 65536)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(key.fileobj)
            key.fileobj.close()
            continue
        getattr(child, stream_name).extend(chunk)


def close_stdin(child):
    if child and child.process.stdin and not child.process.stdin.closed:
        child.process.stdin.close()


def cleanup_child(child):
    if child is None:
        return
    close_stdin(child)
    if child.process.poll() is None:
        child.cleanup.append("SIGTERM")
        child.process.terminate()
        try:
            child.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.cleanup.append("SIGKILL")
            child.process.kill()
            child.process.wait(timeout=1)
    else:
        child.process.wait()
    child.reaped = True


def wait_for_ready(endpoint, selector, deadline):
    while True:
        newline = endpoint.stdout.find(b"\n")
        if newline >= 0:
            line = bytes(endpoint.stdout[:newline]).decode("ascii", "strict")
            parts = line.split()
            if len(parts) != 2 or parts[0] != "READY" or not parts[1].isdigit():
                raise RuntimeError(f"invalid endpoint readiness line: {line!r}")
            port = int(parts[1])
            if not 1 <= port <= 65535:
                raise RuntimeError(f"invalid endpoint readiness port: {port}")
            return port
        if endpoint.process.poll() is not None:
            raise RuntimeError("adapter server exited before readiness")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("common 10 second deadline exceeded before readiness")
        drain_events(selector, min(0.05, remaining))


def child_argv(args, run_dir, chain_file, port):
    pki = Path(args.pki)
    if args.role == "server":
        cli = [
            args.openssl, "s_client", "-connect", f"127.0.0.1:{port}",
            "-servername", "localhost", "-verify_hostname", "localhost",
            "-CAfile", str(pki / "ca.pem"), "-verify_return_error", "-tls1_3",
            "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-groups", "P-256",
            "-quiet", "-ign_eof", "-ignore_unexpected_eof",
        ]
        if args.auth == "mutual":
            cli += ["-cert", str(pki / "client.pem"), "-key", str(pki / "client.key"),
                    "-cert_chain", str(chain_file)]
    else:
        cli = [
            args.openssl, "s_server", "-accept", f"127.0.0.1:{port}",
            "-cert", str(pki / "server.pem"), "-key", str(pki / "server.key"),
            "-cert_chain", str(chain_file), "-CAfile", str(pki / "ca.pem"),
            "-verify_return_error", "-tls1_3", "-ciphersuites",
            "TLS_AES_128_GCM_SHA256", "-groups", "P-256", "-num_tickets", "0",
            "-naccept", "1", "-quiet", "-ign_eof", "-ignore_unexpected_eof",
        ]
        if args.auth == "mutual":
            cli += ["-Verify", "3"]
    endpoint_result = run_dir / "endpoint.json"
    endpoint = [
        args.endpoint, "--adapter", args.adapter, "--role", args.role,
        "--pki", args.pki, "--auth", args.auth, "--port", str(port),
        "--result", str(endpoint_result),
    ]
    return cli, endpoint, endpoint_result


def execute(args, run_dir, chain_file):
    selector = selectors.DefaultSelector()
    cli = None
    endpoint = None
    timed_out = False
    failure = None
    endpoint_result_path = None
    try:
        if args.role == "server":
            _, endpoint_argv, endpoint_result_path = child_argv(args, run_dir, chain_file, 0)
            endpoint = Child("adapter endpoint", endpoint_argv, selector)
            deadline = time.monotonic() + 10
            port = wait_for_ready(endpoint, selector, deadline)
            cli_argv, _, _ = child_argv(args, run_dir, chain_file, port)
            cli = Child("openssl CLI", cli_argv, selector)
            cli.write(OPENSSL_PING)
            response_written = True
            expected_cli_output = TURTLE_PONG
        else:
            port = reserve_loopback_port()
            cli_argv, endpoint_argv, endpoint_result_path = child_argv(
                args, run_dir, chain_file, port
            )
            cli = Child("openssl CLI", cli_argv, selector)
            endpoint = Child("adapter endpoint", endpoint_argv, selector)
            deadline = time.monotonic() + 10
            response_written = False
            expected_cli_output = CLIENT_PING

        while True:
            if not response_written and CLIENT_PING in cli.stdout:
                cli.write(SERVER_PONG)
                response_written = True
            cli_done = cli.process.poll() is not None
            endpoint_done = endpoint.process.poll() is not None
            if cli_done and endpoint_done and not selector.get_map():
                break
            if cli_done and not endpoint_done and cli.process.returncode != 0:
                raise RuntimeError(f"openssl CLI exited early with {cli.process.returncode}")
            if endpoint_done and not cli_done and endpoint.process.returncode != 0:
                raise RuntimeError(
                    f"adapter endpoint exited early with {endpoint.process.returncode}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                raise TimeoutError("common 10 second deadline exceeded")
            drain_events(selector, min(0.05, remaining))

        cli.process.wait()
        endpoint.process.wait()
        cli.reaped = True
        endpoint.reaped = True
        close_stdin(cli)
        close_stdin(endpoint)
        if not response_written:
            raise RuntimeError("did not observe complete CLI application request")
        if bytes(cli.stdout) != expected_cli_output:
            raise RuntimeError(
                f"CLI application stdout mismatch: {bytes(cli.stdout)!r} != {expected_cli_output!r}"
            )
        if endpoint.process.returncode != 0:
            raise RuntimeError(f"adapter endpoint exited {endpoint.process.returncode}")
        if cli.process.returncode != 0:
            raise RuntimeError(f"openssl CLI exited {cli.process.returncode}")
        if not endpoint_result_path.exists():
            raise RuntimeError("adapter endpoint did not write its result")
        endpoint_result = json.loads(endpoint_result_path.read_text(encoding="utf-8"))
        if not endpoint_result.get("success"):
            raise RuntimeError(f"adapter endpoint result failed: {endpoint_result.get('error')}")
        validate_negotiated_evidence(endpoint_result)
        return {
            "success": True,
            "error": "",
            "timeout": False,
            "port": port,
            "openssl_cli": cli.record(),
            "endpoint_process": endpoint.record(),
            "endpoint_result": endpoint_result,
            "eof_accommodation": (
                "-ignore_unexpected_eof is required because the public adapter API has no "
                "TLS close_notify operation; this test does not claim TLS shutdown verification"
            ),
        }
    except Exception as error:
        failure = str(error)
        raise
    finally:
        cleanup_child(endpoint)
        cleanup_child(cli)
        while selector.get_map():
            drain_events(selector, 0)
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except Exception:
                    pass
        selector.close()
        if failure is not None:
            failure_record = {
                "success": False,
                "error": failure,
                "timeout": timed_out,
                "openssl_cli": cli.record() if cli else None,
                "endpoint_process": endpoint.record() if endpoint else None,
            }
            if endpoint_result_path and endpoint_result_path.exists():
                try:
                    failure_record["endpoint_result"] = json.loads(
                        endpoint_result_path.read_text(encoding="utf-8")
                    )
                except Exception as parse_error:
                    failure_record["endpoint_result_error"] = str(parse_error)
            (run_dir / "result.json").write_text(
                json.dumps(failure_record, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )


def main():
    args = parse_args()
    run_dir = unique_run_directory(
        Path(args.output), args.role, args.auth, args.adapter
    )
    result_path = run_dir / "result.json"
    version = None
    client_help = None
    server_help = None
    try:
        version = run_metadata([args.openssl, "version", "-a"])
        if version["exit_code"] != 0:
            raise RuntimeError(f"openssl version -a exited {version['exit_code']}")
        client_help = run_metadata([args.openssl, "s_client", "-help"])
        server_help = run_metadata([args.openssl, "s_server", "-help"])
        require_help_options(
            client_help,
            ("-connect", "-servername", "-verify_hostname", "-CAfile",
             "-verify_return_error", "-tls1_3", "-ciphersuites", "-groups", "-quiet",
             "-ign_eof", "-ignore_unexpected_eof", "-cert", "-key", "-cert_chain"),
            "s_client",
        )
        require_help_options(
            server_help,
            ("-accept", "-cert", "-key", "-cert_chain", "-CAfile",
             "-verify_return_error", "-tls1_3", "-ciphersuites", "-groups",
             "-num_tickets", "-naccept", "-quiet", "-ign_eof",
             "-ignore_unexpected_eof", "-Verify"),
            "s_server",
        )
        chain_file = run_dir / "intermediates.pem"
        chain_role = "client" if args.role == "server" and args.auth == "mutual" else "server"
        write_intermediate_chain(Path(args.pki) / f"{chain_role}-chain.pem", chain_file)
        execution = execute(args, run_dir, chain_file)
        execution.update({
            "role": args.role,
            "auth": args.auth,
            "adapter_file": args.adapter,
            "openssl_version": version,
            "openssl_s_client_help": client_help,
            "openssl_s_server_help": server_help,
            "result_directory": str(run_dir),
        })
        result_path.write_text(
            json.dumps(execution, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(run_dir)
        return 0
    except Exception as error:
        failure = {"success": False, "error": str(error)}
        if result_path.exists():
            try:
                failure.update(json.loads(result_path.read_text(encoding="utf-8")))
            except Exception as parse_error:
                failure["prior_result_error"] = str(parse_error)
        failure.update({
            "role": args.role,
            "auth": args.auth,
            "adapter_file": args.adapter,
            "openssl_version": version,
            "openssl_s_client_help": client_help,
            "openssl_s_server_help": server_help,
            "result_directory": str(run_dir),
        })
        result_path.write_text(
            json.dumps(failure, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"openssl CLI integration failed; evidence: {run_dir}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
