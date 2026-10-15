#!/usr/bin/env python3
"""Run TURTLE in an owned user/network namespace topology.

The coordinator never names a namespace in /run/netns and never changes the
caller's network namespace.  Exit 2 means that setup is unsupported; exit 1
means that an experiment ran but did not prove its requested validation gate.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Any


MAX_OBJECT = 65536
PATH_INTERFACES = {
    "tls_c2s": "rstls", "tls_s2c": "rctls",
    "ca_c2s": "rca0", "ca_s2c": "rcca",
}
TLS_PATHS = ("tls_c2s", "tls_s2c")
LOOKUP_PATHS = (*TLS_PATHS, "ca_c2s", "ca_s2c")
ADDRESSES = {
    "client_tls": "10.203.1.2", "server": "10.203.2.2",
    "client_ca": "10.203.3.2", "ca": "10.203.4.2",
}
INTERFACES = {
    "client_tls": "ctls", "server": "stls", "client_ca": "cca", "ca": "ca0",
    "router_client_tls": "rctls", "router_server": "rstls",
    "router_client_ca": "rcca", "router_ca": "rca0",
}
LINKS = (
    ("client", "ctls", "10.203.1.2/30", "rctls", "10.203.1.1/30"),
    ("server", "stls", "10.203.2.2/30", "rstls", "10.203.2.1/30"),
    ("client", "cca", "10.203.3.2/30", "rcca", "10.203.3.1/30"),
    ("ca", "ca0", "10.203.4.2/30", "rca0", "10.203.4.1/30"),
)
TLS_LINKS = LINKS[:2]
TLS_ADDRESSES = {name: ADDRESSES[name] for name in ("client_tls", "server")}
TLS_INTERFACES = {name: INTERFACES[name] for name in
                  ("client_tls", "server", "router_client_tls", "router_server")}
OWNED_INTERFACES = (("client", "ctls"), ("client", "cca"), ("server", "stls"),
                    ("ca", "ca0"), ("router", "rctls"), ("router", "rstls"),
                    ("router", "rcca"), ("router", "rca0"))


class SetupUnsupported(RuntimeError):
    pass


def enter_netns(fd: int) -> None:
    if hasattr(os, "setns"):
        os.setns(fd, 0x40000000)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "setns"):
        raise SetupUnsupported("Python and libc do not provide setns")
    if libc.setns(fd, 0x40000000) != 0:
        error = ctypes.get_errno()
        raise SetupUnsupported(f"setns failed: {os.strerror(error)}")


def enable_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "prctl") or libc.prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise SetupUnsupported(f"cannot enable owned-child subreaper: {os.strerror(error)}")


def terminate_group(process: subprocess.Popen[str], grace: float, evidence: list[dict[str, Any]]) -> bool:
    """Bounded termination of a process group created solely for the director."""
    deadline = time.monotonic() + grace
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    def alive() -> bool:
        try: os.killpg(process.pid, 0); return True
        except ProcessLookupError: return False
    def reap_descendants() -> None:
        process.poll()
        while True:
            try:
                pid, _ = os.waitpid(-process.pid, os.WNOHANG)
                if pid <= 0: break
            except ChildProcessError: break
    while alive() and time.monotonic() < deadline:
        if process.poll() is None:
            try: process.wait(.02)
            except subprocess.TimeoutExpired: pass
        reap_descendants(); time.sleep(.01)
    if alive():
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        kill_deadline = time.monotonic() + .2
        while alive() and time.monotonic() < kill_deadline:
            if process.poll() is None:
                try: process.wait(.02)
                except subprocess.TimeoutExpired: pass
            reap_descendants(); time.sleep(.01)
    reap_descendants()
    if process.poll() is None:
        try: process.wait(.02)
        except subprocess.TimeoutExpired: pass
    result = "reaped" if not alive() and process.poll() is not None else "fatal-not-reaped"
    evidence.append({"director_group": process.pid, "result": result})
    return result == "reaped"


def dump_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def dump_json_exclusive(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def append_json(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def fnv1a64(data: bytes) -> str:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xffffffffffffffff
    return f"fnv1a64:{value:016x}"


def make_snapshot(object_file: Path) -> dict[str, Any]:
    data = object_file.read_bytes()
    if not 1 <= len(data) <= MAX_OBJECT:
        raise ValueError("object must contain 1..65536 bytes")
    return {"type": "turtle-lookup-cache", "schema": 1,
            "object_id": fnv1a64(data), "object_size": len(data),
            "object_hex": data.hex()}


def profile_lookup_enabled(value: Any) -> bool:
    if not isinstance(value, dict):
        raise ValueError("profile must be an object")
    if "lookup" not in value:
        return False
    lookup = value["lookup"]
    if not isinstance(lookup, dict):
        raise ValueError("lookup must be an object")
    enabled = lookup.get("enabled", False)
    if type(enabled) is not bool:
        raise ValueError("lookup.enabled must be boolean")
    return enabled


def validate_net_profile(value: Any, lookup_enabled: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
            "type", "schema", "qdisc", "mtu", "offload", "trace", "loss_seed", "paths"}:
        raise ValueError("net profile has unknown or missing top-level fields")
    if value["type"] != "turtle-netem-profile" or value["schema"] != 1:
        raise ValueError("unsupported net profile type or schema")
    if value["qdisc"] not in ("none", "netem"):
        raise ValueError("qdisc must be none or netem")
    if type(value["mtu"]) is not int or not 576 <= value["mtu"] <= 65535:
        raise ValueError("mtu must be an integer in 576..65535")
    if type(value["trace"]) is not bool:
        raise ValueError("trace must be boolean")
    if value["loss_seed"] is not None:
        if type(value["loss_seed"]) is not int or not 0 <= value["loss_seed"] <= 0xffffffff:
            raise ValueError("loss_seed must be null or an unsigned 32-bit integer")
        raise SetupUnsupported("installed tc netem has no verified loss seed support")
    if not isinstance(value["offload"], dict) or set(value["offload"]) != {"tso", "gso", "gro"}:
        raise ValueError("offload must contain exactly tso, gso, and gro")
    if any(type(item) is not bool for item in value["offload"].values()):
        raise ValueError("offload settings must be boolean")
    allowed_paths = set(LOOKUP_PATHS if lookup_enabled else TLS_PATHS)
    supplied_paths = set(value["paths"]) if isinstance(value["paths"], dict) else set()
    valid_path_sets = {frozenset(allowed_paths)}
    if not lookup_enabled:
        valid_path_sets.add(frozenset(LOOKUP_PATHS))
    if frozenset(supplied_paths) not in valid_path_sets:
        requirement = "all four directional paths" if lookup_enabled else "exactly two TLS paths or all four legacy paths"
        raise ValueError(f"{requirement} are required")
    normalized = copy.deepcopy(value)
    for name, policy in normalized["paths"].items():
        if not isinstance(policy, dict) or set(policy) != {"delay_ms", "loss_percent", "limit_packets"}:
            raise ValueError(f"{name} must contain delay_ms, loss_percent, limit_packets")
        delay, loss, limit = policy["delay_ms"], policy["loss_percent"], policy["limit_packets"]
        if type(delay) is not int or not 0 <= delay <= 1000:
            raise ValueError(f"{name}.delay_ms must be an integer in 0..1000")
        if isinstance(loss, bool) or not isinstance(loss, (int, float)) or not 0 <= loss <= 100:
            raise ValueError(f"{name}.loss_percent must be a finite number in 0..100")
        if not float(loss) == loss or type(limit) is not int or not 1 <= limit <= 100000:
            raise ValueError(f"{name} has an invalid loss or queue limit")
        policy["loss_percent"] = float(loss)
        if normalized["qdisc"] == "none" and (delay != 0 or loss != 0):
            raise ValueError("qdisc none requires zero delay and loss on every path")
    return normalized


def active_net_profile(profile: dict[str, Any], lookup_enabled: bool) -> dict[str, Any]:
    """Normalize a profile to settings that are actually applied by the fixed topology."""
    active = copy.deepcopy(profile)
    names = LOOKUP_PATHS if lookup_enabled else TLS_PATHS
    active["paths"] = {name: active["paths"][name] for name in names}
    return active


def resolve_samples(profile: dict[str, Any], override: int | None) -> int:
    samples = override if override is not None else profile.get("measurement", {}).get("samples", 1000)
    if type(samples) is not int or samples < 1:
        raise ValueError("samples must be positive")
    return samples


class Commands:
    def __init__(self, provenance: dict[str, Any]):
        self.provenance = provenance

    def run(self, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(argv, text=True, capture_output=True, timeout=2)
        except subprocess.TimeoutExpired as error:
            self.provenance.setdefault("commands", []).append({
                "argv": argv, "returncode": None, "stdout": error.stdout, "stderr": error.stderr,
                "failure": "timeout-2s"})
            raise SetupUnsupported(f"command did not finish in 2 seconds: {' '.join(argv)}") from error
        self.provenance.setdefault("commands", []).append({
            "argv": argv, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
        })
        if check and result.returncode:
            raise SetupUnsupported(f"command failed ({result.returncode}): {' '.join(argv)}: {result.stderr.strip()}")
        return result

    def ns(self, pid: int, argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.run(["nsenter", "-t", str(pid), "-n", "--", *argv], check=check)


class OwnedTopology:
    def __init__(self, profile: dict[str, Any], output: Path, lookup_enabled: bool = True):
        self.lookup_enabled, self.output = lookup_enabled, output
        self.profile = active_net_profile(profile, lookup_enabled)
        self.namespace_names = ("client", "server", "ca", "router") if lookup_enabled else ("client", "server", "router")
        self.links = LINKS if lookup_enabled else TLS_LINKS
        self.path_interfaces = {name: PATH_INTERFACES[name] for name in
                                (LOOKUP_PATHS if lookup_enabled else TLS_PATHS)}
        self.observer_interfaces = tuple(link[3] for link in self.links)
        self.addresses = ADDRESSES if lookup_enabled else TLS_ADDRESSES
        self.interfaces = INTERFACES if lookup_enabled else TLS_INTERFACES
        self.helpers: dict[str, subprocess.Popen[str]] = {}
        self.ns_fds: dict[str, int] = {}
        self.observer: subprocess.Popen[str] | None = None
        self.marker: socket.socket | None = None
        self.provenance: dict[str, Any] = {
            "type": "turtle-network-provenance", "schema": 1,
            "status": "initializing", "reason": None,
            "created_monotonic_ns": time.monotonic_ns(),
            "tools": {}, "commands": [], "lifecycle": {"helpers": {}, "namespace_fds_closed": False},
            "condition_identity": {
                "topology": {"kind": ("four-netns-receiver-facing-router-egress" if lookup_enabled else
                                        "three-netns-receiver-facing-router-egress"),
                             "addresses": self.addresses, "interfaces": self.interfaces},
                "requested": self.profile, "actual": None,
                "mtu": {"requested": profile["mtu"], "actual": {}},
                "offload": {"requested": profile["offload"], "actual": {}},
                "trace": {"requested": profile["trace"], "observation_point": "router-veth-af_packet",
                          "packet_unit": "observed-skb-not-physical-wire"},
            },
            "routes": [], "cleanup": [],
        }
        self.commands = Commands(self.provenance)

    @property
    def provenance_path(self) -> Path:
        return self.output / "network-provenance.json"

    def save(self) -> None:
        dump_json(self.provenance_path, self.provenance)

    def _start_namespace_helper(self, name: str, owner_user_inode: int) -> None:
        """Start a helper and wait until its unshare+exec has entered the new netns."""
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        try:
            try:
                child = subprocess.Popen(
                    ["unshare", "--net", "--", sys.executable, "-c",
                     ("import os,signal,sys,time; "
                      "fd=int(sys.argv[1]); os.write(fd,b'R'); os.close(fd); "
                      "signal.signal(signal.SIGTERM, lambda *_: exit(0)); time.sleep(86400)"),
                     str(ready_write)],
                    pass_fds=(ready_write,), text=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.helpers[name] = child
            finally:
                os.close(ready_write)
            readable, _, _ = select.select([ready_read], [], [], 2)
            marker = os.read(ready_read, 2) if readable else b""
        finally:
            os.close(ready_read)
        if marker != b"R":
            detail = "readiness timed out"
            if child.poll() is not None and child.stderr:
                detail = child.stderr.read().strip() or f"exit {child.returncode}"
            raise SetupUnsupported(f"could not create {name} network namespace: {detail}")
        fd = os.open(f"/proc/{child.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        self.ns_fds[name] = fd
        self.provenance["lifecycle"]["helpers"][name] = {
            "pid": child.pid, "namespace_inode": os.fstat(fd).st_ino,
            "user_namespace_inode": os.stat(f"/proc/{child.pid}/ns/user").st_ino,
            "fd": fd, "owned": True,
        }
        if self.provenance["lifecycle"]["helpers"][name]["user_namespace_inode"] != owner_user_inode:
            raise SetupUnsupported("helper is not owned by the common user namespace")

    def setup(self) -> None:
        for tool in ("ip", "tc", "ethtool", "unshare", "nsenter"):
            path = shutil.which(tool)
            if not path:
                raise SetupUnsupported(f"required program is missing: {tool}")
            self.provenance["tools"][tool] = path
            version_flag = "-Version" if tool in ("ip", "tc") else "--version"
            version = subprocess.run([path, version_flag], text=True, capture_output=True, timeout=2)
            self.provenance["tools"][f"{tool}_version"] = (version.stdout + version.stderr).strip()
        self.provenance["tools"]["kernel_release"] = os.uname().release
        owner_user_inode = os.stat("/proc/self/ns/user").st_ino
        self.provenance["lifecycle"]["user_namespace_inode"] = owner_user_inode
        for name in self.namespace_names:
            self._start_namespace_helper(name, owner_user_inode)
        router = self.helpers["router"].pid
        for endpoint, endpoint_if, endpoint_cidr, router_if, router_cidr in self.links:
            self.commands.run(["ip", "link", "add", endpoint_if, "type", "veth", "peer", "name", router_if])
            self.commands.run(["ip", "link", "set", endpoint_if, "netns", str(self.helpers[endpoint].pid)])
            self.commands.run(["ip", "link", "set", router_if, "netns", str(router)])
            for pid, interface, cidr in ((self.helpers[endpoint].pid, endpoint_if, endpoint_cidr),
                                         (router, router_if, router_cidr)):
                self.commands.ns(pid, ["ip", "link", "set", "dev", interface, "mtu", str(self.profile["mtu"])])
                self.commands.ns(pid, ["ip", "addr", "add", cidr, "dev", interface])
                self.commands.ns(pid, ["ip", "link", "set", interface, "up"])
        for child in self.helpers.values():
            self.commands.ns(child.pid, ["ip", "link", "set", "lo", "up"])
        self.commands.ns(router, [sys.executable, "-c",
                                 "from pathlib import Path; Path('/proc/sys/net/ipv4/ip_forward').write_text('1\\n')"])
        routes = [
            ("client", "10.203.2.0/30", "10.203.1.1", "ctls"),
            ("server", "10.203.1.0/30", "10.203.2.1", "stls"),
        ]
        if self.lookup_enabled:
            routes += [("client", "10.203.4.0/30", "10.203.3.1", "cca"),
                       ("ca", "10.203.3.0/30", "10.203.4.1", "ca0")]
        for owner, network, gateway, interface in routes:
            self.commands.ns(self.helpers[owner].pid,
                             ["ip", "route", "add", network, "via", gateway, "dev", interface])
        requested = self.profile["offload"]
        for owner, interface in self._owned_interfaces():
            argv = ["ethtool", "-K", interface]
            for key in ("tso", "gso", "gro"):
                argv += [key, "on" if requested[key] else "off"]
            self.commands.ns(self.helpers[owner].pid, argv)
        self._read_environment()
        self.reset_qdiscs()
        if self.profile["trace"]:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            self.marker = parent
            observer_file = self.output / "packets.jsonl"
            self.observer = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "_observer",
                 "--router-fd", str(self.ns_fds["router"]), "--control-fd", str(child.fileno()),
                 "--interfaces", ",".join(self.observer_interfaces),
                 "--output", str(observer_file)], pass_fds=(self.ns_fds["router"], child.fileno()))
            child.close()
            self._marker({"kind": "capture-start", "monotonic_ns": time.monotonic_ns()})
        self.provenance["status"] = "ready"
        self.save()

    def _owned_interfaces(self) -> list[tuple[str, str]]:
        active = {(endpoint, endpoint_if) for endpoint, endpoint_if, _, _, _ in self.links}
        active.update(("router", router_if) for _, _, _, router_if, _ in self.links)
        return [item for item in OWNED_INTERFACES if item in active]

    def _read_environment(self) -> None:
        actual_offload, actual_mtu = {}, {}
        for owner, interface in self._owned_interfaces():
            key = f"{owner}:{interface}"
            link = json.loads(self.commands.ns(self.helpers[owner].pid,
                                               ["ip", "-j", "link", "show", "dev", interface]).stdout)[0]
            actual_mtu[key] = link["mtu"]
            if link["mtu"] != self.profile["mtu"]:
                raise SetupUnsupported(f"MTU readback differs for {key}")
            features = self.commands.ns(self.helpers[owner].pid, ["ethtool", "-k", interface]).stdout
            parsed = {}
            names = {"tcp-segmentation-offload": "tso", "generic-segmentation-offload": "gso",
                     "generic-receive-offload": "gro"}
            for line in features.splitlines():
                field, separator, value = line.strip().partition(":")
                if separator and field in names:
                    parsed[names[field]] = value.strip().split()[0] == "on"
            if set(parsed) != {"tso", "gso", "gro"}:
                raise SetupUnsupported(f"incomplete offload readback for {key}")
            actual_offload[key] = parsed
            if parsed != self.profile["offload"]:
                raise SetupUnsupported(f"offload readback differs for {key}")
        self.provenance["condition_identity"]["mtu"]["actual"] = actual_mtu
        self.provenance["condition_identity"]["offload"]["actual"] = actual_offload
        route_requests = [("client", "10.203.2.2", "10.203.1.2"),
                          ("server", "10.203.1.2", "10.203.2.2")]
        route_expectations = [("client", "10.203.2.2", "10.203.1.2", "ctls", "10.203.1.1"),
                              ("server", "10.203.1.2", "10.203.2.2", "stls", "10.203.2.1")]
        if self.lookup_enabled:
            route_requests += [("client", "10.203.4.2", "10.203.3.2"),
                               ("ca", "10.203.3.2", "10.203.4.2")]
            route_expectations += [("client", "10.203.4.2", "10.203.3.2", "cca", "10.203.3.1"),
                                   ("ca", "10.203.3.2", "10.203.4.2", "ca0", "10.203.4.1")]
        for owner, destination, source in route_requests:
            result = self.commands.ns(self.helpers[owner].pid,
                                      ["ip", "-j", "route", "get", destination, "from", source])
            readback = json.loads(result.stdout)
            expected = next(item for item in route_expectations
                            if item[:3] == (owner, destination, source))
            if not readback or readback[0].get("dev") != expected[3] or readback[0].get("gateway") != expected[4]:
                raise SetupUnsupported(f"route readback differs for {owner} to {destination}")
            self.provenance["routes"].append({"namespace": owner, "destination": destination,
                                               "source": source, "readback": readback, "verified": True})

    def _qdisc_readback(self) -> dict[str, Any]:
        result = {}
        router = self.helpers["router"].pid
        for path, interface in self.path_interfaces.items():
            raw = json.loads(self.commands.ns(router, ["tc", "-j", "-s", "qdisc", "show", "dev", interface]).stdout)
            roots = [entry for entry in raw if entry.get("root")]
            result[path] = {"interface": interface, "requested": self.profile["paths"][path],
                            "raw": raw, "root_kind": roots[0].get("kind") if roots else None}
        return result

    @staticmethod
    def _stable_qdisc(readback: dict[str, Any]) -> dict[str, Any]:
        """Keep condition fields; counters, handles and kernel refcounts are outcomes/provenance."""
        stable = {}
        for path, value in readback.items():
            roots = [entry for entry in value["raw"] if entry.get("root")]
            root = roots[0] if roots else {}
            options = root.get("options", {})
            delay = options.get("delay")
            delay_ms = delay.get("delay") * 1000 if isinstance(delay, dict) and delay.get("delay") is not None else 0
            loss = options.get("loss-random")
            loss_percent = loss.get("loss") * 100 if isinstance(loss, dict) and loss.get("loss") is not None else 0
            stable[path] = {
                "interface": value["interface"], "kind": value["root_kind"],
                "delay_ms": delay_ms, "loss_percent": loss_percent,
                "limit_packets": options.get("limit"),
            }
        return stable

    def reset_qdiscs(self) -> dict[str, Any]:
        router = self.helpers["router"].pid
        for path, interface in self.path_interfaces.items():
            self.commands.ns(router, ["tc", "qdisc", "del", "dev", interface, "root"], check=False)
            if self.profile["qdisc"] == "netem":
                policy = self.profile["paths"][path]
                self.commands.ns(router, ["tc", "qdisc", "add", "dev", interface, "root", "netem",
                                          "limit", str(policy["limit_packets"]), "delay", f'{policy["delay_ms"]}ms',
                                          "loss", f'{policy["loss_percent"]:.12g}%'])
        readback = self._qdisc_readback()
        expected = "netem" if self.profile["qdisc"] == "netem" else None
        for path, value in readback.items():
            if expected and value["root_kind"] != expected:
                raise SetupUnsupported(f"netem readback missing on {path}")
            if not expected and value["root_kind"] == "netem":
                raise SetupUnsupported(f"netem unexpectedly remains on {path}")
        stable = self._stable_qdisc(readback)
        if expected:
            for path, actual in stable.items():
                requested = self.profile["paths"][path]
                if (abs(actual["delay_ms"] - requested["delay_ms"]) > .001 or
                        abs(actual["loss_percent"] - requested["loss_percent"]) > .001 or
                        actual["limit_packets"] != requested["limit_packets"]):
                    raise SetupUnsupported(f"netem readback differs from request on {path}")
        self.provenance["condition_identity"]["actual"] = {
            "qdisc": self.profile["qdisc"], "paths": stable,
            "loss_seed": {"requested": None, "supported": False},
        }
        self.provenance["applied_qdisc_readback"] = readback
        return readback

    def _marker(self, value: dict[str, Any]) -> None:
        if not self.marker:
            return
        self.marker.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        self.marker.settimeout(.5)
        reply = b""
        while not reply.endswith(b"\n"):
            part = self.marker.recv(4096 - len(reply))
            if not part:
                raise RuntimeError("packet observer closed marker channel")
            reply += part
        if json.loads(reply) != {"ack": value.get("observation_id", value["kind"])}:
            raise RuntimeError("packet observer marker acknowledgement mismatch")

    def observe(self, request: dict[str, Any], observations: Path) -> str:
        observation_id = f'{request["attempt"]}:{request["phase"]}:{request["edge"]}'
        if request["phase"] == "setup" and request["edge"] == "begin":
            qdiscs = self.reset_qdiscs()
        else:
            qdiscs = self._qdisc_readback()
        now = time.monotonic_ns()
        self._marker({"kind": "phase", "observation_id": observation_id,
                      "attempt": request["attempt"], "phase": request["phase"],
                      "edge": request["edge"], "monotonic_ns": now})
        append_json(observations, {"type": "network-observation", "schema": 1,
                    "observation_id": observation_id, "attempt": request["attempt"],
                    "phase": request["phase"], "edge": request["edge"],
                    "monotonic_ns": now, "qdiscs": qdiscs,
                    "packet_trace": "packets.jsonl" if self.profile["trace"] else None})
        return observation_id

    def cleanup(self) -> list[str]:
        failures: list[str] = []
        deadline = time.monotonic() + .5
        if self.marker:
            try: self._marker({"kind": "capture-stop", "monotonic_ns": time.monotonic_ns()})
            except Exception as error:
                self.provenance["cleanup"].append({"observer_marker_error": str(error)})
                failures.append(f"observer stop marker failed: {error}")
            try: self.marker.close()
            except OSError as error: failures.append(f"observer marker fd close failed: {error}")
            self.marker = None
        if self.observer:
            remaining = max(0, deadline - time.monotonic())
            try: self.observer.wait(remaining)
            except subprocess.TimeoutExpired:
                self.observer.kill()
                try: self.observer.wait(.2); result = "killed-after-500ms"
                except subprocess.TimeoutExpired: result = "fatal-not-reaped"
                self.provenance["cleanup"].append({"observer": result})
                if result == "fatal-not-reaped": failures.append("packet observer could not be reaped")
            else: self.provenance["cleanup"].append({"observer": "reaped", "returncode": self.observer.returncode})
        for name, child in self.helpers.items():
            if child.poll() is None: child.terminate()
        for name, child in self.helpers.items():
            try: child.wait(max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                try: child.wait(.2); result = "killed"
                except subprocess.TimeoutExpired: result = "fatal-not-reaped"
                self.provenance["cleanup"].append({"helper": name, "result": result})
                if result == "fatal-not-reaped": failures.append(f"{name} namespace helper could not be reaped")
            else: self.provenance["cleanup"].append({"helper": name, "result": "reaped",
                                                       "returncode": child.returncode})
            if child.stderr:
                try: child.stderr.close()
                except OSError as error: failures.append(f"{name} helper pipe close failed: {error}")
        namespace_fds_closed = True
        for name, fd in self.ns_fds.items():
            try: os.close(fd)
            except OSError as error:
                namespace_fds_closed = False
                failures.append(f"{name} namespace fd {fd} close failed: {error}")
        self.ns_fds.clear()
        self.provenance["lifecycle"]["namespace_fds_closed"] = namespace_fds_closed
        self.provenance["lifecycle"]["owned_pipe_fds_closed"] = not any("pipe close failed" in item for item in failures)
        self.provenance["finished_monotonic_ns"] = time.monotonic_ns()
        if failures:
            self.provenance.setdefault("secondary_cleanup_failures", []).extend(failures)
            if self.provenance.get("status") in ("complete", "probe-complete", "ready", "initializing"):
                self.provenance.update(status="cleanup-failed", reason="owned cleanup could not be proven")
        try:
            self.save()
        except Exception as error:
            failure = f"final provenance save failed: {error}"
            failures.append(failure)
            self.provenance.setdefault("secondary_cleanup_failures", []).append(failure)
            if self.provenance.get("status") in ("complete", "probe-complete", "ready", "initializing"):
                self.provenance.update(status="cleanup-failed", reason="owned cleanup provenance is unknown")
            # Best-effort independent evidence. Failure here remains observable
            # through the nonzero return even if the filesystem is unavailable.
            try:
                dump_json(self.output / "network-provenance.partial.json", self.provenance)
                dump_json(self.output / "network-cleanup-errors.json", {
                    "type": "turtle-network-cleanup-errors", "schema": 1,
                    "failures": failures})
            except OSError:
                pass
        return failures


def recv_line(sock: socket.socket, buffer: bytearray) -> bytes | None:
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            line = bytes(buffer[:newline]); del buffer[:newline + 1]
            return line
        data = sock.recv(4096)
        if not data:
            if buffer:
                raise RuntimeError("partial phase-control JSON line at EOF")
            return None
        buffer.extend(data)
        if len(buffer) > 4096:
            raise RuntimeError("phase-control JSON line exceeds 4096 bytes")


def validate_phase(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"type", "schema", "attempt", "phase", "edge"}:
        raise RuntimeError("invalid phase request fields")
    if value["type"] != "phase" or value["schema"] != 1 or type(value["attempt"]) is not int or value["attempt"] < 1:
        raise RuntimeError("invalid phase request identity")
    if value["phase"] not in ("setup", "scenario", "cleanup") or value["edge"] not in ("begin", "end"):
        raise RuntimeError("invalid phase request value")
    return value


def run_coordinator(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists():
        print(f"output already exists: {output}", file=sys.stderr); return 2
    output.mkdir(parents=True)
    observations = output / "network-observations.jsonl"
    topology: OwnedTopology | None = None
    director: subprocess.Popen[str] | None = None
    phase_parent: socket.socket | None = None
    phase_child: socket.socket | None = None
    buffer = bytearray()
    stop = False
    terminal_code = 1
    protocol_failure = None
    expected_edges: dict[int, int] = {}
    sequence = (("setup", "begin"), ("setup", "end"), ("scenario", "begin"),
                ("scenario", "end"), ("cleanup", "begin"), ("cleanup", "end"))
    def record_missing(attempt: int, start: int, end: int, reason: str) -> None:
        missing = []
        for phase, edge in sequence[start:end]:
            partial_id = f"{attempt}:{phase}:{edge}:missing"
            append_json(observations, {
                "type": "network-observation", "schema": 1,
                "record_kind": "partial-window", "observation_id": partial_id,
                "attempt": attempt, "phase": phase, "edge": edge,
                "monotonic_ns": time.monotonic_ns(), "qdiscs": None,
                "packet_trace": "packets.jsonl" if topology and topology.profile["trace"] else None,
                "missing_reason": reason})
            missing.append(partial_id)
        if topology and missing:
            topology.provenance.setdefault("partial_phase_windows", []).extend(missing)
    def interrupted(_signum, _frame):
        nonlocal stop
        stop = True
    old_int, old_term = signal.signal(signal.SIGINT, interrupted), signal.signal(signal.SIGTERM, interrupted)
    try:
        enable_subreaper()
        run_profile = json.loads(Path(args.profile).read_text())
        lookup_enabled = profile_lookup_enabled(run_profile)
        profile = validate_net_profile(json.loads(Path(args.net_profile).read_text()), lookup_enabled)
        topology = OwnedTopology(profile, output, lookup_enabled); topology.setup()
        phase_parent, phase_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        director_names = ("client", "server", "ca") if lookup_enabled else ("client", "server")
        manifest = {
            "type": "turtle-network-manifest", "schema": 1,
            "namespace_fds": {name: topology.ns_fds[name] for name in director_names},
            "addresses": topology.addresses, "interfaces": topology.interfaces,
            "net_profile": topology.profile,
            "provenance_file": str(topology.provenance_path),
            "observations_file": str(observations), "phase_control_fd": phase_child.fileno(),
        }
        manifest_path = output / "network-manifest.json"; dump_json(manifest_path, manifest)
        command = [str((Path(args.build).resolve() / "turtle")), "run", "--profile", str(Path(args.profile).resolve()),
                   "--samples", str(args.samples), "--output", str(output),
                   "--network-manifest", str(manifest_path)]
        pass_fds = tuple(topology.ns_fds[name] for name in director_names) + (phase_child.fileno(),)
        topology.provenance["director"] = {"argv": command, "pass_fds": list(pass_fds),
                                           "router_fd_passed": False}
        topology.save()
        director = subprocess.Popen(command, pass_fds=pass_fds, text=True, start_new_session=True)
        phase_child.close()
        while director.poll() is None and not stop:
            ready, _, _ = select.select([phase_parent], [], [], .1)
            if not ready: continue
            line = recv_line(phase_parent, buffer)
            if line is None:
                # Closing the inherited phase fd and process exit are distinct
                # kernel observations.  Give an already-finalizing director the
                # bounded runner cleanup interval before deciding it is stuck.
                try: director.wait(.5)
                except subprocess.TimeoutExpired:
                    protocol_failure = "director remained alive after phase-control EOF"
                    # The EOF wait consumed the runner's 500 ms grace.  Do not
                    # restart it; escalate the owned group immediately.
                    terminate_group(director, 0, topology.provenance["cleanup"])
                break
            request = validate_phase(json.loads(line))
            attempt = request["attempt"]
            index = expected_edges.get(attempt, 0)
            requested_edge = (request["phase"], request["edge"])
            if requested_edge == ("cleanup", "begin") and index < 4:
                record_missing(attempt, index, 4, "abort advanced directly to cleanup")
                index = 4
            if index >= len(sequence) or requested_edge != sequence[index]:
                raise RuntimeError(f"out-of-sequence phase request for attempt {attempt}")
            expected_edges[attempt] = index + 1
            observation_id = topology.observe(request, observations)
            reply = {**request, "type": "ack", "observation_id": observation_id}
            phase_parent.sendall(json.dumps(reply, separators=(",", ":")).encode() + b"\n")
        if director.poll() is None:
            if not terminate_group(director, .5, topology.provenance["cleanup"]):
                raise RuntimeError("director process group could not be reaped")
        incomplete = [attempt for attempt, index in expected_edges.items() if index != len(sequence)]
        for attempt in incomplete:
            index = expected_edges[attempt]
            record_missing(attempt, index, len(sequence), "director exited before phase window completed")
            expected_edges[attempt] = len(sequence)
        if protocol_failure or (incomplete and director.returncode == 0):
            raise RuntimeError(protocol_failure or f"successful director omitted phase windows: {incomplete}")
        topology.provenance["director"]["returncode"] = director.returncode
        topology.provenance["status"] = "complete" if director.returncode == 0 else "director-failed"
        terminal_code = 130 if stop else director.returncode
        return terminal_code
    except SetupUnsupported as error:
        if topology:
            if buffer:
                topology.provenance["phase_control_partial"] = {
                    "status": "partial", "bytes_hex": bytes(buffer).hex()}
            topology.provenance.update(status="unsupported", reason=str(error)); topology.save()
        else:
            dump_json(output / "network-provenance.json", {"type": "turtle-network-provenance", "schema": 1,
                      "status": "unsupported", "reason": str(error)})
        print(error, file=sys.stderr); terminal_code = 2; return terminal_code
    except Exception as error:
        if topology:
            if buffer:
                topology.provenance["phase_control_partial"] = {
                    "status": "partial", "bytes_hex": bytes(buffer).hex()}
            topology.provenance.update(status="error", reason=str(error)); topology.save()
        print(error, file=sys.stderr); terminal_code = 1; return terminal_code
    finally:
        signal.signal(signal.SIGINT, old_int); signal.signal(signal.SIGTERM, old_term)
        if phase_parent: phase_parent.close()
        if phase_child:
            try: phase_child.close()
            except OSError: pass
        if director and director.poll() is None:
            evidence = topology.provenance["cleanup"] if topology else []
            terminate_group(director, .5, evidence)
        # Reap any owned descendants orphaned after a director failure.  As a
        # subreaper this coordinator only receives its own descendant tree.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid <= 0: break
            except ChildProcessError: break
        if topology:
            cleanup_failures = topology.cleanup()
            if cleanup_failures:
                print("; ".join(cleanup_failures), file=sys.stderr)
                if terminal_code == 0:
                    return 1


def outer_isolated(command: str, args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    # Check before any probe, subprocess, or provenance write. The coordinator
    # repeats this check as the race guard inside the isolated user namespace.
    if output.exists():
        print(f"output already exists: {output}", file=sys.stderr); return 2
    before = host_network_identity()
    if not before["supported"]:
        output.mkdir(parents=True)
        dump_json(output / "network-provenance.json", {
            "type": "turtle-network-provenance", "schema": 1,
            "status": "unsupported", "reason": "host network identity could not be observed",
            "host_network_identity": {"before": before, "after": None, "unchanged": None}})
        return 2
    argv = ["unshare", "--user", "--map-root-user", "--net", "--",
            sys.executable, str(Path(__file__).resolve()), "_coordinator", command,
            "--build", str(Path(args.build).resolve()), "--profile", str(Path(args.profile).resolve()),
            "--net-profile", str(Path(args.net_profile).resolve()), "--samples", str(args.samples),
            "--output", str(Path(args.output).resolve())]
    try:
        returncode = subprocess.run(argv).returncode
    except FileNotFoundError:
        print("unshare is required", file=sys.stderr); return 2
    after = host_network_identity()
    unchanged = compare_host_identity(before, after)
    provenance_path = output / "network-provenance.json"
    if provenance_path.is_file():
        provenance = json.loads(provenance_path.read_text())
        provenance["host_network_identity"] = {"before": before, "after": after,
                                                "unchanged": unchanged}
        if unchanged is not True:
            field = "secondary_reasons" if provenance.get("status") not in ("complete", "probe-complete") else "reason"
            reason = ("host network identity changed" if unchanged is False
                      else "host network identity could not be observed")
            if field == "reason":
                provenance.update(status="error" if unchanged is False else "unsupported", reason=reason)
            else:
                provenance.setdefault(field, []).append(reason)
        dump_json(provenance_path, provenance)
    if unchanged is None:
        print("host network identity could not be observed", file=sys.stderr)
        return returncode if returncode != 0 else 2
    if unchanged is False:
        print("host network identity changed during isolated run", file=sys.stderr)
        return returncode if returncode != 0 else 1
    return returncode


def host_network_identity() -> dict[str, Any]:
    result: dict[str, Any] = {"supported": True, "errors": []}
    try:
        result["network_namespace_inode"] = os.stat("/proc/self/ns/net").st_ino
    except OSError as error:
        result["network_namespace_inode"] = None
        result["errors"].append({"component": "network_namespace", "reason": str(error)})
    for name, argv in (("links", ["ip", "-j", "link", "show"]),
                       ("routes", ["ip", "-j", "route", "show", "table", "all"]),
                       ("qdiscs", ["tc", "-j", "qdisc", "show"])):
        try:
            command = subprocess.run(argv, text=True, capture_output=True, timeout=2)
            if command.returncode != 0:
                result[name] = None
                result["errors"].append({"component": name,
                                         "reason": f"exit {command.returncode}: {command.stderr.strip()}"})
            else:
                result[name] = json.loads(command.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            result[name] = None
            result["errors"].append({"component": name, "reason": str(error)})
    result["supported"] = not result["errors"] and all(
        result.get(name) is not None for name in ("network_namespace_inode", "links", "routes", "qdiscs"))
    return result


def compare_host_identity(before: dict[str, Any], after: dict[str, Any]) -> bool | None:
    if not before.get("supported") or not after.get("supported"):
        return None
    fields = ("network_namespace_inode", "links", "routes", "qdiscs")
    return all(before[field] == after[field] for field in fields)


def probe(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists():
        print(f"output already exists: {output}", file=sys.stderr); return 2
    output.mkdir(parents=True)
    profile = default_net_profile("netem")
    profile["paths"]["ca_s2c"]["delay_ms"] = 1
    probe_profile = output / "probe-net-profile.json"; dump_json(probe_profile, profile)
    # The hidden coordinator can probe without a turtle run.
    argv = ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
            str(Path(__file__).resolve()), "_probe", "--net-profile", str(probe_profile),
            "--output", str(output)]
    before = host_network_identity()
    if not before["supported"]:
        dump_json(output / "network-provenance.json", {
            "type": "turtle-network-provenance", "schema": 1,
            "status": "unsupported", "reason": "host network identity could not be observed",
            "host_network_identity": {"before": before, "after": None, "unchanged": None}})
        return 2
    result = subprocess.run(argv)
    after = host_network_identity()
    unchanged = compare_host_identity(before, after)
    provenance_path = output / "network-provenance.json"
    if provenance_path.is_file():
        provenance = json.loads(provenance_path.read_text())
        provenance["host_network_identity"] = {"before": before, "after": after,
                                                "unchanged": unchanged}
        if unchanged is not True:
            reason = ("host network identity changed" if unchanged is False
                      else "host network identity could not be observed")
            if provenance.get("status") == "probe-complete":
                provenance.update(status="error" if unchanged is False else "unsupported", reason=reason)
            else:
                provenance.setdefault("secondary_reasons", []).append(reason)
        dump_json(provenance_path, provenance)
    if unchanged is None: return result.returncode if result.returncode != 0 else 2
    if unchanged is False: return result.returncode if result.returncode != 0 else 1
    return result.returncode


def probe_coordinator(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve(); topology = None; terminal_code = 1
    try:
        profile = validate_net_profile(json.loads(Path(args.net_profile).read_text()), True)
        topology = OwnedTopology(profile, output, True); topology.setup()
        topology.provenance["tcp_info_probe"] = probe_tcp_info(topology)
        topology.provenance["status"] = "probe-complete"; topology.save()
        terminal_code = 0; return terminal_code
    except SetupUnsupported as error:
        if topology: topology.provenance.update(status="unsupported", reason=str(error)); topology.save()
        print(error, file=sys.stderr); terminal_code = 2; return terminal_code
    except Exception as error:
        if topology: topology.provenance.update(status="error", reason=str(error)); topology.save()
        print(error, file=sys.stderr); terminal_code = 1; return terminal_code
    finally:
        if topology:
            failures = topology.cleanup()
            if failures:
                print("; ".join(failures), file=sys.stderr)
                if terminal_code == 0:
                    return 1


def probe_tcp_info(topology: OwnedTopology) -> dict[str, Any]:
    """Exercise a routed TCP flow and preserve returned TCP_INFO lengths/support."""
    server_code = (
        "import json,socket; "
        "s=socket.socket(); s.bind(('10.203.2.2',0)); s.listen(1); "
        "print(s.getsockname()[1],flush=True); c,_=s.accept(); c.recv(1); c.sendall(b'y'); "
        "i=c.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,256); "
        "print(json.dumps({'structure_bytes':len(i)}),flush=True)"
    )
    client_code = (
        "import json,socket,sys; s=socket.socket(); s.bind(('10.203.1.2',0)); "
        "s.connect(('10.203.2.2',int(sys.argv[1]))); s.sendall(b'x'); assert s.recv(1)==b'y'; "
        "i=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,256); "
        "print(json.dumps({'structure_bytes':len(i)}))"
    )
    server_argv = ["nsenter", "-t", str(topology.helpers["server"].pid), "-n", "--",
                   sys.executable, "-c", server_code]
    server = subprocess.Popen(server_argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        port_line = server.stdout.readline()
        if not port_line:
            raise SetupUnsupported(f"TCP_INFO probe server failed: {server.stderr.read().strip()}")
        client = topology.commands.ns(topology.helpers["client"].pid,
                                      [sys.executable, "-c", client_code, port_line.strip()])
        try:
            server_stdout, server_stderr = server.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            server.kill(); server_stdout, server_stderr = server.communicate()
            raise SetupUnsupported("TCP_INFO probe server did not finish")
        topology.provenance["commands"].append({"argv": server_argv, "returncode": server.returncode,
                                                 "stdout": port_line + server_stdout,
                                                 "stderr": server_stderr})
        if server.returncode:
            raise SetupUnsupported(f"TCP_INFO probe server failed: {server_stderr.strip()}")
        server_result, client_result = json.loads(server_stdout), json.loads(client.stdout)
        minimum = {"total_retrans": 104, "snd_mss": 20, "rcv_mss": 24,
                   "segs_out": 140, "segs_in": 144, "bytes_acked": 128,
                   "bytes_received": 136}
        for result in (server_result, client_result):
            result["field_support"] = {name: result["structure_bytes"] >= length
                                       for name, length in minimum.items()}
        return {"server": server_result, "client": client_result,
                "flow": {"source": "10.203.1.2", "destination": "10.203.2.2",
                         "server_port": int(port_line)}}
    finally:
        if server.poll() is None:
            server.kill(); server.wait()


def default_net_profile(qdisc: str = "netem") -> dict[str, Any]:
    return {"type": "turtle-netem-profile", "schema": 1, "qdisc": qdisc, "mtu": 1500,
            "offload": {"tso": False, "gso": False, "gro": False}, "trace": True,
            "loss_seed": None,
            "paths": {name: {"delay_ms": 0, "loss_percent": 0.0, "limit_packets": 10000}
                      for name in PATH_INTERFACES}}


def verify_pki(pki: Path) -> bytes:
    required = ("ca.pem", "server.pem", "server-chain.pem", "server.key")
    if any(not (pki / name).is_file() for name in required):
        raise SetupUnsupported("verify requires a pre-created ECDSA three-certificate PKI")
    chain = (pki / "server-chain.pem").read_bytes()
    blocks = re.findall(br"-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n", chain)
    if not 1 <= len(chain) <= MAX_OBJECT or len(blocks) != 3 or b"".join(blocks) != chain:
        raise SetupUnsupported("server-chain.pem must contain exactly three PEM certificates")
    for block in blocks:
        cert = subprocess.run(["openssl", "x509", "-noout", "-text"], input=block,
                              capture_output=True)
        if cert.returncode or b"Public Key Algorithm: id-ecPublicKey" not in cert.stdout:
            raise SetupUnsupported("all server-chain certificates must use ECDSA public keys")
    key = subprocess.run(["openssl", "pkey", "-in", str(pki / "server.key"), "-text", "-noout"],
                         capture_output=True, text=True)
    if key.returncode or "ASN1 OID: prime256v1" not in key.stdout:
        raise SetupUnsupported("server key is not an ECDSA P-256 key")
    verify = subprocess.run(["openssl", "verify", "-CAfile", str(pki / "ca.pem"),
                             "-untrusted", str(pki / "intermediates.pem"), str(pki / "server.pem")],
                            capture_output=True, text=True)
    if verify.returncode:
        raise SetupUnsupported("server certificate chain verification failed")
    return chain


def verification_profile(pki: Path, samples: int, timeout_ms: int,
                         snapshot: Path | None = None) -> dict[str, Any]:
    return {"name": "synthetic-lookup-plus-standard-tls", "pki": str(pki),
            "tls": {"version": "TLS1.3", "cipher": "TLS_AES_128_GCM_SHA256",
                    "group": "secp256r1", "signature": "ecdsa_secp256r1_sha256",
                    "server_name": "localhost", "mutual_auth": False, "compatibility_ccs": True,
                    "framework_io": True, "tickets": 0, "application_bytes": 32,
                    "record_size_limit": 0, "certificate_compression": False},
            "socket": {"tcp_nodelay": True, "send_buffer": 65536, "receive_buffer": 65536},
            "measurement": {"samples": samples, "connections": 1, "warmups": 0,
                            "timeout_ms": timeout_ms, "failure_policy": "fixed-attempts",
                            "flush_grace_ms": 500, "ca_cpu": -1, "pin_cores": False,
                            "perf": False},
            "lookup": {"enabled": True, "object_file": str(pki / "server-chain.pem"),
                       "cache_mode": "fixed-snapshot" if snapshot else "empty",
                       "snapshot_file": str(snapshot) if snapshot else None},
            "technique": {"name": "synthetic-certificate-lookup"}}


def verify(args: argparse.Namespace) -> int:
    root, pki = Path(args.output).resolve(), Path(args.pki).resolve()
    if root.exists(): print(f"output already exists: {root}", file=sys.stderr); return 2
    root.mkdir(parents=True)
    try: chain = verify_pki(pki)
    except SetupUnsupported as error:
        dump_json(root / "verification-manifest.json", {"type": "turtle-netem-verification", "schema": 1,
                  "status": "unsupported", "reason": str(error), "runs": []})
        print(error, file=sys.stderr); return 2
    snapshot_file = root / "fixed-snapshot.json"
    dump_json(snapshot_file, make_snapshot(pki / "server-chain.pem"))
    specs = []
    for name, qdisc, delay in (("baseline", "none", 0), ("zero", "netem", 0), ("delay-20ms", "netem", 20)):
        net = default_net_profile(qdisc)
        if qdisc == "netem": net["paths"]["ca_s2c"]["delay_ms"] = delay
        specs.append((name, 8, 10000, net, "diagnostic", None))
    tls_only = default_net_profile(); tls_only["paths"]["tls_s2c"]["delay_ms"] = 20
    specs.append(("tls-only-20ms", 8, 10000, tls_only, "selectivity", None))
    loss = default_net_profile(); loss["paths"]["ca_s2c"].update(delay_ms=5, loss_percent=20.0)
    specs.append(("loss-ca-s2c-5ms-20pct", 64, 10000, loss, "loss", None))
    timeout = default_net_profile(); timeout["paths"]["ca_s2c"]["delay_ms"] = 1000
    specs.append(("timeout-ca-s2c-1000ms", 3, 100, timeout, "timeout", None))
    specs.append(("warm-hit-request0", 1, 10000, default_net_profile(), "warm-hit", snapshot_file))
    manifest = {"type": "turtle-netem-verification", "schema": 1, "status": "running",
                "object_id": fnv1a64(chain), "object_size": len(chain),
                "fixed_before_execution": True, "runs": []}
    unsupported_checked = False
    seeded = default_net_profile(); seeded["loss_seed"] = 1
    try: validate_net_profile(seeded)
    except SetupUnsupported: unsupported_checked = True
    manifest["unsupported_checks"] = {"explicit_loss_seed_rejected": unsupported_checked}
    for name, samples, timeout_ms, net, gate, snapshot in specs:
        profile_file, net_file = root / f"{name}.profile.json", root / f"{name}.net.json"
        dump_json(profile_file, verification_profile(pki, samples, timeout_ms, snapshot)); dump_json(net_file, net)
        manifest["runs"].append({"name": name, "samples": samples, "connections": 1, "warmups": 0,
                                 "timeout_ms": timeout_ms, "net_profile": net,
                                 "gate": gate, "output": str(root / name), "status": "not-started"})
    dump_json(root / "verification-manifest.json", manifest)
    unsupported = False
    for row in manifest["runs"]:
        row["status"] = "running"; dump_json(root / "verification-manifest.json", manifest)
        namespace = argparse.Namespace(build=args.build, profile=root / f'{row["name"]}.profile.json',
                                      net_profile=root / f'{row["name"]}.net.json', samples=row["samples"],
                                      output=Path(row["output"]))
        rc = outer_isolated("run", namespace)
        row.update(status="complete" if rc == 0 else ("unsupported" if rc == 2 else "failed"), returncode=rc)
        dump_json(root / "verification-manifest.json", manifest)
        if rc == 2: unsupported = True; break
    if unsupported:
        manifest["status"] = "unsupported"; dump_json(root / "verification-manifest.json", manifest); return 2
    integrity_ok = True
    for row in manifest["runs"]:
        ok, integrity_reasons = evaluate_run_integrity(row)
        row["integrity"] = {"proven": ok, "reasons": integrity_reasons}
        integrity_ok &= ok
    loss_row = next(row for row in manifest["runs"] if row["gate"] == "loss")
    proven, reasons, window_details = evaluate_loss_gate_with_details(Path(loss_row["output"]), 64)
    manifest["loss_gate"] = {"proven": proven, "reasons": reasons,
                             "scenario_windows": window_details}
    diagnostic_ok = all(r["integrity"]["proven"] and has_packet_flow(Path(r["output"]))
                        for r in manifest["runs"] if r["gate"] in ("diagnostic", "selectivity"))
    timeout_row = next(row for row in manifest["runs"] if row["gate"] == "timeout")
    timeout_ok, timeout_reasons = evaluate_timeout_gate(Path(timeout_row["output"]), 3)
    warm_row = next(row for row in manifest["runs"] if row["gate"] == "warm-hit")
    warm_ok, warm_reasons = evaluate_warm_hit(Path(warm_row["output"]))
    manifest["diagnostic_conditions_proven"] = diagnostic_ok
    manifest["timeout_gate"] = {"proven": timeout_ok, "reasons": timeout_reasons}
    manifest["warm_hit_gate"] = {"proven": warm_ok, "reasons": warm_reasons}
    manifest["status"] = "complete" if (integrity_ok and proven and diagnostic_ok and timeout_ok and
                                          warm_ok and unsupported_checked) else "validation-unproven"
    dump_json(root / "verification-manifest.json", manifest)
    return 0 if manifest["status"] == "complete" else 1


def evaluate_run_integrity(row: dict[str, Any]) -> tuple[bool, list[str]]:
    output, returncode, gate = Path(row["output"]), row.get("returncode"), row.get("gate")
    reasons = []
    provenance_file = output / "network-provenance.json"
    if not provenance_file.is_file():
        return False, ["network provenance missing"]
    try: provenance = json.loads(provenance_file.read_text())
    except (OSError, json.JSONDecodeError) as error: return False, [f"network provenance unreadable: {error}"]
    host = provenance.get("host_network_identity", {})
    if (host.get("unchanged") is not True or
            not host.get("before", {}).get("supported") or
            not host.get("after", {}).get("supported")):
        reasons.append("supported unchanged host network identity was not proven")
    lifecycle = provenance.get("lifecycle", {})
    if lifecycle.get("namespace_fds_closed") is not True or lifecycle.get("owned_pipe_fds_closed") is not True:
        reasons.append("owned descriptor cleanup was not proven")
    if provenance.get("secondary_cleanup_failures"):
        reasons.append("owned cleanup reported secondary failures")
    if (output / "network-cleanup-errors.json").exists() or (output / "network-provenance.partial.json").exists():
        reasons.append("final cleanup/provenance evidence is partial")
    cleanup_rows = provenance.get("cleanup", [])
    for item in cleanup_rows:
        if "fatal-not-reaped" in item.values(): reasons.append("an owned process was not reaped")
    helpers = {item.get("helper") for item in cleanup_rows
               if item.get("result") in ("reaped", "killed")}
    observer_done = any(item.get("observer") in ("reaped", "killed-after-500ms")
                        for item in cleanup_rows)
    topology_kind = provenance.get("condition_identity", {}).get("topology", {}).get("kind")
    expected_helpers = {
        "three-netns-receiver-facing-router-egress": {"client", "server", "router"},
        "four-netns-receiver-facing-router-egress": {"client", "server", "ca", "router"},
    }.get(topology_kind)
    trace_requested = provenance.get("condition_identity", {}).get("trace", {}).get("requested")
    if expected_helpers is None or helpers != expected_helpers or observer_done is not trace_requested or \
            provenance.get("finished_monotonic_ns") is None:
        reasons.append("complete owned helper/observer cleanup inventory is missing")
    allowed_failed_director = gate in ("loss", "timeout") and returncode == 1
    if returncode == 0:
        if provenance.get("status") != "complete" or provenance.get("director", {}).get("returncode") != 0:
            reasons.append("successful runner lacks complete director provenance")
    elif allowed_failed_director:
        if (provenance.get("status") != "director-failed" or
                provenance.get("director", {}).get("returncode") != 1):
            reasons.append("nonzero result was not a preserved director outcome")
        ledger = output / "attempts.jsonl"
        try:
            finals = [item for item in map(json.loads, ledger.read_text().splitlines())
                      if item.get("record_kind") == "attempt_final"]
        except (OSError, json.JSONDecodeError): finals = []
        if not finals or any(item.get("final_status") not in ("success", "timeout") for item in finals):
            reasons.append("nonzero director result contains arbitrary error/incomplete outcomes")
    else:
        reasons.append(f"unexpected runner return code {returncode}")
    return not reasons, reasons


def evaluate_loss_gate(output: Path, attempts: int) -> tuple[bool, list[str]]:
    proven, reasons, _ = evaluate_loss_gate_with_details(output, attempts)
    return proven, reasons


def evaluate_loss_gate_with_details(output: Path, attempts: int) -> tuple[bool, list[str], list[dict[str, Any]]]:
    reasons = []
    window_details: list[dict[str, Any]] = []
    final_by_attempt: dict[int, dict[str, Any]] = {}
    ledger = output / "attempts.jsonl"
    if not ledger.is_file(): reasons.append("attempt ledger missing")
    else:
        rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        started = {r.get("attempt_id") for r in rows if r.get("record_kind") == "attempt_started"}
        expected_attempts = set(range(1, attempts + 1))
        if started != expected_attempts:
            reasons.append(f"expected exact started attempt IDs 1..{attempts}, observed {sorted(started, key=str)}")
        finals = [r for r in rows if r.get("record_kind") == "attempt_final"]
        final_by_attempt = {r["attempt_id"]: r for r in finals if isinstance(r.get("attempt_id"), int)}
        summaries = [r for r in rows if r.get("record_kind") == "run_summary"]
        if len(finals) != attempts: reasons.append(f"expected {attempts} final attempts, observed {len(finals)}")
        if set(final_by_attempt) != expected_attempts:
            reasons.append(f"expected exact final attempt IDs 1..{attempts}, observed {sorted(final_by_attempt)}")
        if any(r.get("final_status") not in ("success", "timeout") for r in finals):
            reasons.append("loss gate contains error or incomplete attempt outcomes")
        if len(summaries) != 1 or summaries[0].get("requested") != attempts or \
                summaries[0].get("started") != attempts:
            reasons.append("attempt summary denominator identity missing or inconsistent")
    observations = output / "network-observations.jsonl"
    drops = None
    if observations.is_file():
        rows = list(map(json.loads, observations.read_text().splitlines()))
        by_attempt: dict[int, dict[str, dict[str, Any]]] = {}
        for row in rows:
            if row.get("phase") == "scenario" and isinstance(row.get("qdiscs"), dict):
                by_attempt.setdefault(row["attempt"], {})[row["edge"]] = row
        drops = 0
        for attempt in range(1, attempts + 1):
            pair = by_attempt.get(attempt, {})
            if set(pair) != {"begin", "end"}:
                final = final_by_attempt.get(attempt, {})
                phase = final.get("failure_phase")
                actual_begin = "begin" in pair
                scenario_started = actual_begin or phase in ("scenario", "flush", "exit") or final.get("final_status") == "success"
                status = "missing-unproven" if scenario_started else "not-applicable-before-scenario"
                window_details.append({"attempt": attempt, "status": status, "failure_phase": phase})
                if scenario_started: reasons.append(f"attempt {attempt} started scenario qdisc window missing")
                continue
            values = []
            for edge in ("begin", "end"):
                qdiscs = pair[edge].get("qdiscs")
                raw = qdiscs.get("ca_s2c", {}).get("raw", []) if isinstance(qdiscs, dict) else []
                root = next((item for item in raw if item.get("root")), None)
                values.append(root.get("drops") if root else None)
            if any(value is None for value in values):
                window_details.append({"attempt": attempt, "status": "counter-missing",
                                       "failure_phase": final_by_attempt.get(attempt, {}).get("failure_phase")})
                reasons.append(f"attempt {attempt} CA s2c drop counter unsupported"); continue
            delta = values[1] - values[0]
            if delta < 0: reasons.append(f"attempt {attempt} CA s2c drop counter regressed")
            else:
                drops += delta
                window_details.append({"attempt": attempt, "status": "observed", "drop_delta": delta,
                                       "failure_phase": final_by_attempt.get(attempt, {}).get("failure_phase")})
    if not drops: reasons.append("positive qdisc drop evidence missing")
    if not has_ca_packet_flow(output):
        reasons.append("packet flow evidence missing")
    provenance = output / "network-provenance.json"
    if not provenance.is_file(): reasons.append("network namespace provenance missing")
    else:
        data = json.loads(provenance.read_text())
        if data.get("condition_identity", {}).get("topology", {}).get("addresses") != ADDRESSES:
            reasons.append("CA flow namespace/address provenance mismatch")
    retrans = 0; supported = False
    for summary in output.glob("sample-*/ca.jsonl"):
        for row in map(json.loads, summary.read_text().splitlines()):
            if row.get("record_kind") != "connection_summary": continue
            start, end = row.get("tcp_start"), row.get("tcp_end")
            if isinstance(start, dict) and isinstance(end, dict) and \
                    start.get("total_retrans") is not None and end.get("total_retrans") is not None:
                supported = True
                delta = end["total_retrans"] - start["total_retrans"]
                if delta < 0: reasons.append(f"TCP total_retrans regressed in {summary}")
                else: retrans += delta
    if not supported or retrans <= 0: reasons.append("positive CA TCP_INFO total_retrans delta evidence missing")
    return not reasons, reasons, window_details


def has_packet_flow(output: Path) -> bool:
    packets = output / "packets.jsonl"
    return packets.is_file() and any(json.loads(line).get("record_kind") == "packet"
                                     for line in packets.read_text().splitlines())


def has_ca_packet_flow(output: Path) -> bool:
    packets = output / "packets.jsonl"
    if not packets.is_file(): return False
    for row in map(json.loads, packets.read_text().splitlines()):
        flow = row.get("flow", {})
        if (row.get("record_kind") == "packet" and row.get("logical_path") == "ca_s2c" and
                flow.get("source") == ADDRESSES["ca"] and flow.get("destination") == ADDRESSES["client_ca"] and
                row.get("tcp", {}).get("payload_length", 0) > 0):
            return True
    return False


def evaluate_timeout_gate(output: Path, attempts: int) -> tuple[bool, list[str]]:
    reasons = []
    ledger = output / "attempts.jsonl"
    if not ledger.is_file():
        return False, ["attempt ledger missing"]
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    started = [row for row in rows if row.get("record_kind") == "attempt_started"]
    finals = [row for row in rows if row.get("record_kind") == "attempt_final"]
    expected = set(range(1, attempts + 1))
    if ({row.get("attempt_id") for row in started} != expected or
            {row.get("attempt_id") for row in finals} != expected or
            len(started) != attempts or len(finals) != attempts):
        reasons.append(f"expected {attempts} started/final attempts")
    if not finals or any(row.get("final_status") != "timeout" for row in finals):
        reasons.append("fixed high-delay attempts did not all retain timeout status")
    return not reasons, reasons


def evaluate_warm_hit(output: Path) -> tuple[bool, list[str]]:
    reasons = []
    lookup = output / "sample-000001" / "lookup.jsonl"
    if not lookup.is_file():
        return False, ["warm-hit lookup artifact missing"]
    rows = [json.loads(line) for line in lookup.read_text().splitlines()]
    kinds = [row.get("kind") for row in rows if row.get("record_kind") == "event"]
    if "CACHE_HIT" not in kinds and "HIT" not in kinds: reasons.append("cache hit event missing")
    sent = output / "sample-000001" / "lookup-0.sent.bin"
    ca_received = output / "sample-000001" / "ca-0.received.bin"
    if not sent.is_file() or sent.stat().st_size != 0: reasons.append("warm hit sent an application request")
    if not ca_received.is_file() or ca_received.stat().st_size != 0: reasons.append("CA received an application request on warm hit")
    packets = output / "packets.jsonl"
    setup_packet = False
    if packets.is_file():
        for row in map(json.loads, packets.read_text().splitlines()):
            flow = row.get("flow", {})
            if (row.get("record_kind") == "packet" and
                    {flow.get("source"), flow.get("destination")} == {ADDRESSES["ca"], ADDRESSES["client_ca"]}):
                setup_packet = True; break
    if not setup_packet: reasons.append("warm-hit CA TCP preparation packets missing")
    return not reasons, reasons


def observer(args: argparse.Namespace) -> int:
    try:
        enter_netns(args.router_fd)
    except OSError as error:
        raise OSError(error.errno, f"cannot enter router network namespace: {error.strerror}") from error
    control = socket.socket(fileno=args.control_fd); control.setblocking(False)
    output = Path(args.output)
    sockets = {}
    interfaces = args.interfaces.split(",")
    if not interfaces or len(set(interfaces)) != len(interfaces) or any(name not in PATH_INTERFACES.values() for name in interfaces):
        raise ValueError("observer interfaces must be a nonempty unique fixed-topology subset")
    for interface in interfaces:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        try:
            raw.bind((interface, 0))
        except OSError as error:
            raw.close()
            raise OSError(error.errno, f"cannot bind observer to {interface}: {error.strerror}") from error
        raw.setblocking(False)
        sockets[raw] = interface
    append_json(output, {"type": "turtle-packet-trace", "schema": 1, "record_kind": "header",
                         "clock": "CLOCK_MONOTONIC", "observation_point": "router-veth-af_packet",
                         "packet_unit": "observed-skb-not-physical-wire", "interfaces": list(sockets.values())})
    buffer = bytearray(); running = True
    while running:
        ready, _, _ = select.select([control, *sockets], [], [], .1)
        for source in ready:
            if source is control:
                try: line = recv_line(control, buffer)
                except BlockingIOError: continue
                if line is None: running = False; break
                marker = json.loads(line); marker.update(type="turtle-packet-trace", schema=1, record_kind="marker")
                append_json(output, marker)
                identity = marker.get("observation_id", marker["kind"])
                control.sendall(json.dumps({"ack": identity}, separators=(",", ":")).encode() + b"\n")
                if marker["kind"] == "capture-stop": running = False
            else:
                try: frame, address = source.recvfrom(65535)
                except BlockingIOError: continue
                row = decode_packet(frame, sockets[source], address[2] == getattr(socket, "PACKET_OUTGOING", 4))
                if row: append_json(output, row)
    stats = {}
    for raw, interface in sockets.items():
        try:
            packets, drops = struct.unpack("II", raw.getsockopt(263, 6, 8)); stats[interface] = {"packets": packets, "drops": drops}
        except OSError as error: stats[interface] = {"packets": None, "drops": None, "reason": str(error)}
        raw.close()
    append_json(output, {"type": "turtle-packet-trace", "schema": 1, "record_kind": "footer",
                         "monotonic_ns": time.monotonic_ns(), "capture_socket_statistics": stats})
    return 0


def decode_packet(frame: bytes, interface: str, outgoing: bool) -> dict[str, Any] | None:
    if len(frame) < 54 or struct.unpack_from("!H", frame, 12)[0] != 0x0800: return None
    ihl = (frame[14] & 0x0f) * 4
    if len(frame) < 14 + ihl + 20 or frame[23] != 6: return None
    tcp = 14 + ihl; source, destination = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    source_port, destination_port, sequence, acknowledgement = struct.unpack_from("!HHII", frame, tcp)
    data_offset = (frame[tcp + 12] >> 4) * 4
    total = struct.unpack_from("!H", frame, 16)[0]
    direction = "egress" if outgoing else "ingress"
    mapping = {("rctls", "ingress"): "tls_c2s", ("rctls", "egress"): "tls_s2c",
               ("rstls", "ingress"): "tls_s2c", ("rstls", "egress"): "tls_c2s",
               ("rcca", "ingress"): "ca_c2s", ("rcca", "egress"): "ca_s2c",
               ("rca0", "ingress"): "ca_s2c", ("rca0", "egress"): "ca_c2s"}
    return {"type": "turtle-packet-trace", "schema": 1, "record_kind": "packet",
            "monotonic_ns": time.monotonic_ns(), "interface": interface, "direction": direction,
            "logical_path": mapping[(interface, direction)],
            "flow": {"source": source, "source_port": source_port,
                     "destination": destination, "destination_port": destination_port, "protocol": "tcp"},
            "tcp": {"sequence": sequence, "acknowledgement": acknowledgement,
                    "flags": frame[tcp + 13], "payload_length": max(0, total - ihl - data_offset)},
            "frame_length": len(frame), "packet_unit": "observed-skb-not-physical-wire"}


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser(description=__doc__); sub = main.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot"); snap.add_argument("--object", type=Path, required=True); snap.add_argument("--output", type=Path, required=True)
    probe_p = sub.add_parser("probe"); probe_p.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run"); run.add_argument("--build", type=Path, required=True); run.add_argument("--profile", type=Path, required=True); run.add_argument("--net-profile", type=Path, required=True); run.add_argument("--samples", type=int); run.add_argument("--output", type=Path, required=True)
    verify_p = sub.add_parser("verify"); verify_p.add_argument("--build", type=Path, required=True); verify_p.add_argument("--pki", type=Path, required=True); verify_p.add_argument("--output", type=Path, required=True); verify_p.add_argument("--require-supported", action="store_true")
    hidden = sub.add_parser("_coordinator"); hidden.add_argument("mode", choices=("run",)); hidden.add_argument("--build", required=True); hidden.add_argument("--profile", required=True); hidden.add_argument("--net-profile", required=True); hidden.add_argument("--samples", type=int, required=True); hidden.add_argument("--output", required=True)
    hidden_probe = sub.add_parser("_probe"); hidden_probe.add_argument("--net-profile", required=True); hidden_probe.add_argument("--output", required=True)
    obs = sub.add_parser("_observer"); obs.add_argument("--router-fd", type=int, required=True); obs.add_argument("--control-fd", type=int, required=True); obs.add_argument("--interfaces", required=True); obs.add_argument("--output", required=True)
    return main


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "snapshot":
            dump_json_exclusive(args.output, make_snapshot(args.object)); return 0
        if args.command == "probe": return probe(args)
        if args.command == "run":
            document = json.loads(args.profile.read_text())
            args.samples = resolve_samples(document, args.samples)
            executable = args.build / "turtle"
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise SetupUnsupported("built turtle executable is missing or not executable")
            return outer_isolated("run", args)
        if args.command == "verify": return verify(args)
        if args.command == "_coordinator": return run_coordinator(args)
        if args.command == "_probe": return probe_coordinator(args)
        if args.command == "_observer": return observer(args)
    except SetupUnsupported as error:
        print(error, file=sys.stderr); return 2
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr); return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
