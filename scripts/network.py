#!/usr/bin/env python3
"""소유 네임스페이스의 방향별 netem과 원본 패킷·커널 관측을 실행합니다."""
from __future__ import annotations
import uuid,resource
import argparse,copy,ctypes,hashlib,json,os,re,select,shutil,signal,socket,struct,subprocess,sys,time
from pathlib import Path
from typing import Any
from run import run

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


def dump_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def append_json(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


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
        self.profile = copy.deepcopy(profile)
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
        self.kernel_observer: subprocess.Popen | None = None
        self.kernel_control: socket.socket | None = None
        self.provenance: dict[str, Any] = {
            "contract": "turtle-message-network/1",
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
        self.provenance["condition_identity"]["privilege"] = {
            "uid": os.geteuid(),
            "user_namespace_inode": os.stat("/proc/self/ns/user").st_ino,
        }
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
            cwnd = self.profile.get("initial_cwnd", {}).get(owner) if interface in ("ctls", "stls") else None
            self.commands.ns(self.helpers[owner].pid,
                             ["ip", "route", "add", network, "via", gateway, "dev", interface] +
                             (["initcwnd", str(cwnd)] if cwnd is not None else []))
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

    def start_kernel_observer(self, build: Path) -> None:
        if not self.profile.get("kernel_events", False):
            return
        obj = build.resolve() / "kernel-observer.bpf.o"
        manifest = obj.with_suffix(".json")
        if not obj.is_file() or not manifest.is_file():
            raise SetupUnsupported("run scripts/build-kernel-observer.py before kernel-events experiments")
        provenance = json.loads(manifest.read_text())
        source = Path(__file__).with_name("kernel-observer.bpf.c")
        if (provenance["object_sha256"] != hashlib.sha256(obj.read_bytes()).hexdigest() or
                provenance["source_sha256"] != hashlib.sha256(source.read_bytes()).hexdigest()):
            raise SetupUnsupported("kernel observer object does not match its source/build manifest")
        dump_json(self.output / "kernel-observer-build.json", provenance)
        parent, child = socket.socketpair()
        self.kernel_control = parent
        command = [sys.executable, str(Path(__file__).with_name("kernel_observer.py").resolve()),
                   "--object", str(obj), "--output", str(self.output / "kernel-events.json"),
                   "--control-fd", str(child.fileno()),"--run-id",self.provenance["run_id"]]
        for name in ("client", "server", "router"):
            command += [f"--{name}-fd", str(self.ns_fds[name])]
        for direction, option in (("tls_c2s", "--c2s-target"), ("tls_s2c", "--s2c-target")):
            offset = self.profile["targeted_drop"][direction]
            if offset is not None: command += [option, str(offset)]
        try:
            with (self.output / "kernel-observer.log").open("w") as log:
                self.kernel_observer = subprocess.Popen(command, stdout=log, stderr=log,
                    pass_fds=(child.fileno(), *(self.ns_fds[name] for name in ("client", "server", "router"))))
        finally:
            child.close()
        ready, _, _ = select.select([parent], [], [], 10)
        if not ready or parent.recv(1) != b"R":
            raise SetupUnsupported("kernel observer did not become ready; see kernel-observer.log and kernel-events.json")
        self.provenance["kernel_observer"] = {"pid": self.kernel_observer.pid,
            "status": "ready", "source": "kernel-events.json", "object_sha256": provenance["object_sha256"]}
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
            requested_cwnd = self.profile.get("initial_cwnd", {}).get(owner) if expected[3] in ("ctls", "stls") else None
            if requested_cwnd is not None:
                metrics = readback[0].get("metrics", [])
                actual_cwnd = next((item.get("initcwnd") for item in metrics if "initcwnd" in item), None)
                if actual_cwnd != requested_cwnd:
                    raise SetupUnsupported(f"initial cwnd route readback differs for {owner}")
            self.provenance["routes"].append({"namespace": owner, "destination": destination,
                                               "source": source, "readback": readback, "verified": True})

    def _qdisc_readback(self) -> dict[str, Any]:
        result = {}
        router = self.helpers["router"].pid
        for path, interface in self.path_interfaces.items():
            raw = json.loads(self.commands.ns(router, ["tc", "-j", "-s", "qdisc", "show", "dev", interface]).stdout)
            roots = [entry for entry in raw if entry.get("kind") == "netem"] or [entry for entry in raw if entry.get("root")]
            result[path] = {"interface": interface, "requested": self.profile["paths"][path],
                            "raw": raw, "root_kind": roots[0].get("kind") if roots else None}
        return result

    @staticmethod
    def _stable_qdisc(readback: dict[str, Any]) -> dict[str, Any]:
        """Keep condition fields; counters, handles and kernel refcounts are outcomes/provenance."""
        stable = {}
        for path, value in readback.items():
            roots = [entry for entry in value["raw"] if entry.get("kind") == "netem"] or [entry for entry in value["raw"] if entry.get("root")]
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
            if "rate_bps" in value["requested"]:
                rate = options.get("rate", {}).get("rate")
                stable[path]["rate_bps"] = rate * 8 if rate else None
        return stable

    def reset_qdiscs(self) -> dict[str, Any]:
        router = self.helpers["router"].pid
        for path, interface in self.path_interfaces.items():
            self.commands.ns(router, ["tc", "qdisc", "del", "dev", interface, "root"], check=False)
            if self.profile["qdisc"] == "netem":
                policy = self.profile["paths"][path]
                # Put only the data flow into netem. Control TCP remains in band 1.
                self.commands.ns(router, ["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:",
                                          "prio", "bands", "3", "priomap"] + ["0"] * 16)
                match_port = "44330" if path.startswith("tls_") else "44332"
                port_field = "dport" if path.endswith("c2s") else "sport"
                self.commands.ns(router, ["tc", "filter", "add", "dev", interface, "protocol", "ip",
                                          "parent", "1:", "prio", "1", "u32", "match", "ip", "protocol", "6", "0xff",
                                          "match", "ip", port_field, match_port, "0xffff", "flowid", "1:2"])
                self.commands.ns(router, ["tc", "qdisc", "add", "dev", interface, "parent", "1:2", "handle", "10:", "netem",
                                          "limit", str(policy["limit_packets"]), "delay", f'{policy["delay_ms"]}ms',
                                          "loss", f'{policy["loss_percent"]:.12g}%'] +
                                 (["rate", f'{policy["rate_bps"]}bit'] if policy.get("rate_bps") is not None else []))
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
                        actual["limit_packets"] != requested["limit_packets"] or
                        actual.get("rate_bps") != requested.get("rate_bps")):
                    raise SetupUnsupported(f"netem readback differs from request on {path}")
        self.provenance["condition_identity"]["actual"] = {
            "qdisc": self.profile["qdisc"], "paths": stable,
            "loss_seed": {"requested": None, "supported": False},
        }
        if "initial_cwnd" in self.profile:
            self.provenance["condition_identity"]["actual"]["initial_cwnd"] = self.profile["initial_cwnd"]
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

    def cleanup(self) -> list[str]:
        failures: list[str] = []
        if getattr(self, "kernel_control", None):
            try: self.kernel_control.sendall(b"S")
            except OSError: pass  # setup failure can already have closed this owned channel
            self.kernel_control.close(); self.kernel_control = None
        if getattr(self, "kernel_observer", None):
            try: self.kernel_observer.wait(5)
            except subprocess.TimeoutExpired:
                self.kernel_observer.kill(); self.kernel_observer.wait()
            complete = False
            path = self.output / "kernel-events.json"
            if path.is_file():
                complete = json.loads(path.read_text()).get("status") == "complete"
            self.provenance["cleanup"].append({"kernel_observer": "reaped",
                "returncode": self.kernel_observer.returncode, "collection_complete": complete})
            if self.kernel_observer.returncode != 0 or not complete:
                failures.append("kernel observer collection or cleanup incomplete")
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
                    "contract": "turtle-message-network-cleanup/1",
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


def observer(args: argparse.Namespace) -> int:
    collector_wall,collector_cpu=time.monotonic_ns(),time.process_time_ns()
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
        raw.setsockopt(socket.SOL_SOCKET, 35, 1)
        raw.setblocking(False)
        sockets[raw] = interface
    append_json(output, {"contract": "turtle-message-packets/1", "record_kind": "header",
                         "clock": "CLOCK_MONOTONIC", "observation_point": "router-veth-af_packet",
                         "raw_capture": "packets.pcap", "raw_capture_clock": "CLOCK_REALTIME",
                         "timestamp_location": "per-packet SO_TIMESTAMPNS or userspace fallback",
                         "packet_unit": "observed-skb-not-physical-wire", "interfaces": list(sockets.values())})
    pcap = output.with_suffix('.pcap').open('wb')
    # Nanosecond pcap, Ethernet frames. JSON rows retain interface and direction.
    pcap.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
    packet_index = 0
    active_run=None
    buffer = bytearray(); running = True
    while running:
        ready, _, _ = select.select([control, *sockets], [], [], .1)
        for source in ready:
            if source is control:
                try: line = recv_line(control, buffer)
                except BlockingIOError: continue
                if line is None: running = False; break
                marker = json.loads(line); marker.update(contract="turtle-message-packets/1", record_kind="marker")
                if marker.get("run_id"):active_run=marker["run_id"]
                append_json(output, marker)
                identity = marker.get("observation_id", marker["kind"])
                control.sendall(json.dumps({"ack": identity}, separators=(",", ":")).encode() + b"\n")
                if marker["kind"] == "capture-stop": running = False
            else:
                try: frame, ancillary, _, address = source.recvmsg(65535,128)
                except BlockingIOError: continue
                clock_begin = time.monotonic_ns()
                realtime = time.time_ns()
                clock_end = time.monotonic_ns()
                kernel_time=None
                for level,kind,value in ancillary:
                    if level==socket.SOL_SOCKET and kind==35:
                        seconds,nanoseconds=struct.unpack('ll',value[:struct.calcsize('ll')]); kernel_time=seconds*1000000000+nanoseconds
                capture_time=kernel_time if kernel_time is not None else realtime
                offset = pcap.tell()
                pcap.write(struct.pack('<IIII', capture_time // 1000000000,
                                       capture_time % 1000000000, len(frame), len(frame)))
                pcap.write(frame)
                row = decode_packet(frame, sockets[source], address[2] == getattr(socket, "PACKET_OUTGOING", 4))
                if row:
                    row.update(run_id=active_run,packet_index=packet_index, pcap_offset=offset,
                               realtime_ns=realtime, kernel_realtime_ns=kernel_time, timestamp_location="AF_PACKET-SO_TIMESTAMPNS-skb" if kernel_time is not None else "userspace-after-receive", clock_monotonic_begin_ns=clock_begin,
                               clock_monotonic_end_ns=clock_end)
                    append_json(output, row)
                packet_index += 1
    pcap.close()
    stats = {}
    for raw, interface in sockets.items():
        try:
            packets, drops = struct.unpack("II", raw.getsockopt(263, 6, 8)); stats[interface] = {"packets": packets, "drops": drops}
        except OSError as error: stats[interface] = {"packets": None, "drops": None, "reason": str(error)}
        raw.close()
    append_json(output, {"contract": "turtle-message-packets/1", "record_kind": "footer",
                         "monotonic_ns": time.monotonic_ns(), "capture_socket_statistics": stats, "collector_elapsed_ns":time.monotonic_ns()-collector_wall,"collector_process_cpu_ns":time.process_time_ns()-collector_cpu,"collector_peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"overhead_attribution":"collector process resource usage; not subtracted from endpoint measurements"})
    return 0


def decode_packet(frame: bytes, interface: str, outgoing: bool) -> dict[str, Any] | None:
    if len(frame) < 54 or struct.unpack_from("!H", frame, 12)[0] != 0x0800: return None
    ihl = (frame[14] & 0x0f) * 4
    if len(frame) < 14 + ihl + 20 or frame[23] != 6: return None
    tcp = 14 + ihl; source, destination = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    source_port, destination_port, sequence, acknowledgement = struct.unpack_from("!HHII", frame, tcp)
    data_offset = (frame[tcp + 12] >> 4) * 4
    total = struct.unpack_from("!H", frame, 16)[0]
    if ihl < 20 or data_offset < 20 or total < ihl + data_offset or len(frame) < 14 + total:
        return None
    direction = "egress" if outgoing else "ingress"
    mapping = {("rctls", "ingress"): "tls_c2s", ("rctls", "egress"): "tls_s2c",
               ("rstls", "ingress"): "tls_s2c", ("rstls", "egress"): "tls_c2s",
               ("rcca", "ingress"): "ca_c2s", ("rcca", "egress"): "ca_s2c",
               ("rca0", "ingress"): "ca_s2c", ("rca0", "egress"): "ca_c2s"}
    logical_path = mapping[(interface, direction)]
    data_port = 44330 if logical_path.startswith("tls_") else 44332
    # The client's ephemeral port may equal either listening port. Only the
    # server-side port identifies the service, in both packet directions.
    service_port = destination_port if logical_path.endswith("c2s") else source_port
    if service_port not in (data_port, data_port + 1):
        return None
    flow_class = "control" if service_port == data_port + 1 else "data"
    if flow_class == "control":
        logical_path = logical_path.replace("tls_", "control_tls_").replace("ca_", "control_ca_")
    return {"contract": "turtle-message-packets/1", "record_kind": "packet",
            "flow_class": flow_class,
            "monotonic_ns": time.monotonic_ns(), "interface": interface, "direction": direction,
            "logical_path": logical_path,
            "flow": {"source": source, "source_port": source_port,
                     "destination": destination, "destination_port": destination_port, "protocol": "tcp"},
            "tcp": {"sequence": sequence, "acknowledgement": acknowledgement,
                    "flags": frame[tcp + 13], "payload_length": total - ihl - data_offset,
                    "header_bytes": data_offset, "options_hex": frame[tcp+20:tcp+data_offset].hex()},
            "ip": {"header_bytes": ihl, "total_bytes": total,
                   "options_hex": frame[34:14+ihl].hex()},
            "payload_offset": tcp + data_offset,
            "frame_length": len(frame), "packet_unit": "observed-skb-not-physical-wire"}


def profile(document,lookup):
    if document.get('contract')!='turtle-message-network-plan/1':raise ValueError('unsupported network plan')
    paths=LOOKUP_PATHS if lookup else TLS_PATHS
    result=dict(contract=document['contract'],qdisc='netem',mtu=1500,offload=dict(tso=False,gso=False,gro=False),
                trace=True,loss_seed=None,initial_cwnd=dict(client=None,server=None),kernel_events=False,
                targeted_drop=dict(tls_c2s=None,tls_s2c=None),paths={})
    if set(document)-set(result):raise ValueError('unknown network field')
    result.update(document)
    if result['loss_seed'] is not None:raise SetupUnsupported('netem seed readback is unsupported')
    if result['qdisc'] not in ('none','netem') or not 576<=result['mtu']<=65535:raise ValueError('invalid network policy')
    supplied=result['paths'];result['paths']={}
    if set(supplied)-set(paths):raise ValueError('unknown directional path')
    for name in paths:
        policy=dict(delay_ms=0,loss_percent=0,limit_packets=1000,rate_bps=None);policy.update(supplied.get(name,{}))
        if not 0<=policy['delay_ms']<=1000 or not 0<=policy['loss_percent']<=100 or not 1<=policy['limit_packets']<=100000:raise ValueError('invalid netem policy')
        rate=policy['rate_bps']
        if rate is not None and (not isinstance(rate,int) or rate<8 or rate%8):raise ValueError('rate must be a positive multiple of 8')
        result['paths'][name]=policy
    if any(v is not None for v in result['targeted_drop'].values()) and not result['kernel_events']:raise ValueError('targeted drop requires kernel events')
    if result['kernel_events'] and (not result['trace'] or any(result['offload'].values())):raise ValueError('kernel events require packet collection and disabled segmentation offloads')
    return result


def execute(args):
    if os.stat('/proc/self/ns/net').st_ino==args.parent_inode:raise RuntimeError('coordinator must own a separate network namespace')
    root=Path(args.output).resolve();obj=Path(args.object).resolve() if args.object else None
    policy=profile(json.loads(Path(args.network).read_text()),obj is not None)
    topology=OwnedTopology(policy,root,lookup_enabled=obj is not None)
    run_id=str(uuid.uuid4());topology.provenance["run_id"]=run_id
    service=None;code=1
    try:
        topology.setup();topology._marker(dict(kind="run",run_id=run_id));topology.start_kernel_observer(Path(args.build))
        prefixes={r:['nsenter','-t',str(topology.helpers[r].pid),'-n','--'] for r in ('client','server')}
        role_options={}
        if obj:
            argv=['nsenter','-t',str(topology.helpers['ca'].pid),'-n','--',sys.executable,str(Path(__file__).with_name('mockca.py')),str(obj),str(root/'mockca'),'--address',ADDRESSES['ca']]
            service=subprocess.Popen(argv)
            deadline=time.monotonic()+5
            while not (root/'mockca/ready').exists():
                if service.poll() is not None or time.monotonic()>deadline:raise RuntimeError('MockCA startup failed')
                time.sleep(.01)
            role_options['client']=dict(lookup_address=ADDRESSES['ca'],lookup_port=44332,lookup_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),lookup_size=obj.stat().st_size)
        options=json.loads(Path(args.run_spec).read_text()) if args.run_spec else {}
        if set(options)&{'contract','run_id','output','pki','port','control_port','address','external_peer'}:raise ValueError('run options contain topology-owned fields')
        options.update(run_id=run_id,address=ADDRESSES['server'],port=44330,control_port=44331,stream=True,depth='white-box',kernel=policy['kernel_events'],network_condition=hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest())
        run(args.build,args.pki,root/'run',args.client,args.server,prefixes=prefixes,role_options=role_options,**options)
        topology.provenance['final_qdisc_readback']=topology._qdisc_readback()
        topology.provenance.update(status='complete');code=0
    except Exception as error:
        topology.provenance.update(status='unsupported' if isinstance(error,SetupUnsupported) else 'failed',reason=str(error))
        print(error,file=sys.stderr)
    finally:
        if service:
            service.terminate();service.wait(timeout=6)
        if topology.cleanup():code=1
    if not code:
        from packets import analyze
        from report import summarize
        dump_json(root/'packet-report.json',analyze(root))
        summarize(root/'run',root/'report')
    return code


def main():
    if len(sys.argv)>1 and sys.argv[1]=='_observer':
        p=argparse.ArgumentParser()
        for key in ('router-fd','control-fd'):p.add_argument('--'+key,type=int,required=True)
        p.add_argument('--interfaces',required=True);p.add_argument('--output',required=True)
        return observer(p.parse_args(sys.argv[2:]))
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',default='build-message');p.add_argument('--pki',default='pki/default');p.add_argument('--output',required=True);p.add_argument('--network',required=True)
    p.add_argument('--run-spec');p.add_argument('--object');p.add_argument('--client',default='openssl');p.add_argument('--server',default='openssl');p.add_argument('--parent-inode',type=int)
    a=p.parse_args()
    if a.parent_inode is not None:return execute(a)
    root=Path(a.output).resolve();root.mkdir(parents=True,exist_ok=False)
    before=host_network_identity()
    command=['unshare','--net']+(['--user','--map-root-user'] if os.geteuid()!=0 else [])+['--',sys.executable,str(Path(__file__).resolve()),*sys.argv[1:],'--parent-inode',str(os.stat('/proc/self/ns/net').st_ino)]
    with (root/'coordinator.log').open('w') as log:code=subprocess.call(command,stdout=log,stderr=subprocess.STDOUT)
    after=host_network_identity();unchanged=compare_host_identity(before,after)
    dump_json(root/'host-network.json',dict(contract='turtle-message-network-host/1',before=before,after=after,unchanged=unchanged,coordinator_returncode=code))
    return code if code else 0 if unchanged else 1


if __name__=='__main__':raise SystemExit(main())
