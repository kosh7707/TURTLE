#!/usr/bin/env python3
"""Randomize normal TLS configurations within batches; preserve every attempt."""

import argparse
import itertools
import json
from pathlib import Path
import random
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=Path("build"))
    parser.add_argument("--pki", type=Path, default=Path("pki/default"))
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--libraries", default="openssl,wolfssl,mbedtls")
    parser.add_argument("--modes", default="timing,memory")
    parser.add_argument("--auth", choices=("server", "mutual", "both"), default="both")
    parser.add_argument("--cross", action="store_true", help="all client/server pairs, not just same-library pairs")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--batches", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--no-affinity", action="store_true", help="explicitly relax the three-physical-core requirement")
    args = parser.parse_args()
    if args.samples <= 0 or args.batches <= 0:
        parser.error("samples and batches must be positive")
    build, pki, output = args.build.resolve(), args.pki.resolve(), args.output.resolve()
    libraries = args.libraries.split(",")
    modes = args.modes.split(",")
    if any(mode not in ("timing", "memory", "trace") for mode in modes):
        parser.error("modes must be timing, memory, or trace")
    for library in libraries:
        if not (build / "adapters" / f"{library}.so").is_file():
            parser.error(f"missing built adapter: {library}")
    output.mkdir(parents=True, exist_ok=False)
    provenance = output / "provenance"
    provenance.mkdir()
    for filename in ("build-manifest.txt", "compile_commands.json", "CMakeCache.txt"):
        if (build / filename).is_file():
            shutil.copyfile(build / filename, provenance / filename)
    cache = build / "CMakeCache.txt"
    dependencies = Path(__file__).resolve().parent.parent / ".deps"
    if cache.is_file():
        for line in cache.read_text().splitlines():
            if line.startswith("TURTLE_DEPS_ROOT:PATH=") and line.split("=", 1)[1]:
                dependencies = Path(line.split("=", 1)[1])
    if (dependencies / "manifests").is_dir():
        shutil.copytree(dependencies / "manifests", provenance / "dependencies")
    pairs = list(itertools.product(libraries, repeat=2)) if args.cross else [(name, name) for name in libraries]
    auth = ("server", "mutual") if args.auth == "both" else (args.auth,)
    configurations = list(itertools.product(pairs, modes, auth))
    rng = random.Random(args.seed)
    manifest = {"schema": 1, "seed": args.seed, "batches": args.batches,
                "note": "randomized batches; no invalid-sample replacement; not a publication-quality result", "runs": []}

    def save():
        (output / "study.json").write_text(json.dumps(manifest, indent=2) + "\n")

    for batch in range(1, args.batches + 1):
        order = list(configurations)
        rng.shuffle(order)
        for position, ((client, server), mode, auth_type) in enumerate(order, start=1):
            path = output / f"batch-{batch:03d}" / f"{position:03d}-{client}-{server}-{auth_type}-{mode}"
            command = [str(build / "turtle"), "run", "--client", client, "--server", server,
                       "--pki", str(pki), "--output", str(path), "--samples", str(args.samples),
                       "--warmups", str(args.warmups), "--mode", mode, "--batch", str(batch),
                       "--seed", str(args.seed), f"--{auth_type}-auth"]
            if args.profile:
                command += ["--profile", str(args.profile.resolve())]
            if args.no_affinity:
                command.append("--no-affinity")
            entry = {"batch": batch, "order": position, "command": command,
                     "started_unix": time.time(), "status": "running"}
            manifest["runs"].append(entry)
            save()
            result = subprocess.run(command, capture_output=True, text=True)
            entry.update(status="complete" if result.returncode == 0 else "invalid",
                         returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            save()
            if result.returncode:
                raise SystemExit(f"Stopped without replacing invalid samples: {path}")
            for raw in sorted(path.glob("sample-*/*.jsonl")):
                if raw.name not in ("client.jsonl", "server.jsonl"):
                    continue
                subprocess.run([build / "turtle-interpret", raw, raw.with_suffix(".decoded.json")], check=True)
    subprocess.run([build / "turtle-report", output, output / "report"], check=True)
    print(f"Study artifacts: {output}")


if __name__ == "__main__":
    main()
