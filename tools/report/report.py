#!/usr/bin/env python3
"""C++ 분석 결과만 읽는 선택적 비교 보고서. 실행·계측·원자료 해석은 하지 않는다."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import random
import statistics
from presentation import write_report, write_lifecycle_report


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def quantile(numbers, fraction):
    values = sorted(numbers)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    index = int(position)
    return values[index] if position == index else values[index] + (values[index + 1] - values[index]) * (position - index)


def bootstrap_difference(sample, baseline, rng, count):
    if not sample or not baseline:
        return None
    draws = [statistics.median(rng.choices(sample, k=len(sample))) -
             statistics.median(rng.choices(baseline, k=len(baseline))) for _ in range(count)]
    return [quantile(draws, .025), quantile(draws, .975)]


def summarize(data, base, config, baseline, rng, count):
    median = statistics.median(data) if data else None
    q1, q3 = quantile(data, .25), quantile(data, .75)
    ci = ([0, 0] if data else None) if config == baseline else bootstrap_difference(data, base, rng, count)
    return {"valid_samples": len(data), "availability": "available" if data else "no_valid_samples",
            "median": median, "q1": q1, "q3": q3, "iqr": q3 - q1 if data else None,
            "baseline": baseline, "median_difference": median - statistics.median(base) if data and base else None,
            "bootstrap_95_low": ci[0] if ci else None, "bootstrap_95_high": ci[1] if ci else None}


def write_csv(path, rows):
    with Path(path).open("w", newline="") as file:
        fields = list(dict.fromkeys(k for row in rows for k in row)) or ["configuration", "role", "metric"]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
                          for k, v in row.items()} for row in rows)


def regenerate(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    manifest = load(source / "manifest.json")
    if manifest["schema"] not in ("turtle.manifest.v2", "turtle.manifest.v3"):
        raise ValueError("unsupported manifest")
    spec = manifest["spec"]
    baseline = spec["baseline"]
    count, seed = spec.get("bootstrap_samples", 2000), spec.get("bootstrap_seed", 0)
    if type(count) is not int or count < 1:
        raise ValueError("bootstrap_samples must be positive")
    samples, states, units = defaultdict(list), defaultdict(Counter), {}
    attempts, diagnostics, profiles, sources = [], [], [], {}
    for attempt in manifest["attempts"]:
        path = source / attempt["directory"] / "analysis.json"
        item = load(path)
        if item["schema"] != "turtle.attempt-report.v4":
            raise ValueError("C++ v4 analysis required: " + str(path))
        sources[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
        purpose = attempt.get("purpose", "measurement")
        if item.get("purpose", purpose) != purpose:
            raise ValueError("attempt purpose mismatch: " + str(path))
        summary = {**attempt, **{k: item[k] for k in (
            "success", "ordinary_timing_sample", "invalid_reasons", "phase_complete", "phase_invalid_reasons",
            "network_complete", "network_invalid_reasons", "perf_complete", "perf_invalid_reasons")}}
        for key in ("configuration_matches", "required_metrics_valid", "eligible"):
            if key in item:
                summary[key] = item[key]
        for role, data in item["roles"].items():
            profile = data.get("cpu_profile", {})
            if profile.get("requested"):
                profiles.append({"configuration": attempt["configuration"], "directory": attempt["directory"],
                                 "role": role, **{k: profile.get(k) for k in ("availability", "reason", "sample_count", "scenario")},
                                 "phases": profile.get("phases", []), "calls": profile.get("calls", [])})
        if purpose != "measurement":
            diagnostics.append(summary)
            continue
        attempts.append(summary)
        for row in item["measurements"]:
            key = attempt["configuration"], row["group"], row["role"], row["scope"], row["metric"]
            if key in units and units[key] != row["unit"]:
                raise ValueError("inconsistent measurement unit")
            units[key] = row["unit"]
            samples.setdefault(key, [])
            states[key]["available" if row["valid_sample"] else row["excluded_reason"]] += 1
            if row["valid_sample"]:
                samples[key].append(row["value"])
    rng = random.Random(seed)
    groups = {key: [] for key in ("metrics", "phase_metrics", "counter_metrics")}
    for key in sorted(samples):
        config, group, role, scope, metric = key
        selected = [a for a in attempts if a["configuration"] == config]
        data = samples[key]
        row = {"configuration": config, "role": role, "metric": metric, "unit": units[key],
               "attempts": len(selected), "successes": sum(a["success"] for a in selected),
               **summarize(data, samples.get((baseline, group, role, scope, metric), []), config, baseline, rng, count),
               "sample_sum": sum(data) if data else None, "availability_counts": dict(states[key])}
        if group == "phase_metrics":
            row.update(phase=scope, phase_successes=sum(a["success"] and a["phase_complete"] for a in selected))
        elif group == "counter_metrics":
            row["scope"] = scope
        groups[group].append(row)
    result = {"schema": "turtle.comparison.v4", "baseline": baseline, "attempts": attempts, "diagnostics": diagnostics, **groups,
              "cpu_profiles": profiles, "analysis_sha256": sources,
              "statistics": {"population": "cpp_valid_sample_process_observations", "quantile": "linear_n_minus_one",
                             "bootstrap": "independent_process_samples_percentile", "bootstrap_samples": count, "bootstrap_seed": seed}}
    destination.mkdir(parents=True, exist_ok=True)
    save(destination / "report.json", result)
    for name, group in (("report", "metrics"), ("phase_report", "phase_metrics"), ("counter_report", "counter_metrics")):
        write_csv(destination / (name + ".csv"), result[group])
    save(destination / "cpu_report.json", {"schema": "turtle.cpu-report.v1", "profiles": profiles})
    cpu_rows = []
    for profile in profiles:
        for kind, scope, section in ([('phase', s['phase'], s) for s in profile['phases']] +
                                     [('call', s['operation'], s) for s in profile['calls']] +
                                     ([('scenario', 'scenario', profile['scenario'])] if profile['scenario'] else [])):
            for function in section['functions'] or [{}]:
                cpu_rows.append({"configuration": profile['configuration'], "directory": profile['directory'],
                                 "role": profile['role'], "scope_kind": kind, "scope": scope,
                                 "availability": section['availability'], "reason": section['reason'], **function})
    write_csv(destination / "cpu_report.csv", cpu_rows)
    if manifest["schema"] == "turtle.manifest.v3":
        write_lifecycle_report(destination, manifest, result)
    else:
        write_report(destination, manifest, result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    regenerate(args.run, args.output)
