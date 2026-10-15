#!/usr/bin/env python3
"""구현자 계약과 내부 부품의 포함 경계 및 순환 의존을 검사합니다."""
import argparse
from pathlib import Path
import re
import sys
import tempfile

INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]', re.MULTILINE)
EXTENSIONS = {".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".cxx"}


def check(root):
    root = root.resolve()
    source = root / "src"
    public = root / "include"
    adapters = root / "implementations"
    graph = {}
    file_graph = {}
    errors = []
    for directory in (source, public, adapters):
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix not in EXTENSIONS:
                continue
            relative = path.relative_to(root)
            file_graph.setdefault(relative.as_posix(), set())
            origin = None
            if path.is_relative_to(source):
                parts = path.relative_to(source).parts
                if len(parts) > 1:
                    origin = parts[0]
                    graph.setdefault(origin, set())
            # Remove comments without hiding includes in ordinary string tokens.
            text = re.sub(r"/\*.*?\*/", "", path.read_text(), flags=re.DOTALL)
            text = re.sub(r"//[^\n]*", "", text)
            for include in INCLUDE.findall(text):
                candidates = (path.parent / include, public / include,
                              source / include, root / include)
                resolved = next((p.resolve() for p in candidates if p.is_file()), None)
                # A nonexistent src include is still a boundary violation.
                internal = (resolved is not None and resolved.is_relative_to(source))
                explicit_src = "src" in Path(include).parts
                external_contract = path.is_relative_to(public) or path.is_relative_to(adapters)
                if external_contract and (internal or explicit_src):
                    errors.append(f"{relative}: 내부 헤더를 포함할 수 없습니다: {include}")
                if origin and internal:
                    parts = resolved.relative_to(source).parts
                    if len(parts) > 1 and parts[0] != origin:
                        graph[origin].add(parts[0])
                if resolved is not None and resolved.is_relative_to(root):
                    file_graph[relative.as_posix()].add(
                        resolved.relative_to(root).as_posix())
    visited = set()
    active = []

    def visit(module):
        if module in active:
            errors.append("부품 순환 의존: " + " -> ".join(active[active.index(module):] + [module]))
            return
        if module in visited:
            return
        active.append(module)
        for dependency in sorted(graph.get(module, ())):
            visit(dependency)
        active.pop()
        visited.add(module)

    for module in sorted(graph):
        visit(module)

    service_headers = {
        "src/model/service.hpp",
        "src/model/run_config.hpp",
        "src/model/sample.hpp",
    }
    core_headers = {
        "src/model/model.hpp",
        "src/measure/measure.hpp",
        "src/transport/channel.hpp",
        "src/transport/tcp.hpp",
        "src/record/record.hpp",
    }
    for origin in sorted(core_headers & file_graph.keys()):
        pending = list(file_graph[origin])
        reached = set()
        while pending:
            dependency = pending.pop()
            if dependency in reached:
                continue
            reached.add(dependency)
            pending.extend(file_graph.get(dependency, ()))
        for forbidden in sorted(reached & service_headers):
            errors.append(
                f"{origin}: 서비스 조합 헤더를 간접 포함할 수 없습니다: {forbidden}")
    return errors, graph


def self_test():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)

        def write(path, text):
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)

        write("include/turtle/adapter.hpp", "#pragma once\n")
        write("src/model/model.hpp", '#include "turtle/adapter.hpp"\n')
        write("src/model/service.hpp", '#include "model/model.hpp"\n')
        write("src/model/run_config.hpp", '#include "model/service.hpp"\n')
        write("src/model/sample.hpp", '#include "model/run_config.hpp"\n')
        write("src/measure/measure.hpp", '#include "model/model.hpp"\n')
        write("src/transport/channel.hpp", '#include "model/model.hpp"\n')
        write("src/transport/tcp.hpp", '#include "model/model.hpp"\n')
        write("src/record/record.hpp", '#include "model/model.hpp"\n')
        write("implementations/example/a.cpp", '#include "turtle/adapter.hpp"\n')
        assert not check(root)[0]
        write("implementations/example/a.cpp", '#include "model/model.hpp"\n')
        assert any("내부 헤더" in error for error in check(root)[0])
        write("implementations/example/a.cpp", '#include "../../src/missing.hpp"\n')
        assert any("내부 헤더" in error for error in check(root)[0])
        write("implementations/example/a.cpp", '#include "turtle/adapter.hpp"\n')
        write("include/turtle/adapter.hpp", '#include "../../src/model/model.hpp"\n')
        assert any("내부 헤더" in error for error in check(root)[0])
        write("include/turtle/adapter.hpp", "#pragma once\n")
        write("src/model/model.hpp", '#include "measure/measure.hpp"\n')
        assert any("순환 의존" in error for error in check(root)[0])
        write("src/model/model.hpp", '// #include "measure/measure.hpp"\n')
        assert not check(root)[0]
        write("src/measure/measure.hpp", '#include "model/run_config.hpp"\n')
        assert any("서비스 조합 헤더" in error for error in check(root)[0])
        write("src/measure/measure.hpp", '#include "model/model.hpp"\n')
        assert not check(root)[0]
    print("PASS: 경계 검사 자체 시험")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not (args.root / "src").is_dir() or not (args.root / "include").is_dir():
        parser.error("프로젝트 src/ 및 include/ 폴더가 필요합니다")
    errors, graph = check(args.root)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: {len(graph)}개 부품의 포함 경계와 순환 의존 검사")
    print("범위: 정적인 #include만 검사하며 매크로로 생성한 포함 경로와 링크 의존은 검사하지 않습니다")
    return 0


if __name__ == "__main__":
    sys.exit(main())
