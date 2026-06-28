#!/usr/bin/env bash
set -euo pipefail

python -m unittest discover -s tests
rm -rf .guarded_ops build dist src/guardedops.egg-info
scripts/leak_scan.sh --public .
python -m pip wheel . --no-deps -w dist >/tmp/guardedops-wheel.log
python -m pip download . --no-binary :all: --no-deps -d dist >/tmp/guardedops-sdist.log
artifact_dir="$(mktemp -d)"
python - <<'PY' "${artifact_dir}"
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

target = Path(sys.argv[1])
for artifact in Path("dist").iterdir():
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            archive.extractall(target / artifact.name)
    elif artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact) as archive:
            archive.extractall(target / artifact.name.replace(".tar.gz", ""))
PY
scripts/leak_scan.sh --public dist
scripts/leak_scan.sh --public "${artifact_dir}"
help_dir="$(mktemp -d)"
for cmd in "opsctl --help" "routectl --help" "ops-review --help" "ops-guard-hook --help"; do
  safe_name="${cmd%% *}"
  $cmd >"${help_dir}/${safe_name}.txt"
done
scripts/leak_scan.sh --public "${help_dir}"
echo "release gate passed"
