#!/usr/bin/env bash
# Runs the full evaluation and regenerates the paper's tables and figure data.
# usage: experiments/run.sh [scale] [bench-repeats] [race-trials]
#   scale < 1 shortens the benchmarks; bench-repeats (default 3) is the number
#   of independent benchmark runs used to report latency ranges.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCALE="${1:-1}"
REPEATS="${2:-3}"
TRIALS="${3:-10}"
if [[ -n "${ZTAC_ATTACKS:-}" ]]; then
  echo "Full evaluation refuses ZTAC_ATTACKS filtering; use individual suites." >&2
  exit 2
fi
[[ "$REPEATS" =~ ^[1-9][0-9]*$ && "$TRIALS" =~ ^[1-9][0-9]*$ ]] || exit 2
OUT="$ROOT/experiments/results/$(date +%Y%m%d-%H%M%S)"
cd "$ROOT"
cargo build --release --quiet
cargo test --release --quiet > /dev/null
python3 -m unittest discover -s experiments -p test_analyze.py
mkdir -p "$OUT"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(sysctl -n hw.model) $(sysctl -n machdep.cpu.brand_string) $(($(sysctl -n hw.memsize) / 1073741824)) GiB"
  echo "os: $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  echo "git: $("$(xcrun --find git)" --version)"
  echo "python: $("$(xcrun --find python3)" --version 2>&1)"
  echo "rustc: $(rustc --version)"
  echo "load: $(sysctl -n vm.loadavg)"
} > "$OUT/environment.txt"
./target/release/ztac-eval all --out "$OUT" --scale "$SCALE"
EXTRA=()
for i in $(seq 2 "$REPEATS"); do
  ./target/release/ztac-eval bench --out "$OUT/bench$i" --scale "$SCALE"
  EXTRA+=("$OUT/bench$i")
done
./target/release/ztac-eval agreement --out "$OUT"
./target/release/ztac-eval race --out "$OUT" --trials "$TRIALS"
python3 "$ROOT/experiments/analyze.py" "$OUT" "$ROOT/paper/generated" ${EXTRA[@]+"${EXTRA[@]}"}
ln -sfn "$(basename "$OUT")" "$ROOT/experiments/results/latest"
echo "results in $OUT"
