# ZTAC: Object-Bound Confinement for AI Coding Agents

This repository contains the software and the evaluation data for the paper
*Names Are Not Objects: Object-Bound Confinement for Compromised AI Coding
Agents*.

ZTAC (Zero-Trust Agent Cells) confines an AI coding agent on macOS. The agent
runs in a *cell*. A cell is a Seatbelt sandbox. The sandbox lets the agent load
its own code and connect to one Unix socket. It does not let the agent read
workspace files, open network connections, or start programs.

The agent sends each file, program, and network request to a *broker*. The
broker does these steps for each request:

1. It verifies the signature of the request.
2. It resolves the request to the object that the request will use.
3. It applies the policy to that object.
4. It holds the request for a human reviewer if the policy requires approval.
5. It does the operation on the resolved object.
6. It writes a signed record to an audit log.

Programs that the broker starts (`git`, `python3`) run in a Seatbelt profile.
The broker makes this profile from the same policy.

## Contents

| Path | Contents |
|---|---|
| `crates/core` | Wire protocol, canonical JSON, Ed25519 signatures, Seatbelt profiles, broker client |
| `crates/broker` | Broker (`ztac-broker`) and operator tool (`ztacctl`) |
| `crates/cell` | Cell launcher (`ztac-cell`), one-request client (`ztac-client`), boundary probe (`ztac-probe`) |
| `crates/eval` | Evaluation program (`ztac-eval`): attacks, benign workload, benchmarks |
| `experiments/run.sh` | Script that runs the full evaluation |
| `experiments/analyze.py` | Script that makes the tables and numbers from the results |
| `data/20261009-113027` | Results of the evaluation run in the paper |

## Requirements

- macOS with the Xcode command-line tools. ZTAC uses `sandbox-exec`, `git`, and `python3`.
- Rust 1.80 or later.
- Python 3.

## Build

1. Build the programs:

   ```bash
   cargo build --release
   ```

2. Run the unit tests:

   ```bash
   cargo test --release
   ```

## Make the paper numbers from the released data

1. Run the analysis script on the released results:

   ```bash
   python3 experiments/analyze.py data/20261009-113027 generated \
       data/20261009-113027/bench2 data/20261009-113027/bench3
   ```

2. Read the output in `generated/`. The file `generated/numbers.tex` contains
   each number in the paper. The other files contain the tables and the figure
   data.

## Run the evaluation again

On the test computer, the full evaluation takes approximately 11 minutes.

1. Make sure that no other program uses local ports 18301 to 18305.
2. Run the script:

   ```bash
   bash experiments/run.sh
   ```

3. Find the results in `experiments/results/<timestamp>/`. The script also
   writes the tables and numbers to `paper/generated/`.

The evaluation uses `/private/tmp/ztac-eval` as its work directory. The attacks
use only local test files and local test services.

To run one part of the evaluation, use these commands:

```bash
./target/release/ztac-eval security --out /tmp/r    # attacks, all configurations
./target/release/ztac-eval utility  --out /tmp/r    # benign workload
./target/release/ztac-eval bench    --out /tmp/r    # latency and throughput
./target/release/ztac-eval security --only ZTAC --out /tmp/r   # one configuration
```

## Use the broker

1. Make a key for a cell. The command shows the cell identifier and the public key.

   ```bash
   ./target/release/ztacctl keygen cell.key
   ```

2. Write a broker configuration file, `broker.json`. Set `socket_path`,
   `state_dir`, and `workspace_root`. Add the public key of the cell to `cells`.
   The type `BrokerConfig` in `crates/broker/src/config.rs` shows all fields.

3. Start the broker:

   ```bash
   ./target/release/ztac-broker --config broker.json &
   ```

4. Send a request from a cell:

   ```bash
   ./target/release/ztac-cell --socket <socket> --key cell.key -- \
       ./target/release/ztac-client --tool fs_write --params '{"path":"a.txt","data":"hi"}'
   ```

5. Show the requests that wait for approval:

   ```bash
   ./target/release/ztacctl --config broker.json approvals list --status pending
   ```

6. Show all fields of one request before you approve it:

   ```bash
   ./target/release/ztacctl --config broker.json approvals show <id>
   ```

7. Approve the request:

   ```bash
   ./target/release/ztacctl --config broker.json approvals approve <id> --by <name>
   ```

8. Verify the audit log:

   ```bash
   ./target/release/ztacctl --config broker.json audit verify
   ```

## Limits

- ZTAC runs only on macOS. It uses `sandbox-exec`, which Apple marks as deprecated.
- Spawned programs cannot start other programs. Build tools that start
  compilers do not work in the sandbox.
- The broker does not start a program if a file in the workspace has more than
  one hard link.
- An agent that can read a secret and send data to an allowed endpoint can
  send that secret in an encoded form.

## Citation

Use the information in `CITATION.cff` to cite this software.

## License

MIT. See `LICENSE`.
