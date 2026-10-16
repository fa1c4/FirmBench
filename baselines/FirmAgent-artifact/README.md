# FirmAgent source artifact

This repository contains the source needed to run the FirmAgent workflow on a firmware web service you are authorized to test. It is a clean source distribution: firmware images, extracted root filesystems, benchmark targets, generated traces and reports, prebuilt toolchains, credentials, and the old Git history are excluded.

## Prerequisites

- Linux host with Python 3.10, Bash, Docker, and a reachable re-hosted firmware service.
- IDA Pro with the relevant Hex-Rays decompiler and `idat`/`idat64` for pre-fuzzing and the final agent.
- A Greenhouse/FirmAE re-hosting environment and instrumented user-mode QEMU that emits taint and execution traces. See [Install/README.md](Install/README.md) for the setup scripts. These tools are downloaded or built separately and are not part of this repository.
- An OpenAI-compatible LLM endpoint for API extraction and the taint-to-PoC agent.
- Your own firmware image and target binary. Keep target files and generated output outside this source tree when practical.

Install the Python environment with `Install/install_python_env.sh` (Python 3.10 recommended), or install the pinned packages from `requirements.txt` into a compatible environment. The Python installer creates `Environ/Python`, which Git ignores.

```bash
Install/install_python_env.sh
source Environ/Python/env.sh
export IDAT_BIN=/path/to/idat64
export Private_API_KEY=your-key
export LLM_BASE_URL=https://your-endpoint/v1
export LLM_MODEL=your-model
```

## End-to-end workflow

The paths below are placeholders. The target binary directory is a working directory where FirmAgent writes per-target evidence.

### 1. Pre-fuzzing and API extraction

```bash
Pre_Fuzzing/run.sh /path/to/target/httpd
python3 Pre_Fuzzing/llm_extract_api_params.py \
  --input /path/to/target/export-for-ai-httpd \
  --output /path/to/target/Pre_fuzzing.json
```

The first command runs IDA decompilation, sink-scope extraction, and CFG distance calculation. It writes `sink_scope_addr.txt`, `sink_cfg.json`, and `sink_distance_scores.json` next to the binary. API extraction is a separate LLM call that creates the `Pre_fuzzing.json` input for the fuzzer. You can also supply this JSON manually; at minimum it needs `api_endpoints` and `para` string arrays.

### 2. Start a traced re-hosted service

Prepare a running Greenhouse container with the target service, a shared `/scratch` mount, and an instrumented QEMU executable inside the container. The session launcher assumes `/sbin/httpd` and `/qemu-mips-static` by default; use `--httpd` and `--qemu` for other layouts.

```bash
FuzzingRecord/rehost_session.sh start \
  --container YOUR_CONTAINER \
  --dfilter "$(python3 FuzzingRecord/make_dfilter.py /path/to/target/sink_scope_addr.txt)"
```

The launcher sets `QEMU_DFILTER`, `QEMU_LOG=cpu,exec,nochain`, and `QEMU_LOG_FILENAME=/scratch/qemu_trace.log`. The host path corresponding to that mount is needed in the next steps. Keep the trace log until `Source.json` is built.

### 3. Guided API fuzzing

```bash
python3 FuzzingRecord/Fuzzer.py \
  --json-file /path/to/target/Pre_fuzzing.json \
  --distance-file /path/to/target/sink_distance_scores.json \
  --qemu-log /host/shared/qemu_trace.log \
  --idle-pause-container YOUR_CONTAINER \
  --trace-windows-out /path/to/target/trace_windows.jsonl \
  --host CONTAINER_IP \
  --feedback-settle 0.3 \
  --iterations 1000 \
  --random-seed 1 \
  --tag-mode unique
```

Set request method, content type, authentication, and other fuzzer options for the service under test (`python3 FuzzingRecord/Fuzzer.py --help`). The fuzzer writes `result_stream.ndjson` and `fuzzing_summary.json` beside `Pre_fuzzing.json`.

### 4. Construct dynamic sources and run the agent

```bash
python3 FuzzingRecord/build_source_json.py \
  --qemu-log /host/shared/qemu_trace.log \
  --windows /path/to/target/trace_windows.jsonl \
  --result-stream /path/to/target/result_stream.ndjson \
  --output /path/to/target/Source.json

FuzzingRecord/rehost_session.sh stop --container YOUR_CONTAINER

python3 Src/LLMATaint.py \
  -b /path/to/target/httpd \
  -p True \
  -t ci \
  -o /path/to/agent-output
```

`LLMATaint.py` reads `Source.json` from the binary directory by default. It also accepts `--dynamic-source-file` and optional `Indirect_call.json`/`indirect_data.json` evidence when available. Run `python3 Src/LLMATaint.py --help` for agent options and supported vulnerability types.

The full workflow requires a licensed IDA installation, a working re-hosted target, an instrumented QEMU build, and LLM credentials. The repository has no bundled benchmark firmware or recorded run from which to replay a result.

## Source layout

| Path | Purpose |
| --- | --- |
| `Pre_Fuzzing/` | IDA export, sink extraction, CFG distance, API extraction |
| `FuzzingRecord/` | Traced session control, guided fuzzing, trace to `Source.json` |
| `Src/` and `Filter/` | Taint analysis, LLM agent, IDA sink filtering |
| `Install/` | Scripts to obtain and build external toolchains |

## License

See [LICENSE.txt](LICENSE.txt). Use only on firmware and services you own or are authorized to test.
