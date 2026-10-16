# External toolchain setup

The source artifact does not include the toolchains or firmware used in the reproduction. The scripts here fetch or build them under `Environ/` by default (`ENVIRON=/another/path` overrides that directory). They use network access, Docker, and substantial disk space. Review their external project and host requirements before running them.

On the validated setup, the host used Ubuntu 22.04, Python 3.10, Docker, and a separately licensed IDA Pro installation with the appropriate Hex-Rays decompilers. IDA is not installed by these scripts. Set `IDAT_BIN` to your `idat`/`idat64` executable.

```bash
Install/install_all.sh
source Environ/Python/env.sh
export IDAT_BIN=/path/to/idat64
```

`install_all.sh` runs the component installers in dependency order:

| Script | Output |
| --- | --- |
| `install_binwalk.sh` | Firmware extraction tools |
| `install_greenhouse.sh` | Greenhouse source and its submodules |
| `install_qemu.sh` | Instrumented QEMU and Greenhouse QEMU assets |
| `install_firmae.sh` | FirmAE extracted from a local Greenhouse image |
| `install_python_env.sh` | Python virtual environment with agent dependencies |

`install_greenhouse_img.sh` builds the `greenhouse-lite:local` Docker image used by `install_firmae.sh`. You can run each installer separately. The `install_qemu.sh` script expects the Greenhouse clone at `Environ/Greenhouse`, or at `GREENHOUSE_SRC` if set.

To re-host a firmware service, supply your own target and create a running Greenhouse container with its target service and `/scratch` mounted to a host directory. `FuzzingRecord/rehost_session.sh` then starts a traced service inside that container. Its defaults fit the MIPS `/sbin/httpd` layout; use its flags for another architecture or service path. No benchmark firmware, prebuilt container, or target specific re-hosting configuration is included here.

Use environment variables for LLM credentials, never a tracked config file:

```bash
export Private_API_KEY=your-key
export LLM_BASE_URL=https://your-endpoint/v1
export LLM_MODEL=your-model
```
