# Release notes

Release notes live at
<https://github.com/Lazarus-AI/clearwing/releases>. Notes are
auto-generated from merged-PR titles + labels via
[`.github/release.yml`](.github/release.yml) when each release is
cut.

The hand-curated pre-1.0 history has been archived to
[`docs/CHANGELOG-v1.0.md`](docs/CHANGELOG-v1.0.md). Per-PR
`CHANGELOG.md` bullets are no longer required — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the current PR checklist.

---

## Session: 2026-04-27 — Ollama Cloud + Dual Container Support

### Added
- **Ollama Cloud preset** (`clearwing/providers/catalog.py`)
  - New preset `ollama-cloud` for hosted models at `https://ollama.com`
  - Defaults: `deepseek-v4-flash`, requires `OLLAMA_API_KEY`
  - Alternative models: `qwen3-coder:480b`, `minimax-m2.7`, `kimi-k2.6`
- **Dual PentestContainer support** (`clearwing/agent/tools/ops/`)
  - New shared `PentestContainerManager` base class
  - Refactored Kali container (`kalilinux/kali-rolling`)
  - New ParrotOS container (`parrotsec/core:latest`, slim)
  - Both container types registered in tool graph, specialists, and state tracking
- **Parameterized integration tests** (`tests/test_pentest_container.py`)
  - Lifecycle tests for both Kali and ParrotOS (reused from alpine for speed)

### Changed
- `providers/manager.py`: Adapter resolution for ollama.com — now respects explicit `adapter: openai` or falls back to native `ollama`
- `providers/env.py`: Remove unused `pathlib.Path` import (F401 fix)
- `agent/state.py`: Added `parrot_container_id` alongside `kali_container_id`
- `agent/graph.py`: State updater and guardrails now track `parrot_setup` events
- `agent/prompts.py`: Context now surfaces both Kali and Parrot container IDs
- `agent/specialists/recon_agent.py` + `exploit_agent.py`: Import both Kali and Parrot tool sets
- `agent/tools/__init__.py`: `get_all_tools()` exports both Kali and Parrot operations

### Fixed
- Ollama Cloud 401 errors: `/v1` path was missing when using `adapter: openai`; config now uses `https://ollama.com/v1` + `adapter: openai` for OpenAI-compatible streaming
- `provider_name` resolution for `ollama-cloud` preset now routes correctly through `_adapter_for_provider_config`

### Known Issues
- ParrotOS `parrotsec/security:latest` (5.1 GB) is very large; using `parrotsec/core:latest` (~265 MB) may lack some pentest tools
- Windows-only tools (`mimikatz`, `PowerUp`, `WinPEAS`) still require Metasploit bridge or Windows host; no container solution yet on macOS/Linux
- `hashcat` GPU passthrough does not work on Docker Desktop for macOS
