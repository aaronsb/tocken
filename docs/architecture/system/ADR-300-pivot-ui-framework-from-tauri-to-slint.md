---
status: Draft
date: 2026-04-30
deciders:
  - aaronsb
  - claude
related:
  - ADR-100
  - ADR-101
---

# ADR-300: Pivot UI framework from Tauri to Slint

## Context

Tocken started on Tauri 2 (WebKitGTK on Linux) and has accumulated five enrollment sources (paste-URI, manual, file picker, clipboard image, camera) plus the wizard, code panel, and tray scaffold. The crypto / store / session / enrollment / age-plugin-yubikey integration are all pure Rust under `app/src-tauri/src/{enroll,store,session,wizard}/` and are not coupled to the UI framework.

By the time the camera path landed (PR #34), a structural pattern was unmistakable across every native integration:

| Surface | Friction encountered |
|---|---|
| File picker | Required `tauri-plugin-dialog`, capability config, npm-package vs direct invoke trade-off (no bundler) |
| Clipboard image | `navigator.clipboard.read()` denied by WebKitGTK; required falling back to `tauri-plugin-clipboard-manager` and async-fn deadlock fix |
| Camera permission | `getUserMedia` denied by default; required custom `with_webview` permission handler hooked into webkit2gtk |
| Camera frames | Binary IPC via JSON-encoded byte arrays slow to the point of "extremely slow" UX; mitigated by vendoring jsQR (~250 KB) to keep decode in the webview |
| Camera rendering | `<video>` element shows black on Wayland with transparent window; canvas-as-preview workaround also black; `WEBKIT_DISABLE_DMABUF_RENDERER=1` did not resolve; the `getImageData` buffer is empty even when the v4l2 LED is lit |
| Tray | Linux tray menu hack (single-item Activate menu) for libayatana-appindicator quirks (#21) |
| Window UX | Chromeless transparent window not draggable without custom regions (#33) |

The camera path made the structural cost visible: five layers of indirection (gstreamer → WebKit MediaStream → JS `<video>` → canvas `drawImage` → jsQR → IPC → `enroll::file::decode_payloads`) for what is, in pure Rust with `nokhwa` + `rqrr`, a one-screen function. Even when those layers cooperated, it was fragile (a single QR decoded once before regressing to black preview).

The critical observation: **none of this friction was about Tauri being incompetent**. It was about web-shell architecture being structurally wrong for an app whose value is local cryptographic operations on hardware-key-backed storage. We have no web. We have a tray-resident desktop tool that talks to a YubiKey, a v4l2 camera, an XDG file picker, and an age-encrypted local file. Every one of those is more direct in a native UI toolkit.

## Decision

Pivot the UI layer from Tauri to **Slint**. The crypto / store / session / enrollment / wizard backend modules port unchanged; the rewrite scope is the UI shell (`app/src/`) and the Tauri command surface (`app/src-tauri/src/lib.rs`), which becomes a normal Rust binary with a Slint front-end calling the same `enroll::`, `store::`, `session::`, `wizard::` functions directly.

Slint is preferred over CXX-Qt for this codebase because:

- **Smaller dep tree.** Slint links a single Rust crate; no system Qt installation, no LGPL licensing dance, no `qmake`/`moc`/CMake adjacency.
- **Pure-Rust integration.** Slint's `.slint` markup compiles into Rust types at build time; no FFI, no bridge code, no separate build step beyond `build.rs`.
- **Aesthetic ceiling sufficient for tocken.** A 360×480 tray-resident window with a wizard, a code list, an enrollment pane, and a tray icon is well within Slint's wheelhouse. We don't need Qt's full widget catalog.
- **Authors' lineage.** Slint's core team is ex-Qt (Olivier Goffart and team); the design language and discipline carry over.
- **In-process media.** Camera capture via `nokhwa`, QR decode via `rqrr`, clipboard via `arboard` — all already in our dep tree or trivial additions, all running in-process with no IPC, no permission gates, no DMA-BUF/Wayland video compositing path.
- **Embedded-target option preserved.** Slint is explicitly designed for MCU targets (`slint-cpp` on ARM Cortex-M, i.MX RT, ESP32-S3). Speculative but real future direction: a dedicated tocken viewer device — embedded board with a YubiKey-style hardware module and a small display — would be straightforward in Slint and out of reach in CXX-Qt without commercial Qt-for-MCUs licensing.

## Consequences

### Positive

- **Direct hardware access.** Camera, clipboard, file picker, and tray are native APIs, not webview workarounds. The categorical "every native surface is a fight" reverses.
- **Single-language stack.** The whole app becomes Rust + `.slint` markup. No JavaScript, no npm dependency tree, no JS engine, no DOM, no CSS. The cognitive overhead of "which layer is this bug in" collapses.
- **Performance.** Camera capture goes from "extremely slow" (binary-over-JSON IPC, jsQR in JS) to direct in-process Vec<u8> handed to `rqrr`. No serialization. No marshaling. No vendor blob.
- **Smaller binary, faster startup.** No bundled webview. No JS engine cold start. Tray-resident desktop tools are exactly Slint's target shape.
- **Layout system is industrial.** Slint's anchor-based layout fixes #33's enrollment-panel cramping without per-pane CSS gymnastics.
- **Window draggability.** Native window with Slint matches platform conventions; chromeless designs work without custom drag-region hacks.

### Negative

- **UI rewrite cost.** ~2-3 weeks of UI work assuming familiarity with Slint's DSL; longer if learning. The wizard, code panel, tray scaffold, and five enrollment-source panes all redo from scratch.
- **Mobile path regresses.** Slint has Android/iOS support but it's younger than Tauri's. If mobile tocken is on the roadmap, this trades present pain for future cost. (Current judgment: tocken is desktop-first; mobile is hypothetical.)
- **Smaller community.** Slint is younger than Tauri (5 years vs ~6, but smaller adoption). Stack Overflow / Discord coverage thinner. Mitigated by the team's responsiveness and the project's quality.
- **Packaging redo.** AUR / Flatpak / AppImage / .deb recipes all change. AUR is closest to existing pattern; Flatpak needs a new manifest.
- **PR #34 (camera) is a sunk-cost write-off.** The webview permission handler, jsQR vendoring, IPC plumbing — all discarded. We merge it as a historical reference for what didn't work, not as live code.

### Neutral

- **Backend code is unaffected.** `enroll/`, `store/`, `session/`, `wizard/`, `age` integration, `age-plugin-yubikey` subprocess, `recipients.txt` audit aid, ADR-100 store format, ADR-101 secret-length posture — all pure Rust, all portable.
- **CI gates unchanged.** `cargo test --lib` continues to be the pre-PR gate. Smoke fixtures (`scripts/gen-test-secrets.sh`) continue to work.
- **Issue tracking unchanged.** GitHub issues (#7, #8, #9, #10, #12, #13, #14, #15, #20, #21, #33) remain the source of truth for outstanding work; their bodies don't depend on UI framework choice except where explicitly noted (#21 Linux tray UX is largely solved by Slint's native tray support).

## Alternatives Considered

### Stay on Tauri

The "fix DMA-BUF rendering, fix camera black screen, ship raw-bytes IPC, polish layout" path. Each individual fix is tractable, but the pattern has been climbing for five PRs and the camera regression demonstrates that even when fights are won, the result is fragile. Rejected: friction is structural, not per-feature.

### CXX-Qt

Native Qt UI via the KDAB Rust bridge. First-party on KDE, mature widget catalog, decades of polish. Rejected for this project (not for general use): heavier dep tree (system Qt install, LGPL licensing flows, CMake adjacency), and Slint's smaller surface is sufficient for tocken's UI scale. Additional consideration: Qt's portability story is strong for desktop (macOS/Windows/Linux) but constrained for unusual targets — Qt for MCUs exists but is commercial-licensed, which closes the door on a speculative future where tocken runs on a dedicated embedded YubiKey-tethered viewer device. Slint's MCU support is open and active. CXX-Qt remains the right choice for projects that need Qt's full ecosystem and don't anticipate embedded variants.

### egui / iced

Pure-Rust immediate-mode (egui) or Elm-style (iced) UIs. Both work, both have a smaller ecosystem than Slint, both have lower aesthetic ceilings for production-grade desktop apps. egui is built for dev tools (debuggers, profilers); iced is younger than Slint with less documentation. Rejected: Slint hits the same "all-Rust, declarative, native" criteria with stronger UX polish.

### Native per-platform (SwiftUI / WPF / GTK)

Best-in-class on each platform. Rejected for solo-dev maintainability: three UIs to maintain, three sets of platform conventions, three release pipelines.

### Web-shell alternatives (Electron / Wails / Neutralino)

All carry the web-shell architecture's structural cost. Electron is heavier than Tauri (bundles Chromium); Wails has similar webview drama; Neutralino is minimal but younger. Rejected: doesn't address the root cause.

## Implementation notes (for next session)

- **Branch strategy.** Open a `slint-rebuild` branch that lives parallel to `main` until the new app reaches feature parity. `main` continues to build and ship the Tauri version during the transition.
- **Backend extraction first.** Move `enroll/`, `store/`, `session/`, `wizard/`, `now_unix`, `EntrySummary` etc. out of `app/src-tauri/src/lib.rs` into `crates/tocken-core/` (or similar) so both the Tauri version and the Slint rebuild can depend on it without one becoming a sub-module of the other during transition.
- **Order of features.** Wizard → code panel → enrollment (paste/manual/file/clipboard/camera) → tray → packaging. Match the original order so smoke fixtures and ADR-101 weak-secret prompt land on familiar surfaces.
- **Smoke parity.** Each Slint feature lands with the same smoke fixture as the Tauri equivalent (`scripts/gen-test-secrets.sh`).
- **Issue #6 stays open** until the Slint version has all five enrollment sources working. PR #34 is merged as historical reference but doesn't close #6.
- **CONTINUANCE.md** updated to point at this ADR as the session-7 starting context.
