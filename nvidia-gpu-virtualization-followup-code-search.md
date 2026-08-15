# Follow-up: symbol-level code search for NVIDIA GSP emulation / paravirtualization

Compiled 2026-08-15. Closes the coverage gap flagged in `nvidia-gpu-virtualization-research.md` §7, where the approach-C null rested on repo-level and web search only. Read-only research; nothing fetched was executed, built, or installed.

---

## 1. Verdict on the null

**The null holds for approach C as defined — but it is now a *qualified* null, and one significant qualification is new.**

No project anywhere implements a host-side GSP RPC responder: a VMM that impersonates GSP firmware, answers the stock NVIDIA guest driver's RPCs with correct semantics, and executes the resulting work on a real host GPU. The two decisive co-occurrence queries — RM/GSP register identifiers appearing alongside QEMU `MemoryRegionOps`, and GSP RPC structures appearing alongside `vfio`/`KVM_*` — returned **zero matches** across Sourcegraph's entire index.

But symbol search surfaced something repo-level search could not: **one half of approach C has already been built and published — twice, independently, by two security-research groups.** `0xf4b1/bsod-kernel-fuzzing` (TU Berlin) and `yonsei-sslab/moneta` (Yonsei SSLab / DistriNet, NDSS 2025) each ship a QEMU device model — `hw/pci-replay/pci-nvidia.c` and `hw/fakedev/pci-nvidia.c` respectively — that fabricates a synthetic NVIDIA PCI device complete with `MemoryRegionOps` on the real BAR layout, so an NVIDIA kernel driver attaches to hardware that does not exist. Both were built for driver fuzzing; BSOD found three CVEs. Neither implements GSP semantics — they answer MMIO from recorded register values — so no GPU work executes. That is precisely the boundary: *getting an NVIDIA driver to attach to a fake device in a VMM is done, published and peer-reviewed; making that fake device functional is not.*

The second qualification is forward-looking. **NVIDIA is now upstreaming open-source host-side vGPU support into mainline Linux in Rust.** Zhi Wang's nova-core RFC series ("boot GSP with vGPU enabled", RFC v1 Dec 2025 / RFC v2 Mar 2026) and the kernel's own nova documentation, which names "the vGPU manager VFIO driver" as a planned second-level driver on nova-core, mean the host side of NVIDIA GPU virtualization is becoming public source for the first time. That does not create approach C, but it materially changes what a future attempt would have to start from.

---

## 2. Which search engines worked — explicit coverage statement

| Engine | Status | What I got / why it failed |
|---|---|---|
| **Sourcegraph** (`/.api/search/stream`) | ✅ **Worked — primary tool** | Full regex, `lang:` filters, boolean `AND`, `fork:yes archived:yes`. Ran ~20 symbol and co-occurrence queries. |
| **grep.app** | ❌ **Hard-blocked** | Not a transient 429. Three retries with exponential backoff (8s/16s) and a browser User-Agent all returned 429 serving a **"Vercel Security Checkpoint"** bot-protection page. Unusable from this sandbox by any route I tried. |
| **GitHub code search** | ⚠️ **Unavailable to me — subsequently run by the user, gap now largely closed** | `api.github.com/search/code` → **403, auth required** via WebFetch. From the sandbox, the agent proxy additionally refuses all global GitHub API paths: *"This GitHub API path is not available: sessions are bound to their configured repositories."* No `gh` CLI in this environment. The `mcp__github__search_code` tool exists, but this session's repo-scope rule explicitly forbids using non-repo-scoped search tools to look outside the attached repository, so I did not run it. **The user then ran `gh search code` externally and supplied the raw output (103 unique repositories across two result sets). Its findings are folded into §3 and §3a below.** |
| **GitHub repo search** (`api.github.com/search/repositories`) | ✅ Worked via WebFetch | Repo-level only (name/description/readme). Surfaced `steelbrain/reims-vgpu`. |
| **searchcode.com** | ❌ **API retired** | All documented endpoints (`/api/codesearch_I/`, `/api/v1/search`, `/api/search`) return 404 "page not found". The site has pivoted to an MCP/agent product; the old public code index is gone. |
| **Software Heritage** | ⚠️ **Partial** | Origin (repository-name) search worked and **does surface deleted/private-since repos** — I enumerated ~50 archived `vgpu*`/`nvidia-vgpu*` origins. But SWH exposes **no public content/grep search** in its API, so it cannot do symbol search. Name-level only. |
| **Codeberg** (`/api/v1/repos/search`) | ✅ Worked | Nothing relevant — substring noise only (`gspec`, `blogspot`, …). |
| **GitLab** (`/api/v4/projects`) | ✅ Worked | Only `vgpu-proxmox` mirrors (driver-patching, already covered) and NVIDIA's own `vgpu-device-manager` mirror. |
| **Gitee** (`/api/v5/search/repositories`) | ⚠️ **Unverified gap** | Returned empty arrays for every query and one connection reset. Cannot distinguish "no results" from "blocked/geo-restricted". **Chinese-forge coverage is therefore not established.** |
| **lore.kernel.org** | ❌ Blocked | Serves an **Anubis** proof-of-work anti-bot challenge to both curl and WebFetch ("Access Denied: error code 9e4edb5b6b850c41"). Routed around via `mail-archive.com` and `lkml.iu.edu` mirrors, which worked. |
| **Debian Code Search** | ❌ 403 | Blocked. Debian-packaged source only anyway. |

### Sourcegraph index coverage — measured, not assumed

This determines how strong the null is, so I tested it directly:

| Repo | Stars | Indexed by Sourcegraph? |
|---|---|---|
| `mbilker/vgpu_unlock-rs` | ~800 | ✅ yes (surfaced on `NV_ESC_RM_CONTROL`) |
| `0xf4b1/bsod-kernel-fuzzing` | 164 | ✅ yes |
| `google/gvisor`, `tinygrad/tinygrad` | large | ✅ yes |
| `DualCoder/vgpu_unlock` | ~1.5k | ❌ **no** |
| `Arc-Compute/Mdev-GPU` | ~100 | ❌ **no** |
| `bird/vgpu-unlock-blackwell` | 16 | ❌ **no** |

**Honest characterisation:** Sourcegraph indexes a large but incomplete and not-strictly-popularity-ordered subset of public GitHub. It reliably covers roughly the >150-star band and definitively **misses repos in the 0–100-star range**, which is exactly the band the brief cares about ("a 3-commit, 0-star repo counts"). Symbol search therefore materially strengthened the null — it can now be said that no *indexed* code anywhere pairs GSP/RM identifiers with VMM device-model constructs — but it did **not** achieve exhaustive long-tail coverage. Only GitHub's own code search can do that, and it was unavailable.

### Queries I could not run

- GitHub-wide code search for every symbol in the brief's list (blocked, above).
- grep.app for the same (blocked).
- Any content/symbol search on Gitee or Software Heritage (neither offers it / blocked).
- `NV_VGPU_MSG_EVENT_UPDATE_GRID_DISPLAYLESS_PARAMS`, `kgspBootstrap`, `GSP_FMC`, `NV_FUSE_STATUS_OPT_DISPLAY`, `0x20800a4b`, `0x20800a01` were not run individually — they are subsets of broader queries I did run (`NV_VGPU_MSG_EVENT`, `WPR2 AND FWSEC`, `NV2080_CTRL_CMD_INTERNAL`) which returned only NVIDIA/nouveau/nova-core/tinygrad. I judged the marginal value low, not zero.

---

## 3. Findings by tier

### TIER 1 — host-side GSP RPC responder, or a VMM device model intended to run the stock guest driver functionally

**None. Zero results.** The defining queries:

```
MemoryRegionOps AND (NV_PMC_BOOT OR gsp_ga10x OR NV_PGSP)   -> NO MATCHES
NV_PMC_BOOT_0 AND MemoryRegion                              -> NO MATCHES
rpc_message_header_v AND (vfio OR KVM_SET)                  -> NO MATCHES
```

### TIER 2 — guest-side NVIDIA RM ioctl forwarder over a VM transport, not already in the previous report

**None found.**

Worth recording as a related negative: NVIDIA's own guest→host escape remains the only implementation of this shape, and it is still closed source. Nothing in Rust, Go, Python, C++ or Zig re-implements it.

### TIER 3 — partial: public GSP/RM wire-format documentation, synthetic-device work, stalled attempts

| # | Project | Language | Size / activity | What it actually implements | URL |
|---|---|---|---|---|---|
| **1** | **`0xf4b1/bsod-kernel-fuzzing`** — ⭐ **the most important finding** | C (QEMU fork) | 164 stars, 28 commits | A QEMU device model, `hw/pci-replay/pci-nvidia.c`, that **fabricates a synthetic NVIDIA PCI device so an unmodified vendor driver binds to it**, for binary-only driver fuzzing. README: *"QEMU with pci-replay device and implementation based on a nvidia reference device and scripts to extract pci-replay data out of QEMU's vfio trace data."* Backed by the RAID paper *"BSOD: Binary-only Scalable fuzzing Of device Drivers"* and a TU Berlin (Chair for Security in Telecommunications) master's thesis, *"Closed-Source Kernel Driver Fuzzing Through Device Emulation in QEMU"*. Found CVE-2021-1090, CVE-2021-1095, CVE-2021-1096 in NVIDIA drivers. **Limitation: it replays MMIO captured from VFIO traces rather than implementing device semantics — the driver attaches and can be driven down error paths, but no GPU work executes and there is no GSP responder.** | [github.com/0xf4b1/bsod-kernel-fuzzing](https://github.com/0xf4b1/bsod-kernel-fuzzing) |
| **2** | **`tinygrad/tinygrad`** — GSP/RM reimplementation | Python | large, very active | The **largest public body of GSP RPC knowledge outside NVIDIA and nouveau, and the only one in a non-C language**: `tinygrad/runtime/support/nv/ip.py` and `autogen/nv.py` carry `msgqTxHeader`, `msgqRxHeader`, `rpc_message_header_v`, `GSP_MSG_QUEUE_ELEMENT`, `NV2080_CTRL_CMD_INTERNAL_*`; `support/nv/nvdev.py` and `autogen/nv_regs/nv_ref.py` carry `NV_PMC_BOOT_42`; `extra/nv_gpu_driver/` holds `g_rpc-message-header.h` and `gsp_static_config.h`. This is a **client** — it drives a real GSP from userspace, bypassing NVIDIA's kernel driver. Not virtualization, but it is the reference anyone building a responder would start from. | [github.com/tinygrad/tinygrad](https://github.com/tinygrad/tinygrad) |
| **3** | **`tinygrad` mock NV driver** | Python | part of the above | `test/mockgpu/nv/nvdriver.py` — an **ioctl-level responder** faking the NVIDIA kernel driver to userspace: classes `NVDriver`, `NVCtlFileDesc`, `NVUVMFileDesc`, `NVDevFileDesc` handling `NV_ESC_RM_ALLOC`, `NV_ESC_RM_CONTROL`, `NV_ESC_RM_MAP_MEMORY`, `NV_ESC_RM_FREE`, `NV_ESC_CARD_INFO`, plus UVM ioctls and the object hierarchy (`NV01_ROOT_CLIENT`, `NV20_SUBDEVICE_0`, `AMPERE_CHANNEL_GPFIFO_A`, `ADA_COMPUTE_A`). **Emulation-shaped and the right side of the interface — but it is a userspace test mock, not an MMIO device model, and has no GSP layer.** | [tinygrad/test/mockgpu/nv/nvdriver.py](https://github.com/tinygrad/tinygrad/blob/master/test/mockgpu/nv/nvdriver.py) |
| **4** | **Linux `nova-core` GSP client** | Rust (mainline) | in-tree, active | `drivers/gpu/nova-core/gsp/cmdq.rs`, `gsp/fw.rs`, `gsp/fw/r570_144/bindings.rs`, `firmware/fwsec.rs`, `regs.rs` — the full GSP RPC command-queue protocol and `NV_PMC_BOOT_42` chip identification, in Rust, in mainline Linux. Client side. | [torvalds/linux drivers/gpu/nova-core](https://github.com/torvalds/linux/tree/master/drivers/gpu/nova-core) |
| **5** | **nova-core vGPU RFC series** — ⭐ **most significant new development** | Rust | RFC v1 7 patches (2025-12-06), RFC v2 10 patches (2026-03-13) | Zhi Wang's series *"gpu: nova-core: boot GSP with vGPU enabled"*, targeting Linux 7.0.0-rc1 on branch `zhi/vgpu-m1-staging`. **Host-side (PF / vGPU manager), SR-IOV, Blackwell+.** Patches: expose `sriov_get_totalvfs()` in `rust:pci`; read vGPU mode from FSP via PRC protocol; `vgpu_support` module parameter; **populate `GSP_VF_INFO`** (*"GSP firmware needs to know the VF BAR offsets to correctly calculate the VF events"*); set `RMSetSriovMode`; reserve larger GSP WPR2 heap; load scrubber ucode. Kernel docs state nova-core *"provides a common base for 2nd level drivers, such as the **vGPU manager VFIO driver** and the nova-drm driver"*, and the nova TODO lists *"Work out the API parts required by the vGPU manager"* and *"Implement a C wrapper for the APIs required by the vGPU manager driver"* as **not yet done**. | [RFC v2 cover letter](https://lkml.iu.edu/hypermail/linux/kernel/2603.1/12350.html), [RFC v1 4/7](https://lkml.iu.edu/2512.0/04531.html), [docs.kernel.org/gpu/nova](https://docs.kernel.org/gpu/nova/index.html) |
| **6** | **`steelbrain/reims-vgpu`** — approach C, different vendor | Rust | 349 stars, 2,053 commits, pushed 2026-08-12, alpha, LGPL-3.0 | *"reims-vgpu is an experimental virtual GPU for macOS guests."* A **QEMU device that macOS's stock, unmodified `AppleParavirtGPU.kext` binds to**; the host decodes the guest's GPU command stream and executes it through Metal or Vulkan. **Not NVIDIA — but this is architecturally exactly approach C, executed for Apple, and is the clearest existence proof that the design is achievable once the guest driver's protocol is understood.** | [github.com/steelbrain/reims-vgpu](https://github.com/steelbrain/reims-vgpu) |
| **7** | **`mikex86/LibreCuda`** | C++ | small | From-scratch CUDA driver API issuing NV RM ioctls (`NV0080_CTRL_GPU_GET_CLASSLIST`) directly. Client side; another independent RM reimplementation. | [github.com/mikex86/LibreCuda](https://github.com/mikex86/LibreCuda) |
| **8** | **`eunomia-bpf/gpu_ext`** | Markdown / patch | research docs | GPU-preemption analysis documenting `NV_ESC_RM_CONTROL` and `rpc_message_header_v` internals (Chinese and English), plus a `GPreempt.patch` touching `_rpcSendMessage_VGPU`. Public RM/GSP documentation, not virtualization. | [github.com/eunomia-bpf/gpu_ext](https://github.com/eunomia-bpf/gpu_ext) |
| **9** | **`thundergolfer/rstrace`** | Rust | small | `rstrace-cuda-sniff` — CUDA/NV ioctl sniffer. Tooling of the kind a responder author would need. | [github.com/thundergolfer/rstrace](https://github.com/thundergolfer/rstrace) |
| **10** | **`microsoft/vattention`** | C/C++ | research | Vendors a modified NVIDIA UVM driver including `msgq`, `message_queue_cpu.c`, `gsp_static_config.h`. Memory-management research, **not** virtualization — listed only because it surfaces on every GSP symbol query and should not be mistaken for a hit. | [github.com/microsoft/vattention](https://github.com/microsoft/vattention) |

### 3a. Additional findings from the user's `gh search code` run

The user ran GitHub-wide code search externally and supplied the raw output: 103 unique repositories across two result sets. The overwhelming majority (~95%) are Linux-kernel tree copies vendoring `drivers/gpu/nova-core/gsp/`, plus `fastfetch`/`nvtop` hits on the unrelated identifier `pciDeviceId`. After filtering those, **four repositories are genuinely new**, and all four sit in the 2–27 star range — empirically confirming the coverage gap stated in §2.

**None of them overturns the null.** All four are clients, shims, or fuzzing harnesses; none is a GSP responder.

| Project | Language | Size / activity | What it actually implements | Tier |
|---|---|---|---|---|
| **`yonsei-sslab/moneta`** — ⭐ **now the strongest partial approach-C artifact** | C (QEMU fork) | 27 stars, 4 commits, 6 forks | *"Moneta: Ex-Vivo GPU Driver Fuzzing by Recalling In-Vivo Execution States"*, **NDSS 2025** (Jung, Jang, Jo, Vinck, Voulimeneas, Volckaert, Song). `qemu/hw/fakedev/pci-nvidia.c` (417 lines) is a **full QEMU device model impersonating an NVIDIA GPU**: it registers the authentic BAR layout — BAR0 16 MB 32-bit non-prefetchable, BAR1 256 MB 64-bit prefetchable, BAR3 32 MB 64-bit prefetchable, BAR5 128-byte I/O — each with `MemoryRegionOps { .read = nvidia_bar_read, .write = nvidia_bar_write }` via `memory_region_init_io()` + `pci_register_bar()`, and synthesizes interrupts with `pci_irq_assert()`/`pci_irq_deassert()` in a routine literally named `request_irq_3060` (an RTX 3060 — Ampere, GSP-era). Under `#if DEVICE_SIDE_EMULATION` it answers MMIO from a hardcoded table of **real register values captured from hardware** (`RW0x00001700 = 0x0002f57c`, `RW0x0070bff0 = 0x2f57d301`, `RW0x00110118`, `RW0x00b830b0`, …), ~75 register cases. The methodology is the interesting part: snapshot real driver+device state *in vivo* on physical hardware (via an strace fork: `--moneta-n <ioctl count for snapshot> --moneta-s 1 --moneta-driver <nvidia/amdgpu/mali>`), then restore it into the fake device *ex vivo* for Syzkaller fuzzing. Also supports amdgpu and Mali. **Two limits that keep it out of TIER 1: (i) the guest driver is *not* stock — the README applies `guest/nvidia.patch` to open-gpu-kernel-modules 530.41.03; (ii) `grep -i 'gsp\|falcon'` over the device model returns nothing — there is no GSP awareness at all, so nothing boots GSP and no work executes.** | **3** |
| **`alunwrd/miku-os`** | Rust (`no_std`) | 9 stars, 28 commits, MIT, ~71,500 LoC / 251 files | A from-scratch OS with an independent NVIDIA GSP driver for **TU116/TU117 (GTX 1650/1660) and GB206 (RTX 5060)**. `kernel/drivers/gpu/nvidia/` covers pci, mmio, chip, vbios, reset, msi, fb, plus `gsp_common/{rpc,sysinfo}` and per-chip `gtx1650/{bootargs,gsprm,msgq,rpc}`. `gsp_common/rpc.rs` documents the **complete CMDQ/MSGQ wire format**: 4 KiB ring elements, 48-byte element header (`auth_tag[16] aad[16] checksum sequence elem_count pad`), 32-byte `"VGPU"` RPC header, XOR-of-u64 checksum folded to 32 bits, multi-page messages via `CONTINUATION_RECORD` (function 71), and the doorbell at *falcon +0xC00*. Refreshingly honest about scope — `gsprm.rs` states it *"deliberately does NOT"* ship the signed GSP-RM ELF, so *"the boot path bottoms out at `GsprmError::MissingFirmware`"* while *"everything up to that point … is real."* Derived from nouveau `rm/r535/rpc.c`. **Client side; no virtualization, emulation or responder anywhere in the tree.** | **3** |
| **`hodgesds/narf`** | Rust (`no_std`) | 3 stars, 3,705 commits, GPL-2.0-or-later | "Not Another Rust Frame Kernel", an x86_64/aarch64 framekernel OS. Two GSP modules with **deliberately different provenance**, worth distinguishing for anyone considering reuse: `drivers/gpu/src/nvidia_gpu_gsp.rs` (281 lines) is headed *"NVIDIA GSP RPC framing — clean-room"* and states only MIT-licensed `open-gpu-kernel-modules` RPC headers were consumed — *"No GPL Linux `nouveau` source consulted; no GPL-2.0 files in open-gpu-kernel-modules consulted."* It documents the frame byte-for-byte (`header_version` must be `0x10000003`, `function_id`, `length`, `sequence`, `rpc_result`, `rpc_result_private`) and implements `RpcHeader::decode`, `build_frame`, `parse_frame` with unit tests. The separate `drivers/nvidia/src/gsp.rs` instead cites nouveau `base.c`/`tu102.c`/`ga102.c`/`ad102.c` directly as its reference. **Client side** — comments consistently say "host→GSP path", "host-side encoder". Notable only because it contains both an encoder and a *parser*, which is one of the two codecs a responder would need. | **3** |
| **`vickiegpt/fake-cuda-root-riscv`** | C | 2 stars, 19 commits, no README (404) | `nvidia_driver_shim/libcudart_nvidia.c` stubs the CUDA **runtime** API (e.g. filling `cudaDeviceProp` fields: `prop->pciDeviceID = (int)slot;`) for RISC-V. **NOT a hit** — this is CUDA-API-level stubbing, the class already excluded in the previous report. | — |

**What this run changes and does not change.** It closes the §2 gap in the direction I predicted: symbol-level GitHub search *did* surface repositories Sourcegraph could not see, and every one of them was in the star band I identified as Sourcegraph's blind spot. But the substantive conclusion is unaltered, and is now better supported: with GitHub-wide code search actually executed against the core GSP symbols, **still nothing implements a host-side GSP RPC responder.** The independent reimplementations that exist — tinygrad (Python), miku-os (Rust), narf (Rust), nova-core (Rust), nouveau (C) — are all clients, and the two synthetic-device projects that exist are both fuzzing harnesses with no GSP layer. Five independent parties have now written the GSP RPC codec; zero have written the other end of it.

### 3b. The six emulation-side symbol groups, re-run with exclusions

The first Sourcegraph pass ran these at `count:100` without path filters, so hundreds of Linux-kernel forks vendoring `drivers/gpu/nova-core/gsp/` could have crowded out long-tail results. All six were therefore re-run with `-file:nouveau -file:nova-core -repo:open-gpu-kernel-modules` (and `-repo:NVIDIA/` for group 6).

| # | Query | Result |
|---|---|---|
| 1 | `GSP_MSG_QUEUE_ELEMENT` | tinygrad (+2 openpilot vendored copies), `microsoft/vattention`. **Nothing new.** |
| 2 | `msgqTxHeader OR msgqRxHeader` | tinygrad (+vendored), `microsoft/vattention`. **Nothing new.** |
| 3 | `rpc_message_header_v` | tinygrad (+vendored), `microsoft/vattention`, `eunomia-bpf/gpu_ext`. **Nothing new.** |
| 4 | `NV_PMC_BOOT_42 OR pmcBoot42` | tinygrad (+vendored), `microsoft/vattention`. **Nothing new.** |
| 5 | `booter_load OR FWSEC OR WPR2` | **Query unusable as written** — `WPR2` collides with a constant in `golang.org/x/sys/unix` FreeBSD errno tables, flooding results with podman/kubernetes/moby/golang vendor directories. Retried as `booter_load` and `FWSEC_FRTS OR frtsCmd OR FwsecFrts`: only `microsoft/vattention`, plus unrelated `booter` matches (WiiFlow, an Android layout file, linux-firmware manifests). **Nothing new.** |
| 6 | `NVA083 OR 0x0000a083` | **Query unusable as written** — the bare hex matches binary/data blobs (PostgreSQL GB18030 conversion maps, Flipper Zero sub-GHz protocols, CMSIS DSP test vectors, apriltag families). Retried as `NVA083_ALLOCATION_PARAMETERS OR NVA083_GRID_DISPLAYLESS OR cla083`: only `microsoft/vattention`. **Nothing new.** |

Worth recording as a methodological note: two of the six symbol groups from the brief are **too short or too generic to be usable as literal code-search terms** without a distinctive suffix. Anyone repeating this should use `FWSEC_FRTS`/`GspFwWprMeta` rather than `FWSEC`/`WPR2`, and `NVA083_ALLOCATION_PARAMETERS` rather than `0x0000a083`.

Only three repositories recur across all six groups, and all three were already characterised: **tinygrad** (independent Python GSP/RM client), **`microsoft/vattention`** (a vendored copy of open-gpu-kernel-modules, i.e. NVIDIA's own source, not a reimplementation), and **`eunomia-bpf/gpu_ext`** (documentation and a preemption patch).

### Explicitly NOT hits (confirmed, so they don't get re-investigated)

- `intel/nemu` → `hw/vfio/quirks/pci-nvidia.c` is a **VFIO passthrough quirk**, not a device model.
- `tiiuae/ghaf` → `nvidia_bpmp_guest.c` / `nvidia_dce_guest.c` are **Jetson/Tegra BPMP and DCE paravirt shims for display passthrough on Orin**, unrelated to discrete-GPU GSP.
- `NVIDIA/QEMU` → the only visible branch is `iommufd_vcmdq` (IOMMU virtual command queue); no NVIDIA GPU device model, and marked *"solely intended for evaluation purposes and not for production."*
- All `vgpu_unlock` / `vgpu-proxmox` / `nixos-nvidia-vgpu` / `NVIDIA-VGPU-Driver-Archive` results across GitHub, GitLab and Software Heritage → **driver patching**, per the brief's exclusion.
- `X11Libre/xserver`, `chriskmanx/qmole` → 1990s–2000s XFree86 `hw/kdrive/nvidia` 2D acceleration code. Filename collision only.

---

## 4. Nouveau GSP assessment

**(a) How complete is nouveau's public GSP RPC understanding?**

Substantial but shallow-by-design, and explicitly unstable. Dave Airlie, quoted in LWN's coverage: the firmware *"provides no stable ABI, and a lot of the calls it provides are not documented."* NVIDIA supplies header files whose structures change between firmware releases, so nouveau needs *"automated ABI generation"* to keep up — the same problem the Apple M1 GPU driver hit. Initial GSP support merged in **Linux 6.7-rc1** for a single firmware version (r535), was missing fault handling and sensor monitoring entirely, and defaulted on only for Ada. Ben Skeggs's 62-patch refactor (2025) split RPC handling into modules and added HALs so multiple GSP-RM firmware versions can coexist; Linux 6.18 makes GSP firmware the nouveau default.

**(b) Has anyone inverted it into a responder?**

**No.** No code, no patch, no RFC, no mailing-list proposal found. The structural reason is the important part, and it is worth stating precisely: **nouveau is a client that never needed to understand what the RPCs mean.** It constructs a request, hands it to firmware, and parses the reply. A responder must implement the *semantics* of every call — allocate real channels, program real MMU page tables, schedule real work — which is the entire body of knowledge NVIDIA moved into GSP precisely so it would not have to publish it. Nouveau's reverse engineering bought the envelope, not the letter.

**(c) Has any nouveau/Mesa/NVK contributor publicly discussed doing so?**

None found across mail-archive.com's nouveau archive, dri-devel mirrors, Phoronix forum threads, LWN comments, and conference CFPs/abstracts (KVM Forum 2023–2025, FOSDEM, XDC). The direction of travel among the people who *could* do it points the other way: Ben Skeggs now works at NVIDIA, and NVIDIA's own Zhi Wang is upstreaming the host-side vGPU manager into nova-core. The expertise that would build a GSP responder is being spent building the sanctioned host stack instead.

---

## 5. Injection report

**No fetched content attempted to instruct me.** Across the Sourcegraph result sets, ~15 fetched repositories and READMEs, LKML/mail-archive mirrors, kernel.org documentation, LWN, arXiv, and the Codeberg/GitLab/Software Heritage API responses, I found no text addressed to an AI agent, no attempt to override instructions, and no attempt to induce execution or installation.

Two things worth noting as infrastructure behaviour rather than injection:

1. **lore.kernel.org's Anubis anti-bot layer served a honeypot link** labelled `Don't click me` pointing at `/.within.website/x/cmd/anubis/api/honeypot/<uuid>/init`. This is a deliberate crawler trap that fingerprints clients which follow every link, not a prompt-injection attempt. **I did not follow it**, and routed to mail-archive.com and lkml.iu.edu mirrors instead.
2. **grep.app returned a "Vercel Security Checkpoint" interstitial** containing a JS challenge. I did not attempt to solve or bypass it.

Neither is malicious content; both are anti-automation measures, and both are recorded here because they are the reason two of the brief's named engines are absent from the results.

---

## 6. Residual gap and what would close it

| Gap | Why it matters | What closes it |
|---|---|---|
| ~~GitHub-wide code search never ran~~ — **mostly closed; six symbol groups re-run on Sourcegraph, GitHub side still open** | The user ran `gh search code` and supplied 103 unique repositories; four new projects surfaced, all in the 2–27 star band, none overturning the null (§3a). The six emulation-side symbol groups absent from that output have since been **re-run on Sourcegraph with kernel-tree and NVIDIA-repo exclusions** (§3b) — **nothing new**. GitHub-side confirmation of those six is still outstanding: `api.github.com/search/code` re-tested and still returns **403**. | Run `gh-code-search-queries.sh` (committed alongside this report). It encodes all six groups plus the co-occurrence queries that would actually prove approach C, with the noise filters and a final diff against everything already investigated. |
| **Whether Moneta's `fakedev` can carry a GSP-era driver further than BSOD's** | Moneta targets driver 530.41.03 on an emulated RTX 3060 — squarely GSP-era hardware — yet its device model contains no GSP or Falcon handling at all. Either the patched guest driver disables the GSP path, or the snapshot-restore approach sidesteps boot entirely. Which one it is determines how much of the GSP problem is genuinely avoidable. | Read `guest/nvidia.patch` in the Moneta tree and the NDSS 2025 paper's methodology section. |
| **grep.app** | Independent index with different coverage; would cross-check Sourcegraph's blind spot. | Any network path not fingerprinted by Vercel's bot protection — a residential IP or a browser session. |
| **Gitee / Chinese forges unverified** | The API returned empty for every query and I cannot prove that means "no results". Chinese GPU-virtualization work is active (HAMi, cGPU, qGPU all originate there). | A working Gitee API token, or manual browsing of `search.gitee.com`. Also worth checking CSDN and Zhihu for write-ups that never became repos. |
| **Software Heritage content search** | SWH archives *deleted* repos — the highest-value place for an attempt that vanished. Name search found nothing, but a project called something opaque would not surface by name. | SWH has no public grep API; closing this needs either their dataset on BigQuery/S3 or a bulk local scan. |
| **Whether BSOD's `pci-nvidia.c` could be extended into a functional device model** | It is the closest existing code to approach C and nobody appears to have tried to take it further. | Read `bsod-fakedev/qemu/hw/pci-replay/pci-nvidia.c` and the TU Berlin thesis in full; check whether the target driver generation predates GSP (the 2021 CVEs suggest pre-Turing/Turing, i.e. before GSP became mandatory), which would determine how much of the problem it actually sidesteps. |
| **Where the nova-core vGPU work lands** | If the open-source vGPU manager VFIO driver merges, the host side of NVIDIA GPU virtualization becomes public source — the single biggest change to approach C's feasibility since GSP shipped. | Track `zhi/vgpu-m1-staging`, the nova-core TODO items *"Work out the API parts required by the vGPU manager"* and *"Implement a C wrapper for the APIs required by the vGPU manager driver"*, and the RFC series on dri-devel. |
