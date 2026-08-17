# Deep dive: `nestrilabs/virtio-nvgpu`

A second approach-B implementation — and a considerably more advanced one.

Compiled 2026-08-15. **Static source review only.** The repository was cloned read-only; nothing in it was built, installed, or executed. All five branches were examined. Companion to `isospin-microvm-deep-dive.md`, which analyses the other approach-B project found in this research.

---

## 1. Executive summary

`virtio-nvgpu` forwards the NVIDIA kernel driver ioctl surface from a Linux guest to the host **over a virtio virtqueue**, so the guest runs NVIDIA's own unmodified user-mode drivers (Vulkan, OpenGL, CUDA, NVENC) against a guest kernel module that is not NVIDIA's. It is built by **Nestri Labs**, an established open-source cloud-gaming project, and the target workload explains the design: a Wayland compositor inside a headless VM renders, composites, and encodes with NVENC, and only the compressed bitstream leaves the VM.

Two things distinguish it from `isospin-microvm`:

1. **It solves the `mmap` problem.** Isospin stops at "control path only". This project has the VMM allocate a guest physical address, register a **KVM memory slot** mapping it to the host mapping, and hand the GPA back to the guest driver, which wires it in with `remap_pfn_range()`. After that the render loop touches GPU memory through EPT with **no VM exits and no VMM involvement**. That is the architecturally correct answer and it is the difference between "enumerates the GPU" and "can actually run a workload."
2. **It has a real security allowlist**, ported from gVisor's `nvproxy` frontend ioctl map, with capability gating and explicit fd translation.

Commit history on two branches records **`feat: nvidia-smi works`**, with subsequent commits fighting Vulkan, `nvidia-modeset` and DRM. Last activity 2026-04-16.

**Legitimacy: high. Safety of the code: no malicious indicators found.** The caveats are about maturity and vendored binaries, not integrity — see §7.

---

## 2. Branch layout — read this before judging the project

The repository is easy to misread, because **the default branch is the least representative one.**

| Branch | Commits | Contents | Note |
|---|---|---|---|
| `dev` *(default)* | 2 | `README.md`, `ARCHITECTURE.md`, `.gitignore` only | **Design documents only.** Carries the banner: *"This is a design document and proposal. Nothing here is implemented yet."* |
| `feat/init` | 55 | Standalone Rust workspace: `crates/abi`, `crates/device`, `crates/protocol` (~3,300 lines) | Prototype backend. **Still carries the stale "nothing implemented yet" banner in its README** despite containing the implementation. |
| `nv/libkrun` | 19 | Full **libkrun** VMM fork with `src/devices/src/virtio/gpu_nv/` (~1,975 lines) | The real integration. This is where the production device lives. |
| `libkrunfw` | 14 | **libkrunfw** fork with `nvgpu/virtio_gpu_nv.c` (2,743 lines), `nvgpu_gen.py` (1,295 lines) | The guest kernel driver and its ABI generator. |
| `libkrunfw-dev` | 3 | Earlier libkrunfw fork with TEE/SEV patch sets | Superseded. |

Anyone who looks only at `dev` will conclude this is vapourware. It is not — there are roughly **8,000 lines of working code** spread across `feat/init`, `nv/libkrun` and `libkrunfw`. The stale banner is the single most misleading thing about the repository.

Authors: **Wanjohi** (`elviswanjohi47@gmail.com`) and **DatCaptainHorse**. Activity spans 2026-03-31 to 2026-04-16.

---

## 3. Why it exists

From `dev:README.md`, the target pipeline:

```text
Guest VM (headless, no physical display)
  Game / application → Vulkan or OpenGL
    → Wayland compositor (guest-side), composites all windows
    → CUDA zero-copy import of composed frame
    → NVENC hardware encoder (guest-side) → H.264/H.265 (~100 KB/frame)
    → Stream to remote client
```

> The entire render → composite → encode pipeline runs **on the GPU, inside the guest**. Only the compressed bitstream leaves. This requires the guest to have **real, driver-level access** to GPU resources: buffer handles, fences, CUDA device pointers, NVENC sessions.

The README then argues why the existing options fail for this. Against **virtio-gpu + Venus** (API-level translation): games issue 1,000–5,000 draw calls per frame, each serialised and replayed individually, and *"even 1–3 ms of serialization overhead per frame is 6–18% of the budget gone before any GPU work happens"*; further, GPU buffers are owned by the host, so *"guest-side NVENC encoding is not viable because the guest never holds real GPU pointers to import into CUDA."* Against **DRM native context**: that exists for Intel and AMD via Mesa, and there is no NVIDIA equivalent — a point the first report in this series established independently.

That reasoning is sound, and it is the clearest articulation I have seen of *why* someone would build approach B for NVIDIA rather than using what already ships.

---

## 4. Architecture

From `dev:ARCHITECTURE.md`:

```text
Guest                                    Host
──────────────────────────────           ──────────────────────────
App (Vulkan / GL / CUDA / NVENC)
  │ ioctl(/dev/nvidia*)
  ▼
virtio-gpu-nv guest driver
  │ serialize request
  │ virtqueue
  ▼                                      virtio-gpu-nv backend
  ═══════ VM exit ═══════════════════►     │ deserialize request
                                           │ translate handles/FDs
                                           │ ioctl(host_fd, ...)
                                           ▼
                                         NVIDIA KMD → GPU hardware
```

Host runs the real NVIDIA driver and exposes `/dev/nvidiactl`, `/dev/nvidia0`, `/dev/nvidia-uvm`. Guest has NVIDIA's user-mode libraries but **a custom kernel module replaces NVIDIA's**. Hypervisor is KVM; VMM is libkrun, with the backend running in-process.

Note the contrast with isospin: there is **no separate GPU-owning VM and no vsock bridge**. The host itself runs the NVIDIA driver and the VMM talks to it directly. Simpler, one fewer hop, but it also means a host-side driver compromise is a host compromise (§6.3).

---

## 5. The interesting engineering

### 5.1 The `mmap` path — the thing isospin does not have

`nvgpu/virtio_gpu_nv.c` header:

> Ioctls are forwarded over the control virtqueue; **mmap requests result in KVM memory slots set up by the VMM so hot-path GPU writes go direct through EPT — no VMM involvement in the render loop.**

Host side, `src/devices/src/virtio/gpu_nv/mmap.rs`:

> `handle_mmap` — the critical piece that makes steady-state GPU operations run at native speed.
> 1. Perform `mmap()` on the host NVIDIA device fd.
> 2. Allocate a guest physical address (GPA) from the MMIO window.
> 3. Register a KVM memory slot: GPA → host virtual address.
> 4. Return GPA + `mapping_id` to the guest driver.
>
> The guest driver then calls `remap_pfn_range()` to wire that GPA into the requesting process's virtual address space. From that point on, every GPU command write goes directly through EPT to the host physical pages the GPU is DMA'ing from — **zero VMM involvement.**

And in the guest, exactly as described:

```c
ret = remap_pfn_range(vma, vma->vm_start,
                      le64_to_cpu(resp->guest_phys_addr) >> PAGE_SHIFT, size, ...);
```

This is the design that makes the whole approach viable. Ioctls are a control-plane cost paid at setup; the per-frame path is native. It is also the piece that gVisor's `nvproxy` design document flags as the hard part of NVIDIA ioctl proxying, and which isospin explicitly punts (`"mmap not implemented (control path only)"`).

### 5.2 Nested guest pointers — the V1→V2 rewrite table

The problem that defeats naive ioctl forwarding: many `RM_CONTROL` commands carry *nested* params containing further userspace pointers. A VMM cannot follow a guest userspace pointer. This project attacks it two ways.

**Rewriting.** `nvgpu/gen/nvgpu_v1v2_rewrites.h` — *auto-generated from NVIDIA driver 595.58.03 by `nvgpu_gen.py`*:

> Many RM_CONTROL commands have two variants:
> V1: nested params contain a userspace pointer to a data buffer
> V2: nested params contain inline data (no second-level pointer)
> The guest driver cannot forward V1 to the VMM because the VMM cannot dereference guest userspace pointers inside nested params.

So the guest driver rewrites V1 calls into their V2 equivalents, driven by a generated table with per-command offsets:

```c
struct nvgpu_v1v2_entry {
    u32 v1_cmd, v2_cmd, v2_size;
    u32 v1_userptr_offset;  /* byte offset of NvP64 in V1 nested params */
    u32 v1_copy_prefix, v2_data_offset, v2_data_size;
    bool info_style;
};
```

**Interception.** Where no working V2 variant exists, `nvgpu/nvgpu_rm_intercepts.h` handles the command *in the guest*, synthesising the answer from config space or procfs and writing results back to the original guest pointers. It documents its own coverage honestly:

```
0x00000101  SYSTEM_GET_BUILD_VERSION      3 string ptrs   → intercept
0x00000110  SYSTEM_GET_P2P_CAPS_V2        1 array ptr     → TODO
0x20800288  GPU_GET_NVENC_SW_SESSION_INFO 1 array ptr     → TODO
0x20800803  BIOS_GET_NBSI                 1 data ptr      → TODO
0x20801210  GR_GET_CTX_BUFFER_INFO        1 array ptr     → TODO
0x20810107  VGPU_MGR_GET_PGPU_INFO        2 ptrs          → TODO (MIG)
0x90960103  SWINTR_GET_INFO               1 array ptr     → TODO
```

This is the exact problem isospin leaves as `// TODO: Parse params and translate any embedded handles`. Here it is a designed subsystem with a generator behind it.

**The security consequence is the important part**, and it appears to be deliberate: because the VMM never dereferences a guest pointer, an entire class of confused-deputy bug is structurally excluded rather than mitigated.

### 5.3 ABI versioning by code generation

`nvgpu_gen.py` (1,295 lines) generates `nvgpu_rmalloc_classes.h` and `nvgpu_v1v2_rewrites.h` from NVIDIA driver source, and `crates/abi/src/versions/` carries per-version modules (`v535_129_03.rs`, `v595_58_03.rs`) behind a `version.rs` selector.

NVIDIA guarantees no ioctl ABI stability across driver releases — the constraint that gVisor manages with a rolling support window and that LWN identified as nouveau's structural burden. Generating the tables from driver source rather than hand-transcribing them is the correct response, and it is the single most forward-looking decision in the project.

### 5.4 Device coverage

The guest driver registers considerably more than a token surface:

```c
struct cdev cdev_gpu[248];  /* /dev/nvidia0 … nvidia247 */
struct cdev cdev_ctl;       /* /dev/nvidiactl */
struct cdev cdev_uvm;       /* /dev/nvidia-uvm */
struct cdev cdev_caps;      /* /dev/nvidia-caps */
struct cdev cdev_modeset;   /* /dev/nvidia-modeset */
```

plus DRI card nodes and synthesised `/proc` and `/sys` entries — commits include *"Add support for SYS files and DRI cards"* and *"Add support for passing sys and dri cards from the host"*. Real userspace stacks probe all of this; covering it is unglamorous and necessary.

---

## 6. Security assessment

### 6.1 What the design gets right

- **A real ioctl allowlist.** `src/devices/src/virtio/gpu_nv/allowlist.rs`: *"Security boundary: only ioctls on this list are forwarded to the host NVIDIA driver. Unknown commands are rejected with ENOTTY. The frontend list is ported from gVisor's nvproxy frontendIoctl map."* Isospin has no allowlist at all.
- **Capability gating.** The allowlist is constructed from `caps` (`NVGPU_CAP_GRAPHICS`, `NVGPU_CAP_VIDEO`), mirroring gVisor's driver-capability model, so a compute-only guest never gets the graphics surface.
- **Explicit fd translation.** `FD_TRANSLATION_IOCTLS` records which ioctls carry an embedded fd and at what offset (`NV_ESC_REGISTER_FD` at offset 0), so guest fd numbers are translated rather than passed through.
- **Isolation by host fd, not by handle arithmetic.** `handle_table.rs` maps opaque guest handles to `OwnedFd`s. RM objects are scoped by the host driver to the `nvidiactl` fd that created them, so **the host NVIDIA driver enforces client separation itself** rather than the proxy re-implementing it. This is a stronger model than isospin's virtual→real handle translation, which had a predictable-handle weakness.
- **The VMM never dereferences guest pointers** (§5.2) — structural, not incidental.
- **Deliberate teardown.** `handle_table.rs` documents the ungraceful path: virtio device reset → `teardown()` → `drain_all()` drops every `OwnedFd`, so a VM crash frees all host-side RM state. It cites nvproxy's `Release()` as the model.

### 6.2 Where it is incomplete

- **UVM is not allowlisted.** *"UVM ioctls are always forwarded for the full UVM command set."* UVM is a large and historically bug-prone surface; gVisor allowlists it. This is the most significant gap.
- **Two unidentified allowlist entries.** `a.frontend.insert(0x34); // TODO: Write which one is this` and the same for `0x4a`. Allowing an ioctl nobody has identified is exactly the thing an allowlist exists to prevent.
- **Interrupt delivery unfinished.** `/* TODO: deliver to waiting guest processes */` in the guest driver.
- **Debugging-era allowances may persist.** Commits include *"fix: Temporarily allow some ioctl calls"* and *"fix: Try mocking the data, see if it is our suspect"*. Anyone deploying this should audit the allowlist against those commits rather than assume they were reverted.

### 6.3 The structural exposure

The host runs the NVIDIA driver and the VMM forwards guest-controlled ioctls into it. That is the same exposure gVisor states plainly about itself — *"gVisor is much less effective at mitigating vulnerabilities within the NVIDIA GPU drivers themselves, because gVisor passes through calls to be handled by the kernel module."* Here it lands on the **host kernel**, not on an intermediate VM. Isospin's inverted "GPU server" topology, whatever else it lacks, contains driver bugs inside a VM; this design does not.

Separately, KVM memory slots mapping GPU BAR pages into guest physical space give the guest **direct MMIO access to the GPU** in the steady state. That is the point — it is what buys native performance — but it means the guest can write GPU registers and command buffers without mediation. The isolation resting on that path is whatever the GPU's own contexts and the host driver's channel setup provide, which for a consumer card is not a multi-tenant boundary. **This design is appropriate for one trusted tenant per host; it is not a multi-tenant sandbox, and does not claim to be.**

---

## 7. Is it legitimate and safe?

### 7.1 Legitimacy — yes, well-established

**Nestri Labs** is a real open-source cloud-gaming project: 18 public repositories, a main project at `nestrilabs/nestri` ("Deploy and stream games/apps in the cloud"), a website at nestri.io, tagged releases and active issues. This is not an anonymous drive-by repository. Two named contributors with consistent history. The technical design coheres exactly with the organisation's stated product need, which is itself a strong authenticity signal — the code does what the project would actually require.

The repository is small by attention (2 stars, 0 forks) but that reflects obscurity, not illegitimacy.

### 7.2 Code safety — no malicious indicators

Swept across **all five branches**:

| Check | Result |
|---|---|
| `curl \| sh`, `wget \| sh`, `eval $(…)`, `base64 -d`, `/dev/tcp/`, `nc -e`, `chmod +s` | **One hit only:** the standard `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` rustup line in `DEV.md`. Documentation, and the canonical install command. Nothing else. |
| Outbound hosts referenced | All legitimate and all consistent with upstream libkrun/libkrunfw: `passt.top`, `podman.io`, `matrix.to`, `elixir.bootlin.com`, `docs.mesa3d.org`, `android.googlesource.com`, `developer.apple.com`, `sh.rustup.rs`. No pastebins, no IP literals beyond `127.0.0.1`, no unexplained endpoints. |
| Syscall-table hooking / `kallsyms` / `write_cr0` in the guest module | None. Standard `cdev`/`file_operations`/virtio registration. |
| Obfuscation, minification, encoded payloads | None. The code is well commented and readable throughout. |
| Telemetry / phone-home | None found. |
| Licensing | `feat/init` Apache-2.0; guest kernel module `SPDX-License-Identifier: GPL-2.0` (correct and required); libkrun/libkrunfw forks retain upstream GPL-2.0 / LGPL-2.1 files. Coherent. |
| Rust dependencies | Standard; `kvm-bindings`, `libc` and the usual libkrun tree. |

**Nothing in this repository behaves like malware or a supply-chain trap.**

### 7.3 The genuine caveats

These are provenance and maturity issues, not integrity findings:

- **The forks do not preserve upstream history.** `nv/libkrun` begins with a commit literally titled *"feat: Clone libkrun locally"* — libkrun and libkrunfw were copied in as bulk commits rather than forked with history. Consequence: **you cannot diff the vendored trees against upstream from within the repository.** If you intend to build this, diff `nv/libkrun` against `containers/libkrun` and `libkrunfw` against `containers/libkrunfw` yourself. That is the single most useful verification step available and I could not perform it from source reading alone.
- **Binary blobs I cannot verify by reading.** `edk2/KRUN_EFI.silent.fd`, `qboot/sev/bios.bin`, `qboot/tdx/bios.bin`, `initrd/initrd.gz`, `examples/snp-example-data-disk.img`. All are standard components of upstream libkrun/libkrunfw and their presence is expected — but combined with the missing upstream history, their byte-provenance is unestablished. Checksum them against upstream releases before trusting them.
- **A self-referential submodule.** `nv/libkrun:.gitmodules` declares `path = libkrunfw-nvgpu`, `url = ./`, `branch = libkrunfw` — the repository includes itself at another branch. Unusual but benign, and it keeps everything in one place. Note it if you clone `--recursive`.
- **The default branch misrepresents the project** (§2). Judge it from `nv/libkrun` and `libkrunfw`.
- **It is a young prototype.** Last commit 2026-04-16; the history is dense with `dbg:` commits. It reached `nvidia-smi` and was mid-fight with Vulkan and modeset.

### 7.4 Recommendation

**Safe to read, clone, and study — and it is the better of the two approach-B projects to learn from.** If you intend to *run* it: it needs a host NVIDIA driver, builds a custom kernel and an out-of-tree guest module, and runs a forked VMM. Do that on a machine you can reinstall. Verify the vendored libkrun/libkrunfw trees and blobs against upstream first. And treat it as single-trusted-tenant (§6.3) — the direct-MMIO fast path is not a multi-tenant boundary.

---

## 8. Comparison with `isospin-microvm`

Both are approach B. They are not at the same stage.

| | `isospin-microvm` | `virtio-nvgpu` |
|---|---|---|
| Transport | vsock sockets | **virtio virtqueue** |
| Topology | GPU VM + host bridge + worker VMs (3 tiers) | Host driver + libkrun VMM + guest (2 tiers) |
| VMM | Firecracker + Cloud Hypervisor | libkrun |
| **`mmap` / data plane** | **Not implemented** — "control path only" | **KVM memslot + `remap_pfn_range`, EPT-direct, no exits** |
| Nested pointer params | `// TODO: translate embedded handles` | V1→V2 rewrite table + guest-side intercepts |
| ABI versioning | Hand-written structs | **Generated per driver version** (`nvgpu_gen.py`) |
| Ioctl allowlist | **None** | Yes — ported from gVisor `nvproxy`, capability-gated |
| Isolation model | Virtual→real handle translation (real handles globally predictable) | Per-guest host fds; host driver enforces |
| Guest devices | `nvidiactl`, `nvidia0` | `nvidia0-247`, `nvidiactl`, `uvm`, `caps`, `modeset`, DRI |
| Driver-bug blast radius | Contained in the GPU VM | **Host kernel** |
| Reached | `nvidia-smi -L` milestone | **`nvidia-smi` working**, Vulkan in progress |
| Org / provenance | Unknown author, 0 stars | Nestri Labs, established project |
| Licence | MIT | Apache-2.0 + GPL-2.0 module |

`virtio-nvgpu` is ahead on essentially every technical axis that matters, and its `mmap` design is the difference between a control-plane demo and something that could plausibly run a game. Isospin's one architectural advantage is topological: by keeping the NVIDIA driver inside a VM, a driver compromise does not reach the host.

---

## 9. What this changes in the wider research

The earlier reports concluded that approach B existed only as vendor work — Microsoft's GPU-PV and NVIDIA's own vGPU — until `isospin-microvm` turned up. **This is now the second independent non-vendor implementation, and it is markedly more complete.** Two obscure projects (2 stars and 0 stars respectively), built in the same period, independently attacking the same problem.

That changes the reading of the null result. Approach B is not exotic or theoretical: it is being attempted, in the open, by small teams with concrete product needs — cloud gaming here, microVM cold-start there. What remains genuinely absent is **approach C**: nobody is emulating a synthetic NVIDIA GPU or impersonating GSP. Both of these projects deliberately cut *above* GSP, forwarding ioctls and letting the host driver own the firmware relationship entirely. That is not an oversight; it is the only tractable place to cut, and the fact that two independent teams chose the same boundary is the strongest evidence yet for why approach C has no instances.
