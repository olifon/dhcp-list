# Deep dive: `straylight-software/isospin-microvm`

How it works, how far it gets, and whether it is safe.

Compiled 2026-08-15. **Static source review only — nothing in this repository was built, installed, or executed.** Every claim below is cited to a file and, where it matters, quoted. Roughly 6,900 lines were read across the guest kernel module, the broker daemon, the Nix flake, and the host scripts.

---

## 1. What it is, in one paragraph

Isospin is an attempt to make GPU-backed microVMs start instantly. Instead of giving each VM a GPU, it keeps **one** long-lived VM that owns the physical GPU through VFIO and runs the real NVIDIA driver, and then lets many short-lived Firecracker VMs borrow it by **forwarding the NVIDIA Resource Manager ioctl surface over vsock**. The worker VMs load a small kernel module, `nvidia-shim.ko`, that creates fake `/dev/nvidiactl` and `/dev/nvidia0` character devices and proxies every ioctl written to them across the VM boundary to a broker daemon. In the taxonomy used in the rest of this research, that is **approach B — paravirtual** — and it is the first instance found in the wild that is neither Microsoft's WDDM GPU-PV nor NVIDIA's own vGPU.

---

## 2. Provenance and metadata

| | |
|---|---|
| Repository | `straylight-software/isospin-microvm` |
| Stars / forks | **0 / 0** |
| Commits | 52 |
| License | MIT — `Copyright (c) 2024-2026 Straylight Software` |
| Languages | Rust (broker), C (guest kernel module), Nix (build), shell (host scripts) |
| Kernel module licence tag | `MODULE_LICENSE("GPL")`, `MODULE_AUTHOR("Isospin Authors")` |
| Build system | Nix flake + Buck2; `nixpkgs`, `flake-parts`, `oxalica/rust-overlay` |
| Target hardware referenced | NVIDIA **RTX PRO 6000 Blackwell (128 GB)**, driver **580.95.05** |
| Self-described status | README says "Alpha"-grade in tone; no formal stability promise |

The hardware and driver version in the README are specific and current, which suggests the author has the machine in front of them rather than writing speculatively. There is no organisation page, no paper, no release, and no external discussion of this project that I could find.

---

## 3. The problem it is solving

From the README:

> Isospin eliminates the ~20 second GPU cold boot penalty by keeping a "GPU VM" with the real NVIDIA driver running, while lightweight worker VMs connect instantly via the gpu-broker.

This is a real and specific pain point. Initialising an NVIDIA driver against a passed-through GPU — enumerating the device, loading and booting GSP firmware, setting up the RM object hierarchy — takes on the order of twenty seconds. For a lambda-style workload where the VM itself boots in under a second, that dominates everything. Isospin's answer is to pay the cost once, in a VM that never shuts down, and let everyone else attach to the already-hot driver.

Note what this implies: the design's goal is **cold-start latency**, not isolation and not density. That framing matters for the security assessment in §8, because isolation is a consequence the design must then earn, rather than its founding purpose.

---

## 4. Architecture

Three tiers, reproduced from the README's diagram:

```
┌────────────────────────────────────────────────────────────────────────┐
│ GPU VM (Cloud Hypervisor + VFIO)                                       │
│   nvidia.ko (580.95.05) → NVIDIA RTX PRO 6000 Blackwell (128GB)        │
│   gpu-broker (real ioctl forwarding) on vsock:9999                     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Cloud Hypervisor vsock
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ HOST: vsock-bridge                                                       │
│   Bridges CH vsock ↔ Firecracker vsock                                   │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ Firecracker vsock
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Worker VM (Firecracker, boots in <1s)                                    │
│   nvidia-shim.ko → /dev/nvidiactl, /dev/nvidia0 (proxied to broker)      │
│   Applications use GPU instantly, no driver initialization               │
└──────────────────────────────────────────────────────────────────────────┘
```

The host bridge exists because Firecracker and Cloud Hypervisor implement vsock differently, so the two hypervisors cannot talk directly; a userspace process on the host splices the two.

An important structural point: **the physical GPU is never exposed to the worker VMs at all.** It is bound to `vfio-pci` on the host and handed whole to the GPU VM. Worker VMs see only character devices backed by a socket. Whatever else is true, the workers have no MMIO access and no DMA path to host memory — which is more than can be said for straight passthrough.

---

## 5. Component walk-through

### 5.1 `nvidia-shim.ko` — the guest module (`gpu-broker/kernel/nvidia-shim.c`, 1,260 lines)

Its own header states the design plainly:

> `nvidia-shim.ko - GPU broker shim for ioctl forwarding`
> `This module intercepts NVIDIA ioctls and forwards them to the GPU broker via vsock. It can be built in two modes:`
>
> **GUEST MODE** (default, `NV_SHIM_HOST=0`) — *"Runs in a VM without GPU access. Forwards ioctls to broker on host."*
> `nvidia-shim.ko ───vsock CID=2───► real nvidia.ko`
>
> **HOST MODE** (`NV_SHIM_HOST=1`) — *"Runs on host. Forwards ioctls to broker inside a VM that has the real GPU. This is the 'GPU server' model where the VM owns the GPU."*
> `nvidia-shim.ko ───vsock CID=3───► real nvidia.ko`

That bidirectionality is worth pausing on. The same module supports the conventional "host has the GPU, guest borrows it" arrangement *and* the inverted arrangement where a VM owns the GPU and the host borrows it back. The second is the mode Isospin actually uses, and it is the more interesting one: it means the host itself never loads the NVIDIA driver, so a driver bug is contained inside a VM.

The module registers character devices standing in for `/dev/nvidiactl`, `/dev/nvidia0` and `/dev/nvidia-uvm`, and forwards these escapes:

| Category | Escapes forwarded |
|---|---|
| RM core | `NV_ESC_RM_ALLOC` (0x2B), `RM_CONTROL` (0x2A), `RM_FREE` (0x29), `RM_ALLOC_MEMORY` (0x27), `RM_ALLOC_OBJECT` (0x28), `RM_DUP_OBJECT` (0x34), `RM_SHARE` (0x35), `RM_MAP_MEMORY` (0x4E), `RM_UNMAP_MEMORY` (0x4F) |
| Frontend | `CARD_INFO` (200), `REGISTER_FD` (201), `ALLOC_OS_EVENT` (206), `FREE_OS_EVENT` (207), `STATUS_CODE` (209), `CHECK_VERSION_STR` (210), `ATTACH_GPUS_TO_FD` (212), `SYS_PARAMS` (214), `GET_PCI_INFO` (215), `EXPORT_DEVICE_FD` (218) |

Transport is a kernel socket: `sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &broker->sock)`, with module parameters `broker_cid` (default 2 = host), `broker_port` (default 9999), and `broker_socket` for a Unix-socket testing path. There is a reconnection thread and a wait queue, so a broker restart does not permanently wedge the guest.

### 5.2 The wire protocol

Deliberately plain, fixed-size headers, little-endian, length-prefixed payloads:

```c
#define WIRE_MAGIC 0x4E56424B  /* "NVBK" */

struct wire_request {                struct wire_response {
    u32 magic;                           u32 magic;
    u32 version;                         u32 version;
    u64 client_id;                       u64 client_id;
    u64 seq;                             u64 seq;
    u32 op_type;                         u8  success;
    u32 payload_len;                     u8  _pad[3];
    /* payload follows */                u32 result_len;
} __attribute__((packed));               /* result follows */
                                     } __attribute__((packed));
```

Nineteen opcodes (`OP_REGISTER_CLIENT` 0 … `OP_EXPORT_DEVICE_FD` 18) map onto the escapes above. Note that the protocol is *semantic*, not a raw ioctl tunnel: the shim decodes each escape into a typed operation rather than shipping opaque ioctl buffers. That is a meaningfully better design than a blind pipe, because it gives the broker something to reason about — see §8.

### 5.3 The broker (`gpu-broker/`, Rust, ~5,600 lines)

Four layers, and it is worth keeping them distinct because they do not all carry equal weight:

**`server.rs` (628 lines)** — connection management. Unix socket listener, io_uring event loop, per-client shared-memory rings and eventfds. One detail matters for security: at line 369 the server does `req.client = client_id;`, **overwriting whatever client ID arrived on the wire with the one bound to the authenticated connection.** A client therefore cannot impersonate another client by lying in the header. That is the correct thing to do and it is done.

**`proxy.rs` (961 lines)** — the real translation layer. Its doc comment states the pipeline: *"1. Validate → 2. Translate (HandleTable) → 3. Call driver → 4. Record result → 5. Respond."* Every operation translates its top-level handles per client, e.g. in `op_alloc`:

```rust
let real_root = if h_root == 0 { 0 }
    else { self.handles.translate(client, VirtualHandle(h_root))?.0 };
```

Quotas are enforced from `ProxyConfig`: `handle_quota: 10_000` per client, `max_clients: 1_000`, `strict_validation: true` by default.

**`handle_table.rs`** — per-client handle namespaces. Its doc comment states the intent exactly:

> Each VM client gets its own handle namespace. … When the client references a handle, we translate it. **This prevents clients from accessing each other's GPU objects.**

`translate()` is strictly scoped: it looks up the client first, then the handle within that client's map, and errors with `HandleNotFound` otherwise. There is no global handle namespace to fall through to.

**`driver.rs` (1,304 lines)** — the bottom edge. Opens `/dev/nvidiactl` and `/dev/nvidia0`, and issues real ioctls through a single `unsafe fn raw_ioctl<T>(&self, cmd: IoctlRequest, params: &mut T)`. It has both a real path and a `MockDriver`, so the whole stack can be exercised without hardware.

### 5.4 The pure functional core (`broker.rs`, 1,236 lines)

Separately from the live path there is a state machine written as `(State, Input) → (State', Output)`:

> No callbacks. No threads mutating state. No hidden control flow. Just data in, data out.
> — Deterministic replay from any input sequence · time-travel debugging · exhaustive property testing · *"The simulation IS the test"*

`proptest` is a dev-dependency and there are equivalence assertions across replayed states. This is a genuinely good engineering decision for a protocol proxy, where the interesting bugs are state-machine bugs. It is, however, a **model** — the serving path runs through `proxy.rs`, and the two implement overlapping logic separately. Divergence between model and implementation is an obvious future hazard.

---

## 6. How far it actually gets

This is the part a reader most needs, and it is verifiable in source rather than a matter of judgement. **The control plane is implemented; the data plane is not.**

| Capability | Status | Evidence |
|---|---|---|
| RM object alloc / free / control | Implemented, handle-translated | `proxy.rs` `op_alloc`, `op_free`, `op_control` |
| Handle isolation per client | Implemented for top-level handles | `handle_table.rs::translate` |
| `mmap` of GPU memory into the guest | **Not implemented** | `nvidia_shim_mmap()` ends in `pr_warn("nv-shim: mmap not implemented (control path only)\n")` |
| UVM (unified memory) | **Stubbed** | *"UVM ioctls are stubbed - we just return success."* |
| `RM_CONTROL` output parameters | **Not implemented** | *"Note: out_params copy not yet implemented. The params format is complex (pointer at offset 24 in struct, but data may be inline for small params). For M1 (nvidia-smi -L), we don't need out_params."* |
| Embedded handles inside control params | **Not translated** | `proxy.rs:375` — `// TODO: Parse params and translate any embedded handles` |

The stated milestone is `nvidia-smi -L` — enumerate the GPU. That is a long way from running CUDA. Without `mmap` there is no way to get a command buffer, a doorbell, or device memory into the guest process, and without UVM there is no unified addressing. **CUDA cannot run through Isospin today.**

That wall is not incidental, and it is where the project's difficulty really lives. gVisor's `nvproxy` design document identifies the same thing as the hard part of proxying NVIDIA ioctls: `NV_ESC_RM_MAP_MEMORY` merely *prepares* a mapping, which a later `mmap` on a **different** file descriptor consumes — and, as that document notes, those two operations "can be invoked from different processes." Reproducing that across a VM boundary means faulting guest pages against host GPU BAR memory, which is a different and much harder problem than relaying an ioctl. Isospin has done the tractable half well and has not started the hard half.

---

## 7. Where it sits in the taxonomy

| | |
|---|---|
| **Class** | **Paravirtual (approach B)** — a guest-side driver forwarding the RM ioctl surface over a VM transport; the guest never owns the device |
| Not approach C | It does not fabricate a synthetic GPU or impersonate GSP. It forwards *above* the GSP layer entirely, which is precisely why it can work at all — GSP is the GPU VM's problem, not Isospin's |
| Not API remoting | The cut is at the kernel driver ioctl boundary, not at CUDA. Unmodified CUDA userspace is the intent |
| Not container-level | The boundary is a VM, unlike gVisor `nvproxy` |
| Closest relatives | gVisor `nvproxy` (same ioctl-forwarding idea, container boundary instead of VM); Microsoft GPU-PV (same idea, WDDM instead of RM, VM bus instead of vsock) |

The distinguishing feature versus every other approach-B implementation found in this research: **it is the only one not authored by the platform vendor.** Microsoft wrote GPU-PV for Windows; NVIDIA wrote vGPU. Isospin is an outsider doing it against an undocumented, unstable ioctl surface.

---

## 8. Security analysis

Two questions get conflated under "is it safe", so I will separate them: is the *code* safe to handle (§9), and is the *design* safe to deploy (this section). All of the following are observations about incomplete alpha software with the author's own TODOs still in it — not vulnerability claims against anything deployed.

### 8.1 What the design gets right

- **The GPU is never exposed to workers.** No MMIO, no BARs, no DMA path from a worker VM to host memory. Compared with straight passthrough this removes the single largest concern — a guest driver with DMA to host RAM.
- **The host does not run the NVIDIA driver.** In the inverted "GPU server" arrangement the driver lives inside a VM. An NVIDIA driver vulnerability compromises that VM, not the host kernel.
- **Client identity is server-assigned.** `server.rs:369` overwrites the wire-supplied `client` with the connection's own ID. Spoofing another tenant's identity in the header does not work.
- **Per-client handle namespaces with quotas.** `translate()` is scoped to the client; `handle_quota: 10_000` and `max_clients: 1_000` bound resource exhaustion.
- **Semantic protocol, not a raw tunnel.** Because the shim decodes escapes into typed operations, the broker *can* validate. A design that tunnelled opaque ioctl buffers would foreclose that entirely.
- **`unsafe` is concentrated.** Essentially all of it sits in `driver.rs`'s single `raw_ioctl` and the fd handling around it, rather than being sprinkled through the codebase.

### 8.2 Where isolation is currently incomplete

**Embedded handles in control params are not translated.** This is the significant one, and the author has already flagged it:

```rust
// proxy.rs:375
// TODO: Parse params and translate any embedded handles
```

`op_control` translates `h_client` and `h_object`, then passes the params buffer through byte-for-byte: `let mut params_buf = params.to_vec();` … `self.driver.control(real_client, real_object, cmd, &mut params_buf)?`. The `Driver` trait signature takes `params: &mut [u8]` — an opaque blob. A large fraction of the `NV2080_CTRL_*` / `NV0080_CTRL_*` surface carries handles *inside* those params. Those reach the real driver untranslated.

**Real handles are globally predictable.** The compounding factor:

```rust
fn generate_real_handle(&self) -> NvHandle {
    // Use a simple counter based on stats
    // Real implementation would track this properly
    (0x8000_0000 + self.stats.handles_allocated as u32 + 1)
}
```

`stats.handles_allocated` is a **single counter shared across all clients**, so real handles are `0x80000001`, `0x80000002`, … in global allocation order. Combined with the untranslated params, a tenant that can guess or enumerate another tenant's real handle values can name them inside a control params buffer. The virtual→real indirection that `handle_table.rs` advertises as preventing cross-client access does not cover that path. The author's own comment concedes the placeholder.

**No command allowlist.** I grepped the entire tree for `allowlist`, `whitelist`, `allowed_cmd`, `sanitiz`, and found nothing. Every RM control command a guest can name is forwarded. gVisor takes the opposite approach — an explicit per-device-file ioctl allowlist, with unknown commands refused — and even so its documentation warns:

> gVisor is much less effective at mitigating vulnerabilities within the NVIDIA GPU drivers themselves, *because* gVisor passes through calls to be handled by the kernel module.

That caveat applies to Isospin with more force, since there is no allowlist at all.

**The broker holds the keys.** It has open file descriptors on the real `/dev/nvidiactl` and `/dev/nvidia0` and serves untrusted input from every worker VM. It is the single point whose compromise yields full GPU control — within the GPU VM, which is the mitigating factor.

**A kernel module in every worker.** `nvidia-shim.ko` is 1,260 lines of C parsing attacker-adjacent structures in guest kernel context. Bugs there are guest-kernel bugs. That is a smaller blast radius than the host, but it is not nothing, and the module is young.

### 8.3 Fair framing

None of §8.2 is a criticism of the project on its own terms. It is a 52-commit alpha whose stated milestone is `nvidia-smi -L`, and the gaps are marked `TODO` in the source by the author rather than hidden. The right reading is: **the isolation architecture is sketched correctly and implemented partially.** The handle table, the server-side client binding, and the semantic protocol are the right bones. Params translation and an allowlist are the obvious next work, and both are tractable within the existing structure.

---

## 9. Is the repository safe?

### 9.1 Safe to read, clone, and inspect — yes

I swept everything fetched for the usual indicators and found none:

| Check | Result |
|---|---|
| Outbound URLs in source/scripts | **None** |
| `curl … \| sh`, `wget … \| sh`, `eval`, `base64 -d`, `/dev/tcp`, `nc -e` | **None** |
| `chmod +s` / setuid tricks | **None** |
| Syscall-table hooking, `kallsyms` lookups, `kprobe`, `write_cr0`, `set_memory_rw` | **None** — the module uses ordinary `misc`/`cdev` registration and `file_operations` |
| Obfuscated or minified code | None; the code is unusually well commented |
| Telemetry / phone-home | None found |
| Licence | MIT, coherent, with a real copyright line |
| Nix inputs | `NixOS/nixpkgs`, `hercules-ci/flake-parts`, `oxalica/rust-overlay` — all standard and well-known |
| Rust dependencies | Mainstream and unremarkable: `io-uring`, `memmap2`, `thiserror`, `anyhow`, `tracing`, `serde`, `zerocopy`, `nix`, `libc`, `clap`, `proptest`, `tempfile` |

Nothing in this repository behaves like malware or a supply-chain trap. It reads as sincere systems research.

**Standing caveat:** this assessment covers the ~6,900 lines I actually fetched and read — the broker sources, the kernel module, the flake, and the VFIO scripts. I did not review the vendored `nvidia-open/` tree (that is NVIDIA's own published source), the vendored Rust crates under `3rdparty/`, the Buck2 toolchain files, or the bundled `firecracker/` and `cloud-hypervisor/` trees. "No indicators found" is not the same as "audited clean", and a zero-star repository from an unknown author carries provenance risk that no amount of source reading removes.

### 9.2 Safe to run — not on anything you care about

Independent of code quality, running it is genuinely invasive:

- **Requires root and rebinds your GPU.** `scripts/vfio-bind.sh` runs `modprobe vfio-pci`, unbinds the device from its current driver, writes `driver_override`, and binds it to `vfio-pci`. That yanks the GPU away from the host — expect your display to go dark if it is your only card. The script is careful (`set -euo pipefail`, root check, device-existence check) and reversible via `vfio-unbind.sh`, but it is a real system-level change.
- **Most workflows are `sudo nix run`.** The demo, the VMs and the bridge all run as root.
- **It loads an out-of-tree kernel module.** In the worker VM, but still.
- **The docs concede platform sharpness.** The VFIO book notes that on hosts with ACS-override patches — a common homelab hack that weakens IOMMU group isolation — *"we implemented a warning instead of error"*. Downgrading an isolation check to a warning is defensible for a research tool and disqualifying for production.
- **It cannot run your workload anyway.** Per §6, no `mmap` means no CUDA.

**Recommendation.** Treat it as a reference design and a source to read, which is where its value is right now. If you want to exercise it, use a dedicated machine with a spare GPU, and do not put untrusted tenants behind it — the params-translation gap in §8.2 means cross-tenant isolation is not yet what the architecture intends.

---

## 10. What finishing it would require

In rough order of difficulty:

1. **`mmap` forwarding.** The hard one. Faulting guest pages against host GPU BAR/system memory across a VM boundary, honouring the `RM_MAP_MEMORY`-then-`mmap`-on-another-fd split. Everything else is comparatively bookkeeping.
2. **Real UVM support**, rather than stubs returning success.
3. **Params-aware translation** — a per-command schema describing which offsets in each `NV*_CTRL_*` params struct hold handles, so they can be translated and validated. This is also what an allowlist would hang off. It is a large, tedious, version-coupled table; gVisor maintains the equivalent and it is a standing maintenance cost.
4. **Non-predictable real handles**, scoped per client.
5. **Driver-version pinning.** NVIDIA guarantees no ABI stability across releases, so the shim, the broker's struct layouts, and the GPU VM's driver must be locked together and revalidated on every bump.
6. **Reconciling the model and the implementation**, so `broker.rs`'s tested state machine and `proxy.rs`'s live path cannot drift.

---

## 11. Why this project matters to the wider research

Three reasons worth recording.

It is **the first non-vendor approach-B implementation** located anywhere in this research. That the only two prior examples were written by Microsoft and NVIDIA suggested the design needed vendor-scale resources; Isospin is evidence that an outsider will at least attempt it.

It is **a concrete answer to question 3h** of the first report — whether anyone runs GPUs inside microVMs for lambda-style workloads. Someone is building exactly that, on Firecracker plus Cloud Hypervisor, though it is not yet multi-tenant in the simultaneous-sharing sense.

And it is **a calibration point for search methodology.** A 0-star, 0-fork repository changed a conclusion I had drawn from repository-level and web search, and later from Sourcegraph symbol search — because Sourcegraph does not index it. It surfaced only through GitHub's own code search, and even then only because it vendors `nvidia-open/`, so NVIDIA's GSP symbols appeared in a tree that contains no GSP code of its own. The lesson generalises: for long-tail prior art, the index matters more than the query.
