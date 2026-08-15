# Prior art and real-world deployment of NVIDIA GPU virtualization

Research report — compiled 2026-08-15. Read-only research; nothing fetched was executed, built, or installed.

**Evidence tags used throughout:** `[MEASURED]` primary source read directly (vendor doc, source, captured output) · `[REPORTED]` secondary source or forum claim · `[INFERRED]` my reasoning, stated explicitly · `[UNKNOWN]` could not determine.

---

## 1. Executive answer to Part 1

**Paravirtual (approach B) NVIDIA GPU virtualization exists, is well documented, and ships in production — but never with a stock NVIDIA guest kernel driver.** Three independent implementations are real: NVIDIA's own vGPU (whose guest driver explicitly uses "a paravirtualized interface to the NVIDIA Virtual GPU Manager" for management operations), Microsoft's WDDM GPU paravirtualization (GPU-PV), which deletes the vendor kernel-mode driver from the guest entirely and marshals every `Dxgkrnl` thunk to the host over VM bus — and which works on consumer GeForce cards — and the academic GPUvm/G-KVM line of work, which built both para- and full-virtualization of NVIDIA GPUs at the Xen and KVM hypervisor level using the open Nouveau/Gdev stack.

**Emulated (approach C) — a VMM that fabricates a synthetic NVIDIA GPU *and* impersonates GSP firmware so a completely unmodified stock NVIDIA guest driver boots — I found no instance of, anywhere, in any language.** The closest public attempt is `bird/vgpu-unlock-blackwell`, which got a full CPU-side vGPU pipeline working on an RTX 5090 and successfully delivered a BOOTLOAD RPC into real GSP firmware before hitting hardware-fused-off VF PRIV registers; that is host-side driver patching, not device emulation, and it is blocked in silicon. **This is a genuine null result and I am reporting it as one.**

The reason C is unattempted rather than merely unfinished is visible in NVIDIA's own source tree: the guest→host escape path (`_rpcSendMessage_VGPU()`) is closed-source-only and, per NVIDIA's maintainer, was never productized on the GSP driver model — so there is no public protocol specification to emulate against, and the GSP-based path (`_rpcSendMessage_VGPUGSP()`) terminates in signed firmware running on an on-die RISC-V core.

---

## 2. Prior-art table (NVIDIA)

| Project / work | Approach class | Status / last activity | How far it got | URL |
|---|---|---|---|---|
| **Microsoft WDDM GPU-PV** (Hyper-V GPU-P, Windows Sandbox, WSL2 `/dev/dxg`, WDAG) | **PARAVIRTUAL (B)** — true hit | Shipping since Windows 10 1803 (WDDM 2.4); doc revised 2025-02-06 | Complete and in production on hundreds of millions of machines. Guest has *no* vendor KMD at all; guest `Dxgkrnl` marshals thunks to the host over VM bus. Works on consumer GeForce. | [learn.microsoft.com/…/gpu-paravirtualization](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/gpu-paravirtualization) |
| **Linux `dxgkrnl`** (WSL2 guest driver; clean-room GPU-PV protocol implementation) | **PARAVIRTUAL (B)** — true hit | Active; out-of-tree, upstreaming attempts ongoing (LWN coverage 2025/2026) | Full CUDA on NVIDIA GPUs inside a Linux guest with no NVIDIA KMD in the guest. | [github.com/microsoft/WSL2-Linux-Kernel](https://github.com/microsoft/WSL2-Linux-Kernel) |
| **NVIDIA vGPU / GRID** (the reference product) | **PARAVIRTUAL (B)** (mediated pass-through: fast paths direct, management paravirtualized) | Shipping, current (vGPU 20.x) | Production. Datacenter SKUs + licence only. | [docs.nvidia.com/vgpu](https://docs.nvidia.com/vgpu/) |
| **GPUvm** — Suzuki, Kato, Yamada, Kono, USENIX ATC '14 | **EMULATED (C-like "full virtualization") + PARAVIRTUAL (B)** | Dead (2014) | Both modes implemented on Xen for NVIDIA Fermi. Built on the open Nouveau/Gdev stack, **not** the proprietary driver — so it is not C by the strict "stock unmodified NVIDIA driver" definition. Heavy overhead in full-virt mode. | [usenix.org/…/presentation/suzuki](https://www.usenix.org/conference/atc14/technical-sessions/presentation/suzuki) |
| **G-KVM: A Full GPU Virtualization on KVM** (IEEE, Dec 2016) | Same class as GPUvm | Dead (2016) | Ported GPUvm's design to KVM with an aggregator + QEMU device model; ~82% of native on compute-intensive work. | [ieeexplore.ieee.org/document/7876385](https://ieeexplore.ieee.org/document/7876385) |
| **`bird/vgpu-unlock-blackwell`** | **Driver-patching** (aiming at B) | 2 commits, ~16 stars, hardware-blocked | 19 binary patches on driver 595.58.03; registered 60 vGPU types; created mdevs visible in guests; delivered a complete BOOTLOAD RPC that GSP processed for ~4 s — then GSP crashed on VF PRIV registers at `0x111xxx` that are **fused off** on consumer silicon. The furthest anyone has publicly pushed toward vGPU on a consumer card. | [github.com/bird/vgpu-unlock-blackwell](https://github.com/bird/vgpu-unlock-blackwell) |
| **`DualCoder/vgpu_unlock`** | Driver-patching | Originating project (2021), largely dormant | Spoofs PCI device ID so the vGPU manager accepts a consumer card. Pascal/Turing. | [github.com/DualCoder/vgpu_unlock](https://github.com/DualCoder/vgpu_unlock) |
| **`mbilker/vgpu_unlock-rs`** | Driver-patching | Rust `LD_PRELOAD` reimplementation, maintained | Same trick, more robust; the de-facto community standard. | [github.com/mbilker/vgpu_unlock-rs](https://github.com/mbilker/vgpu_unlock-rs) |
| **`VGPU-Community-Drivers/vGPU-Unlock-patcher`** | Driver-patching | Active through 535.x/550.x branches | Patches the vGPU host package itself rather than hooking at runtime. | [github.com/VGPU-Community-Drivers/vGPU-Unlock-patcher](https://github.com/VGPU-Community-Drivers/vGPU-Unlock-patcher) |
| **`KrutavShah/vGPU_Unlock-Expanded`**, **`danielfullmer/nixos-nvidia-vgpu`**, **`benjamindoron/vGPU-Unlock-Patcher`**, **`lolalk/ubuntu_vgpu_unlock`**, **`pdbear/syno_nvidia_gpu_driver`** | Driver-patching (packaging/derivative) | Various, mostly dormant | Distribution-specific wrappers around the above. | (GitHub) |
| **Arc-Compute `Mdev-GPU`** + **`LibVF.IO`** (GVM Project) | Driver-patching / mdev configuration | Issues open back to early 2024; no visible recent activity | Registers arbitrary mdev types against vendor drivers that ship none or only fixed ones; vendor-neutral YAML front end. Does not implement a device model. | [github.com/Arc-Compute/Mdev-GPU](https://github.com/Arc-Compute/Mdev-GPU), [open-iov.org](https://open-iov.org/index.php/Mdev-GPU) |
| **gVisor `nvproxy`** | **Container-level ioctl proxy** (not a VM boundary) | Active, production | Proxies `/dev/nvidiactl`, `/dev/nvidia#`, `/dev/nvidia-uvm` ioctls from sandbox to host with FD and pointer translation; explicitly does *not* emulate KMD logic. Shape-wise the nearest thing to B, but there is no VM and no guest driver. | [github.com/google/gvisor/…/nvidia_driver_proxy.md](https://github.com/google/gvisor/blob/master/g3doc/proposals/nvidia_driver_proxy.md) |
| **`coldfunction/qCUDA`** | API remoting (over a virtio transport) | Dormant | "GPGPU Virtualization at a New API Remoting Method with Para-virtualization" — paravirtual *transport*, but the cut is at the CUDA API, not the driver. | [github.com/coldfunction/qCUDA](https://github.com/coldfunction/qCUDA) |
| **rCUDA, VMware Bitfusion, Juice Labs, Thunder Compute, `kevmo314/scuda`, RWTH `cricket`, GVirtuS, vCUDA, DS-CUDA, AVA (ASPLOS'20)** | API remoting | Mixed (Bitfusion EOL; SCUDA/cricket active) | All intercept above the driver. **Not B or C.** | [github.com/RWTH-ACS/cricket](https://github.com/RWTH-ACS/cricket) |
| **HAMi (CNCF), `tkestack/vcuda-controller`, Alibaba cGPU, Tencent qGPU** | Container-level sharing | Active | Memory/compute quota enforcement for containers on one host GPU. Not a VM boundary. | [github.com/Project-HAMi/HAMi](https://github.com/Project-HAMi/HAMi) |
| **Liang Yan (SUSE), "A Journey to Support vGPU in Firecracker", KVM Forum 2020** | Passthrough/mdev tooling | Dead (2020 PoC) | Backported VFIO bind + ioctl from rust-vmm/Cloud Hypervisor into Firecracker. Never merged. | [kvmforum2020.sched.com/…](https://kvmforum2020.sched.com/event/eE2n/a-journey-to-support-vgpu-in-firecracker-liang-yan-suse) |
| **NVIDIA patent US10310879B2, "Paravirtualized virtual GPU"** | Patent (approach B) | Filed 2011-10-10, granted 2019; assignee NVIDIA Corp | Claims a privileged VM allocating disjoint GPU channel sets to guest drivers, with a GPU emulation module servicing config-register access and a proxy/master resource manager pair. Effectively the vGPU blueprint. | [patents.google.com/patent/US10310879B2](https://patents.google.com/patent/US10310879B2/en) |
| **virtio-gpu DRM native context for NVIDIA** | Would be B | **Does not exist.** Requested on NVIDIA's forum 2025-01-16 by user `luanv.oliveira`; no NVIDIA reply in the thread. | Freedreno, amdgpu upstreamed; Intel and Asahi in flight; **no NVIDIA driver**. | [forums.developer.nvidia.com/t/virtio-native-context-support/320346](https://forums.developer.nvidia.com/t/virtio-native-context-support/320346) |
| **Emulated NVIDIA GPU + GSP impersonation (approach C)** | — | **NOT FOUND** | No project, paper, patent, thesis, blog series or abandoned repo located in English, Chinese, Japanese or Russian. | — |

### Key primary quotes for Part 1

**Microsoft GPU-PV — the guest has no vendor kernel driver** `[MEASURED]`:

> "There's no KMD in the guest, only UMD. The Virtual Render Device (VRD) KMD replaces the KMD. VRD's purpose is to facilitate the loading of *Dxgkrnl*."
> "There's no video memory manager (*VidMm*) or scheduler (*VidSch*) in the guest."
> "*Dxgkrnl* in a VM gets thunk calls and marshalls them to the host partition via VM bus channels."
> "The current paravirtualization implementation uses the VM bus to communicate between the guest and the host. The maximum message size is 128KB."
> — [GPU paravirtualization, Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/gpu-paravirtualization)

**NVIDIA vGPU is itself paravirtual** `[MEASURED]`:

> "An NVIDIA driver loaded in the guest VM provides direct access to the GPU for performance-critical fast paths, and a paravirtualized interface to the NVIDIA Virtual GPU Manager is used for non-performant management operations."
> — [NVIDIA Virtual GPU Software User Guide](https://archive.docs.nvidia.com/vgpu/13.0/grid-vgpu-user-guide/index.html)

**NVIDIA's own maintainer on the three RPC paths** — `mtijanic` (NVIDIA), 2024-11-05 `[MEASURED]`:

> "`_kgspRpcSendMessage()` Host -> GSP · `_rpcSendMessage_VGPUGSP()` Guest -> GSP · `_rpcSendMessage_VGPU()` Guest -> Host (legacy path, closed source only)"
> "We don't support the legacy path on the GSP driver model. Theoretically it would be possible to do Guest->Host, and then forward Host->GSP to support it, but AFAIK we never productized that."
> — [open-gpu-kernel-modules discussion #312](https://github.com/NVIDIA/open-gpu-kernel-modules/discussions/312)

This is the single most important fact for anyone contemplating B or C: the paravirtual guest→host escape *exists in NVIDIA's driver today*, it is closed source, and NVIDIA itself describes forwarding Guest→Host→GSP as theoretically possible but never built.

**Why consumer silicon blocks the vGPU path** — `bird/vgpu-unlock-blackwell` README `[MEASURED via repo README]`:

> "GRID and consumer drivers share the same `nv-kernel.o_binary` and `gsp_ga10x.bin` (verified MD5)"

…yet GSP faults on VF PRIV registers that are "hardware fused off on consumer GPUs", and those cannot be intercepted in software because GSP is a separate RISC-V core with its own memory access. `[REPORTED — single-author repo, not independently reproduced]`

**gVisor nvproxy design** `[MEASURED]`:

> "ioctls are passed through with minimal intervention; nvproxy does not emulate NVIDIA kernel-mode driver (KMD) logic."
> — [nvidia_driver_proxy.md](https://github.com/google/gvisor/blob/master/g3doc/proposals/nvidia_driver_proxy.md)

---

## 3. AMD and Intel equivalents

| Project | Vendor | Approach class | Status / last activity | How far it got / what it actually does | URL |
|---|---|---|---|---|---|
| **AMD GIM (GPU-IOV Module)** | AMD | SR-IOV host mediator (hardware partitioning, *not* B or C) | Open-sourced April 2025 under GPLv2; releases continuing | VF configuration and enablement, world-switch scheduling, hang detection/FLR, PF↔VF handshake. Tested on **MI300X** + Ubuntu 22.04 + ROCm 6.4. Not upstream in mainline Linux; no announced upstreaming plan. | [github.com/amd/MxGPU-Virtualization](https://github.com/amd/MxGPU-Virtualization) |
| **AMD MxGPU** (S7150, V-series, Radeon PRO V710) | AMD | SR-IOV, hardware | Shipping | Hardware VFs; each guest runs the stock `amdgpu`/Radeon driver against a VF. Deployed in Azure NVv4 (MI25) and listed by Microsoft as a supported Hyper-V GPU-P device (V710). | [learn.microsoft.com/…/gpu-partitioning](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/gpu-partitioning) |
| **SR-IOV on consumer Radeon** | AMD | — | **Not available.** Phoronix (Apr 2025) reports Radeon is "in the roadmap"; nothing shipped. No credible community VBIOS/firmware unlock found. | `[UNKNOWN]` whether any serious community attempt exists — I found none. | [phoronix.com/news/AMD-GIM-Open-Source](https://www.phoronix.com/news/AMD-GIM-Open-Source) |
| **virtio-gpu DRM native context — amdgpu** | AMD / Collabora | **PARAVIRTUAL (B)** — shipped | Mesa 25.0 (2025); needs Linux ≥ 6.13 for KVM fixes; QEMU side at v14 (Oct 2025), virglrenderer ≥ 1.2.0 | Guest runs real `radeonsi`/`radv` UMDs; virtio forwards the **amdgpu kernel UAPI** to the host driver. ~99% of host speed on Unigine Heaven/Superposition. This is the AMD analogue of what an NVIDIA approach-B would look like. | [phoronix.com/news/AMDGPU-VirtIO-Native-Mesa-25.0](https://www.phoronix.com/news/AMDGPU-VirtIO-Native-Mesa-25.0), [patchew QEMU v14](https://patchew.org/QEMU/20251020233949.506088-1-dmitry.osipenko@collabora.com/) |
| **virtio-gpu native context — freedreno / Intel / Asahi** | Qualcomm / Intel / Apple | PARAVIRTUAL (B) | freedreno upstreamed; **Intel i915/Iris/Crocus/ANV landed in Mesa 26.1** (May 2026); Asahi partially merged | Same mechanism, different kernel UAPI. | [Mesa 26.1 release coverage](https://9to5linux.com/mesa-26-1-open-source-graphics-stack-officially-released-heres-whats-new) |
| **Intel GVT-g / KVMGT** | Intel | **Mediated pass-through** — closest real-world thing to C: guest runs the *stock* `i915` driver, hypervisor traps and emulates privileged operations, shadows page tables/GTT | **Deprecated. `gvt-linux` repo archived October 2024**; Intel ceased maintenance, bug fixes and releases. Broadwell (Gen8) → Comet Lake (Gen10) only. | Shipped and widely used for years on Intel iGPUs. Its existence is the proof that the "stock guest driver against a mediated device model" design is achievable — on documented hardware. | [Intel GVT-g, ArchWiki](https://wiki.archlinux.org/title/Intel_GVT-g) |
| **Intel SR-IOV (Xe / i915)** | Intel | SR-IOV, hardware | Battlemage SR-IOV enablement upstreamed in **Linux 6.17**, more in **6.18**; Flex 170 supported | **Consumer Arc B580 excluded — VFs are not enabled.** Phoronix: SR-IOV "will only be supported on the Arc Pro products and not the consumer Arc B-Series graphics cards." | [phoronix.com/news/Intel-SR-IOV-Only-For-Arc-Pro](https://www.phoronix.com/news/Intel-SR-IOV-Only-For-Arc-Pro) |
| **Community SR-IOV on consumer Arc** | Intel | — | Intel Community response: cannot comment on unannounced plans for Arc A-Series; Flex Series "does offer this type of technology." | Nothing working found. | [community.intel.com](https://community.intel.com/t5/Intel-Arc-Discrete-Graphics/Intel-ARC-A770-SR-IOV-under-Linux-not-available/td-p/1474348) |

**Reading of Part 2:** the industry answer to "share a GPU across VMs" converged on **hardware SR-IOV** (AMD, Intel, and NVIDIA's Ampere+ vGPU) plus **paravirtual UAPI forwarding** (virtio-gpu native context) — and *away* from the trap-and-emulate device-model approach that GVT-g represented. GVT-g's deprecation is the single strongest signal about approach C's viability: the one vendor who built it, on hardware they fully documented, killed it.

Note on the virtio-gpu native context security model `[INFERRED]`: it is a real VM boundary in the sense that the guest never touches the device and never has DMA to host memory, but the attack surface it exposes to the guest is the host kernel driver's full ioctl UAPI — structurally the same exposure gVisor's nvproxy documentation warns about. It buys migration/isolation properties that passthrough cannot, at the cost of a large host-kernel attack surface.

---

## 4. Provider table

| Provider | Instance family | vGPU / passthrough / container | Which fingerprint proved it | Evidence |
|---|---|---|---|---|
| **Azure** | `NVadsA10_v5` (NV6ads→NV72ads) | **vGPU** `[MEASURED]` | (a) fractional sizes 1/6, 1/3, 1/2, 1, 2 of an A10; (b) **"Live Migration: Supported"** in the feature table — impossible under passthrough; (c) hibernation supported; (d) GRID licence included, GRID 17.x+ required | [nvadsa10v5-series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/nvadsa10v5-series), [hibernate-resume](https://learn.microsoft.com/en-us/azure/virtual-machines/hibernate-resume) |
| **Azure** | `NVv4` (AMD MI25) | **AMD SR-IOV (MxGPU)** `[MEASURED]` | Fractional 1/8→1 GPU; hibernation supported; Live Migration *Not* Supported. Retires 2026-09-30. | [nvv4-series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/nvv4-series) |
| **Azure** | `NCads_H100_v5`, `NCv3`, ND-series | **Passthrough** `[MEASURED]` | **"Live Migration: Not Supported"**, "Memory Preserving Updates: Not Supported", whole-GPU accelerator counts, absent from the hibernation list | [ncadsh100v5-series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/ncadsh100v5-series) |
| **AWS** | p2/p3/p4/p5, g3/g4dn/g5/g6/g6e | **Passthrough** `[MEASURED, strong]` | **Zero GPU families appear in the EC2 hibernation-supported instance-family list** (only General purpose / Compute / Memory / Storage optimized are listed). Reinforced by AWS telling users to set `NVreg_EnableGpuFirmware=0` to disable **GSP** on G4dn/G5/G5g — a guest cannot control host GSP on a mediated vGPU. | [hibernating-prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html), [nvidia-GRID-driver](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvidia-GRID-driver.html) |
| **AWS** | **`g6f` / `gr6f`** (L4, 1/8, 1/4, 1/2 GPU) | **Almost certainly vGPU** `[INFERRED]` | AWS: "our first GPU instances provisioned with GPU partitioning", 1/8 GPU = 3 GB framebuffer, pre-partitioned by AWS, explicitly "unlike time-slicing or MIG"; GRID 18.4–19.5 required. L4 has no MIG, so a 3 GB fixed-framebuffer partition on L4 is a vGPU profile. AWS never says "vGPU". | [G6f GA announcement](https://aws.amazon.com/about-aws/whats-new/2025/07/amazon-ec2-g6f-instances-fractional-gpus), [nvidia-GRID-driver](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvidia-GRID-driver.html) |
| **Google Cloud** | all GPU machine types (N1+GPU, G2, A2, A3, A4) | **Passthrough** `[MEASURED]` | "compute instances with attached GPUs can't be live migrated"; "You must set these compute instances to stop for host maintenance events"; 60 min advance notice then stop/restart | [gpu-host-maintenance](https://docs.cloud.google.com/compute/docs/gpus/gpu-host-maintenance) |
| **Oracle Cloud (OCI)** | `VM.GPU2.x`, `VM.GPU3.x` and later VM shapes | **Passthrough** `[MEASURED]` | NVIDIA's own OCI deployment guide: "The GPUs in virtual machine instance shapes are configured in GPU pass through mode." | [NVIDIA RTX vWS on OCI release notes](https://docs.nvidia.com/vgpu/qvws/latest/qvws-release-notes-oracle-cloud-infrastructure/index.html) |
| **CoreWeave** | GPU instances | Passthrough / bare metal `[REPORTED]` | Multiple secondary comparisons describe direct pass-through with no virtualization overhead. No primary CoreWeave engineering doc located. | secondary blogs only — treat as weak |
| **Linode / Akamai** | RTX 4000 Ada, RTX PRO 6000 | Passthrough `[REPORTED]` | Described as "passthrough" cards in a provider-comparison writeup; not confirmed from Akamai docs. | weak |
| **RunPod, Vast.ai, Lambda** | GPU Pods / marketplace | `[UNKNOWN]` | One SEO comparison asserts RunPod is "virtualized" vs CoreWeave bare-metal; this is not credible evidence of vGPU. RunPod's product is container-shaped, which suggests container-level sharing, but I could not confirm from a primary source. | — |
| **Modal** | Sandboxes | **Container-level (gVisor + nvproxy)** `[MEASURED for gVisor, REPORTED for scale]` | Listed on gvisor.dev/users; 20,000 concurrent sandboxes at peak reported | [gvisor.dev/users](https://gvisor.dev/users/) |
| **Northflank** | GPU sandboxes | **Container-level (gVisor + nvproxy)** `[MEASURED]` | The only entry on gVisor's users page that explicitly cites GPU: uses gVisor "to run GPU workloads in sandboxed environments when nested virtualization is unavailable" | [gvisor.dev/users](https://gvisor.dev/users/) |
| **Google (GKE Sandbox)** | GKE nodes | Container-level (gVisor + nvproxy) `[MEASURED]` | gVisor's supported-driver window "directly aligns with those available within GKE" | [gvisor.dev/docs/user_guide/gpu](https://gvisor.dev/docs/user_guide/gpu/) |
| **Hyper-V on-prem (Windows Server 2025)** | GPU-P | **vGPU (NVIDIA vGPU 18.x under the hood)** `[MEASURED]` | Microsoft: live migration with GPU partitioning requires "the driver included in the NVIDIA vGPU Software v18.x or later"; supported list is A2/A10/A16/A40/L2/L4/L40/L40S/RTX Pro 6000 BSE + Radeon PRO V710 — i.e. exactly the vGPU-capable SKUs | [gpu-partitioning](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/gpu-partitioning) |

---

## 5. Answers to 3a–3h

### 3a. Which providers use NVIDIA AI Enterprise (NVAIE)?

`[MEASURED]` NVAIE is sold on cloud marketplaces at **$2.00 per GPU per hour** on-demand, with private-offer pricing for committed terms; BYOL requires **one NVAIE subscription licence per GPU** the software runs on (or per instance if the instance has no GPU). NVIDIA names **Microsoft Azure, AWS, Google Cloud and Oracle Cloud Infrastructure** as certified providers for BYOL deployment. Source: [NVIDIA AI Enterprise Licensing](https://docs.nvidia.com/ai-enterprise/planning-resource/licensing-guide/latest/licensing.html) and the [NVAIE Packaging, Pricing and Licensing Guide](https://page.adn.de/hubfs/25042371/Herstellerseiten/Nvidia/Download/Virtualisierung/Nvidia%20AI%20Enterprise%20licensing-guide.pdf).

Important qualification on the "NVAIE ⇒ vGPU" proxy the brief proposes: `[INFERRED]` NVAIE-on-marketplace is overwhelmingly sold as a *software stack* (containers, frameworks, support) that runs fine on passthrough or bare metal. NVAIE presence alone therefore does **not** imply vGPU. The reliable NVAIE→vGPU signal is narrower: when a provider both bundles a **GRID/vWS licence with the instance** *and* sells **fractional GPUs**. That combination is present at Azure (`NVadsA10_v5` — "Each virtual machine instance … comes with a GRID license", fractional sizes) and at AWS (`g6f`/`gr6f` — GRID 18.4+ required, fractional partitions). It is *not* present at GCP or OCI.

Per-GPU pricing beyond the $2/GPU/hr marketplace rate: `[UNKNOWN]` — provider-negotiated NVAIE rates are not public.

### 3b. Which providers support pause / suspend / resume / snapshot-runstate / live-migrate on a GPU VM?

This is the decisive fingerprint and it separates the field cleanly.

**Supports it (⇒ mediation layer present):**

- **Azure `NVadsA10_v5`** — `[MEASURED]` Feature-support table: **"Live Migration | Supported"**. Also on the hibernation list. Both impossible under passthrough.
- **Azure `NVv4`** — `[MEASURED]` On the hibernation list ("VM sizes with up to 112-GB RAM from the following GPU VM series support hibernation: NVv4-series, NVadsA10v5-series"), though Live Migration is *Not* Supported. AMD MxGPU SR-IOV.
- **Hyper-V GPU-P on Windows Server 2025 (on-prem)** — `[MEASURED]` "Beginning with Windows Server 2025, live migration is supported with GPU partitioning." Requires IOMMU DMA-bit-tracking CPUs (EPYC Milan+/Sapphire Rapids+); EPYC Rome supports partitioning but **not** live migration with it. Migration falls back to TCP/IP with compression.
- **XenServer / Citrix Hypervisor with NVIDIA vGPU** — `[REPORTED]` XenServer docs state live migration, storage live migration, and suspend/resume work for vGPU-enabled VMs.

**Explicitly excluded (⇒ passthrough):**

- **AWS EC2** — `[MEASURED]` The hibernation-supported instance-family list contains **no accelerated family at all**: "General purpose: M3, M4, M5 … T4g / Compute optimized: C3 … C9gd / Memory optimized: R3 … X8i / Storage optimized: I3, I3en, I4g, I7i, I7ie, I8g, I8ge, Im4gn, Is4gen". Every P and G family is absent. AWS has no GPU live migration either.
- **Google Cloud** — `[MEASURED]` "compute instances with attached GPUs can't be live migrated. You must set these compute instances to stop for host maintenance events." No GPU model or machine family is carved out as an exception.
- **Azure `NCads_H100_v5`** (and the NC/ND compute families generally) — `[MEASURED]` "Live Migration | Not Supported", "Memory Preserving Updates | Not Supported".
- **OpenStack Nova with vGPU** — `[REPORTED]` "Live migration of vGPU instances between hosts is not supported. Evacuation of vGPU instances is not supported." (So even a mediation layer does not automatically buy migration; the orchestration layer has to implement it.)

`[INFERRED]` The pattern is unambiguous: **every GPU instance family that supports hibernate or live-migrate is a fractional/mediated family, and every whole-GPU compute family lacks both.** Azure is the clearest natural experiment because both kinds live in the same documentation template with the same feature table.

### 3c. Which providers have users on forums identifying vGPU?

`[UNKNOWN]` — **I could not find a single credible forum post quoting `nvidia-smi` output from a rented public-cloud instance showing a vGPU profile name.** I searched Reddit, Level1Techs, ServeTheHome, NVIDIA developer forums and Microsoft Q&A. What I found instead:

- Level1Techs threads are overwhelmingly about *self-hosted* vGPU unlocking (e.g. ["GPGPU (GRID) unlock your nvidia card"](https://forum.level1techs.com/t/gpgpu-grid-unlock-your-nvidia-card/170668), ["vGPU unlock without licensing server?"](https://forum.level1techs.com/t/vgpu-unlock-without-licensing-server/173391)), not rented instances.
- The one Microsoft Q&A thread that looked promising ("Azure A10 GPU instance: nvidia-smi") turns out to be a driver-not-installed problem — the user reports `"NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver"` and `lsmod | grep nvidia` empty. No GPU name string is present. `[MEASURED]`

What *is* documented, and functions as the equivalent signal, is providers **requiring the vGPU/GRID guest driver by version**, which no passthrough instance would need:

- Azure: `[MEASURED]` "The Azure NVads A10 v5 VMs only support GRID 17.x or higher driver versions"; "vGPU18 is now available for the NVadsA10_v5-series". Microsoft redistributes vGPU-licensed GRID installers for NVv3, NCasT4_v3, NVadsA10_v5 and NCv6 RTX PRO 6000 BSE, and states "you don't need to set up an NVIDIA vGPU software license server."
- AWS: `[MEASURED]` "G7e instances require GRID 19.1 or later"; "G6f and Gr6f instances require GRID 18.4 to GRID 19.5."

I am flagging the absence deliberately: the fingerprint the brief asked for is real, but the public record of people *observing* it inside rented instances is essentially empty. A single `nvidia-smi -q` capture from an `NV6ads_A10_v5` and a `g6f.xlarge` would settle 3c and 3e simultaneously.

### 3d. Does NVIDIA itself steer customers to vGPU over passthrough?

`[UNKNOWN] / partial.` I did **not** find an NVIDIA document that argues vGPU is more *secure* than passthrough, or that discusses passthrough's DMA exposure as a reason to prefer vGPU. What NVIDIA's own documentation does say, verbatim:

- `[MEASURED]` Definition, neutral in tone: "In GPU pass-through mode, an entire physical GPU is directly assigned to one VM, bypassing the NVIDIA Virtual GPU Manager. In this mode of operation, the GPU is accessed exclusively by the NVIDIA driver running in the VM to which it is assigned." ([vGPU User Guide](https://archive.docs.nvidia.com/vgpu/13.0/grid-vgpu-user-guide/index.html))
- `[MEASURED]` Capability steering, not security steering — the vGPU feature list is built entirely from things passthrough cannot do: "The suspend-resume feature allows NVIDIA vGPU-configured VMs to be temporarily paused and later resumed without losing their operational state." · "Live migration enables the transfer of VMs configured with NVIDIA vGPUs from one physical host to another without downtime." ([NVIDIA AI Enterprise vGPU features](https://archive.docs.nvidia.com/ai-enterprise/release-4/latest/infra-software/vgpu/features.html))
- `[MEASURED]` The only place NVIDIA affirmatively rules passthrough *out*: "GPU passthrough is not supported on NVIDIA Systems that include NVSwitch when using VMware vSphere."
- `[MEASURED]` NVIDIA markets vGPU's operational features specifically at CSPs: "NVIDIA vGPU offers advanced monitoring and management capabilities, including Suspend/Resume, Live Migration and Warm Updates, making it ideal for Cloud Service Providers (CSPs)…"

So the honest answer: **NVIDIA steers to vGPU on manageability and density grounds, not on a stated security argument.** Claims that "NVIDIA says passthrough is insecure because of DMA" appear only in third-party blogs, not in NVIDIA material I could locate. If such a statement exists it is likely in a partner-portal or sales deck I cannot reach.

### 3e. Is single-tenant vGPU (one VM, whole framebuffer) actually sold and deployed?

**(i) Yes — confirmed on Azure.** `[MEASURED]`

The licensing rule the brief cites is real: "For vGPU for Compute, software enforces one license per vGPU assigned to a VM. That license covers up to 16 vGPU instances on a single GPU, or one vGPU that uses the entire physical GPU framebuffer." ([NVAIE vGPU licensing](https://docs.nvidia.com/ai-enterprise/release-8/latest/infra-software/vgpu/licensing.html))

And Azure sells exactly that configuration. `Standard_NV36ads_A10_v5` and `Standard_NV36adms_A10_v5` are listed with **Accelerators: 1, Accelerator-Memory: 24 GB** — a whole A10 with its full framebuffer — inside a series Microsoft describes as "virtual machines with partial NVIDIA GPUs … starting at 1/6th of a GPU with 4-GiB frame buffer to a full A10 GPU with 24-GiB frame buffer", where "Each virtual machine instance in NVadsA10v5-series comes with a GRID license." All sizes in the series share the same feature table, including **Live Migration: Supported**. Azure's launch blog: "SR-IOV-based GPU partitioning provides a strong, hardware-backed security boundary with predictable performance for each virtual machine" and "With support for NVIDIA vGPU, customers can select from virtual machines with one-sixth of an A10 GPU and scale all the way up to two full A10 GPU configurations."

`[INFERRED]` A whole-GPU size that lives in the same vGPU-partitioned family, carries the same GRID licence, and retains live-migration support is a 1:1 vGPU, not a passthrough card sold under the same name. AWS's `g6f` family is the same shape but tops out below a whole GPU.

**(ii) What the guest sees:** partially answered.

- `[MEASURED]` The guest **must** run the NVIDIA vGPU software graphics driver — not a standard/consumer driver. Azure enforces this by version: GRID 17.x+ for NVadsA10_v5. In a vGPU guest, `nvidia-smi` reports the **vGPU profile name** (e.g. `GRID A100-10C`, `NVIDIA A10-24Q`) rather than the bare board name, and NVIDIA's release notes record bugs where "the names of vGPUs on certain NVIDIA A100 80GB GPUs were sometimes incorrectly shown as 'Graphics Device'" — which only makes sense if the profile name is normally what appears.
- `[UNKNOWN]` **I did not obtain a real captured `nvidia-smi` or `lspci` transcript from inside a 1:1 whole-framebuffer cloud vGPU instance.** The Poppelgaard NVads A10 v5 write-up contains a screenshot but no machine-readable text. So I cannot state from evidence whether the `-24Q`-style profile suffix is visible on the full-GPU Azure sizes, or whether Azure presents something that reads as a plain A10. This is the single most valuable missing datum in this report.

### 3f. How widely is gVisor + nvproxy actually deployed?

**Who** `[MEASURED]` — gvisor.dev/users lists: 3B (Tines), Ant Group, **Anthropic**, Beam, Blink, **Cloudflare**, DigitalOcean, Docker, Freedom of the Press Foundation, **Google**, Grist, **Modal**, **Northflank**, **OpenAI**, Tailscale. Only **Northflank** is described on that page as specifically running GPU workloads under gVisor ("when nested virtualization is unavailable on the underlying infrastructure"). Google itself runs it as GKE Sandbox.

**Scale** `[REPORTED]` — Modal's Lovable case study: ~250,000 applications created over one weekend, >1M sandbox invocations, up to 20,000 concurrent at peak. gVisor's own blog (Apr 2026) reports **Tencent running millions of gVisor sandboxes daily** for agentic-RL training — but that post is about sandbox scale generally, and I did not confirm those are GPU/nvproxy sandboxes.

**Supported driver versions** `[MEASURED]` — a rolling window, not a fixed list: "The range of officially supported driver versions directly aligns with those available within GKE." Enumerate with `runsc nvproxy list-supported-drivers`. Three tiers: supported (CI-tested), unsupported (usable only with `--nvproxy-allow-unsupported-driver`), unknown (always blocked).

**Limitations** `[MEASURED]` — six explicit categories: selected GPU models (T4, A100, A10G, L4, H100); selected driver versions; selected capabilities (`compute`, `utility`, `graphics`, `video`); selected device files (**MIG, DRM and modeset excluded**); selected ioctls per device file; selected platforms (systrap, ptrace; KVM has limitations). Open issues confirm rough edges in practice, e.g. [#10413 "nvproxy: unknown control command 0x3d05"](https://github.com/google/gvisor/issues/10413) and [#10478 GPU checkpointing failure](https://github.com/google/gvisor/issues/10478).

**Published security analysis** `[MEASURED]` — the most important statement is gVisor's own, and it is a limitation, not a reassurance:

> "gVisor is much less effective at mitigating vulnerabilities within the NVIDIA GPU drivers themselves, *because* gVisor passes through calls to be handled by the kernel module." … "it is imperative that users update NVIDIA drivers in a timely manner with or without gVisor."

`[INFERRED]` This is the load-bearing caveat for anyone evaluating nvproxy as a multi-tenant boundary: it shrinks the *Linux* syscall attack surface to near zero while leaving the *NVIDIA driver* attack surface essentially intact (narrowed to an allowlist of ioctls, but still executed by the host KMD). I found no independent third-party formal security audit of nvproxy specifically — `[UNKNOWN]`.

### 3g. Which large provider is 100% confirmed to use native PCIe passthrough?

**Google Cloud** is the cleanest confirmation, from a first-party engineering-behaviour doc rather than marketing:

> "compute instances with attached GPUs can't be live migrated. You must set these compute instances to stop for host maintenance events. You can set your stopped compute instances to automatically restart after the maintenance event completes."
> — [Handle GPU host maintenance events, Compute Engine docs](https://docs.cloud.google.com/compute/docs/gpus/gpu-host-maintenance) `[MEASURED]`

This is decisive because Google live-migrates essentially everything else it runs; the GPU carve-out with no machine-type exception is exactly the passthrough signature, and it is a costly operational admission that no provider makes voluntarily.

**Oracle Cloud** is confirmed by an even more explicit statement, though written by NVIDIA about OCI rather than by Oracle:

> "The GPUs in virtual machine instance shapes are configured in GPU pass through mode."
> — [NVIDIA RTX vWS Cloud on OCI, release notes](https://docs.nvidia.com/vgpu/qvws/latest/qvws-release-notes-oracle-cloud-infrastructure/index.html) `[MEASURED]`

**AWS** is confirmed to a very high but not absolute standard for its whole-GPU families `[MEASURED evidence, INFERRED conclusion]`: no accelerated instance family appears anywhere in the hibernation-supported list, no GPU live migration exists, and AWS instructs customers to set `NVreg_EnableGpuFirmware=0` to disable GSP on G4dn/G5/G5g — a knob a guest simply does not own on a mediated vGPU. The caveat is that AWS's newer **`g6f`/`gr6f` fractional family is the exception** and is almost certainly mediated.

### 3h. Does any provider run GPU inside a microVM for lambda-style multi-tenant workloads?

Short answer: **no confirmed case of several tenants sharing one GPU simultaneously inside microVMs.** `[MEASURED + INFERRED]`

- **Firecracker has no PCIe at all.** `[MEASURED]` The GPU/PCIe discussion (#4845) is an open workstream, not a feature: a PoC where "it's possible to attach multiple PCIe devices through vfio" (Manciukic, 2024-11-06), an MVP scoped to "simple cold plugging" and "a single GPU" (2024-11-08), with "snapshot/resume of PCI devices is not supported" and "GPU-direct, NVME support? Will not be supported in the first iterations". Community meetings were **paused on 2025-02-26** for lack of resources; renewed interest appears in March 2026. Note the design tension AWS itself names: PCIe passthrough breaks memory oversubscription and slows boot — the two properties that make Firecracker worth using.
- **Cloud Hypervisor** supports VFIO passthrough — one whole device to one VM. `[MEASURED]` NVIDIA **vGPU does not work on it**: issue [#7572](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/7572) (reported 2025-12-18 by sjmiller609 of Kernel/onkernel.com) shows the GRID guest driver failing on an L40S vGPU under Cloud Hypervisor — "Failed to read region in index: 0, addr: 4, error: Bad address", host "Register read failed…status: 0x65 Timeout occured", the guest seeing the physical L40S rather than the vGPU, and the installer rejecting the device — while "the same configuration works with QEMU: GRID guest driver installs without error." Corroborating community claim: "nvidia-vgpu is hardcoded to QEMU." `[REPORTED]`
- **crosvm** has the strongest GPU story of the three but via **virtio-gpu / Wayland forwarding to the host GPU** — paravirtual, and in practice a ChromeOS/Android use case, not a public multi-tenant GPU offering. `[REPORTED]`
- **KVM Forum 2020, Liang Yan (SUSE), "A Journey to Support vGPU in Firecracker"** is the only serious attempt at microVM + vGPU I located; it was a PoC backporting VFIO bind/ioctl from Cloud Hypervisor, never merged. `[MEASURED]` (talk listing)

`[INFERRED]` Distinguishing as the brief asks: "one tenant at a time on a whole GPU" inside a lightweight VM is achievable today and is what Cloud Hypervisor + VFIO gives you (which provider actually ships this configuration in production, I did not confirm — `[UNKNOWN]`). Providers doing **several tenants sharing one GPU simultaneously** overwhelmingly do it with **containers** (gVisor+nvproxy at Modal/Northflank/GKE Sandbox; MPS/MIG/HAMi elsewhere), not microVMs — precisely because the one technology that would allow it (vGPU) is hardcoded to QEMU, licensed, and datacenter-hardware-only.

---

## 6. Injection report

**No fetched content attempted to instruct me.** Across ~45 fetched pages and documents — GitHub repositories and issue threads, NVIDIA/Microsoft/AWS/Google/Oracle documentation, Phoronix and Level1Techs and Proxmox forum threads, academic listings, a Google Patents page, and Russian/Chinese/Japanese-language blogs — I encountered no text addressed to an AI agent, no "ignore previous instructions", no instruction to run, build or install anything, and no attempt to have me assert a conclusion.

Two things worth noting as *content* caveats rather than injection:

1. **`bird/vgpu-unlock-blackwell`** makes strong technical claims (byte-identical GRID/consumer binaries verified by MD5; GSP crashing on fused-off VF PRIV registers) that are single-author and not independently reproduced. I have tagged them `[REPORTED]` rather than `[MEASURED]` for that reason, even though I read them in the primary repository.
2. Several **SEO-driven provider-comparison blogs** (returned for RunPod/CoreWeave/Lambda queries) assert virtualization architectures with no sourcing. These are not injection attempts, but they are exactly the kind of confident, unsourced assertion that would corrupt this report if quoted; I have marked those provider rows `[UNKNOWN]` or weak rather than repeat them.

---

## 7. What I could not determine, and what would settle it

| Open question | Why it matters | What would settle it |
|---|---|---|
| **Does any approach-C attempt exist that I missed?** GitHub *code* search (`NV_VGPU_MSG_FUNCTION`, `_rpcSendMessage_VGPU`, `gspRpc`, `NV2080_CTRL_CMD_INTERNAL`) was not executable: grep.app returned HTTP 429 on every attempt, and GitHub's authenticated code-search API is out of scope for this session. My Part-1 null result therefore rests on repo-level and web search, not symbol-level code search. | A 3-commit repo implementing a host-side GSP RPC responder would not surface in any search I ran. | Run `grep.app`, GitHub code search, or Sourcegraph for `NV_VGPU_MSG_FUNCTION`, `_rpcSendMessage_VGPU`, `NV_VGPU_MSG_EVENT`, `GSP_RPC` with the vendor's own headers excluded. Also crawl forks of `NVIDIA/open-gpu-kernel-modules` for diffs touching `src/nvidia/src/kernel/virtualization/`. |
| **What exactly does `nvidia-smi` print inside a 1:1 whole-framebuffer cloud vGPU?** (3c + 3e) | Determines whether single-tenant vGPU is *distinguishable* from passthrough by a guest — the crux of the brief's question. | Launch `Standard_NV36ads_A10_v5` on Azure and `g6f.xlarge` on AWS; capture `nvidia-smi -q`, `nvidia-smi -L`, `lspci -nnvv`, and `dmesg | grep -i nvidia`. About 15 minutes and a few dollars. |
| **Is AWS `g6f` vGPU, or something else?** | It is the only fractional NVIDIA family at AWS and would change the AWS row from clean passthrough to mixed. | Same capture as above on a `g6f` instance; the GPU name string and the presence/absence of a `-3Q`/`-3C`-style profile suffix decide it. |
| **Does NVIDIA make a security-grounded argument for vGPU over passthrough anywhere?** (3d) | The brief's hypothesis; I found capability arguments only. | NVIDIA partner-portal material, vGPU sales decks, or GTC session recordings — all behind logins I cannot reach. |
| **Is Tencent's millions-of-sandboxes gVisor deployment GPU-backed?** (3f) | Would be by far the largest nvproxy deployment on record. | The gVisor blog post of 2026-04-23 read in full, or direct confirmation from Tencent. |
| **Any independent security audit of nvproxy?** (3f) | gVisor's own docs concede it does not mitigate NVIDIA driver vulnerabilities; nobody appears to have quantified the residual surface. | Search academic venues (USENIX Security, NDSS, CCS 2024–2026) for gVisor/nvproxy/GPU-sandbox escape analyses. |
| **CoreWeave / Lambda / RunPod / Vast.ai architecture** | Four of the largest GPU-specialist providers, and I have only SEO-blog claims. | First-party engineering blogs, status-page incident write-ups, or guest-side captures from each. |
| **GPUvm implementation detail** | I could not fetch the paper PDF (USENIX and the scispace mirror both returned 403), so my classification of its full-virtualization mode rests on abstracts and citing surveys. | Read `atc14-paper-suzuki.pdf` directly to confirm whether the full-virtualization mode ran the proprietary NVIDIA driver or only Nouveau/Gdev. |
