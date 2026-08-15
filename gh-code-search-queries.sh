#!/usr/bin/env bash
# GitHub code-search queries for NVIDIA GSP emulation / paravirtualization prior art.
#
# Context: these are the queries that could NOT be run from the research sandbox
# (api.github.com/search/code returns 403 without auth; the sandbox proxy refuses
# global GitHub API paths). Every one of them HAS been run against Sourcegraph
# with the same exclusions and returned nothing new -- but Sourcegraph's index
# demonstrably misses the 0-100 star band, which is the band that matters here.
#
# Requires: gh CLI, authenticated (`gh auth login`).
# Read-only. Writes results to ./ghsearch-out/.
#
# Groups A-F are the six symbol groups. Group G is the one that actually matters:
# co-occurrence of NVIDIA/GSP identifiers with VMM device-model constructs. A hit
# in G is approach C; hits in A-F are most likely just another RPC client.

set -uo pipefail
OUT=./ghsearch-out
mkdir -p "$OUT"

# Noise filter: kernel trees vendoring nova-core/nouveau, NVIDIA's own repos,
# and tinygrad vendored inside openpilot forks.
EXCL='NOT path:nova-core NOT path:nouveau NOT path:tinygrad_repo NOT repo:NVIDIA/open-gpu-kernel-modules NOT repo:NVIDIA/open-gpu-doc'

run() {  # run <label> <query>
  local label="$1"; shift
  local q="$1"
  echo "### $label"
  echo "    $q"
  gh search code "$q" --limit 100 --json repository,path \
    --jq '.[] | "\(.repository.nameWithOwner):\(.path)"' \
    > "$OUT/$label.txt" 2>"$OUT/$label.err" \
    && sort -u "$OUT/$label.txt" -o "$OUT/$label.txt" \
    && echo "    -> $(wc -l < "$OUT/$label.txt") unique results in $OUT/$label.txt" \
    || echo "    -> FAILED: $(head -1 "$OUT/$label.err")"
  sleep 3   # stay under the code-search rate limit
}

# ---- A-F: the six symbol groups -------------------------------------------

run A_gsp_msg_queue   "GSP_MSG_QUEUE_ELEMENT $EXCL"
run B_msgq_headers    "msgqTxHeader $EXCL"
run B_msgq_headers_rx "msgqRxHeader $EXCL"
run C_rpc_header      "rpc_message_header_v $EXCL"
run D_pmc_boot42      "NV_PMC_BOOT_42 $EXCL"
run D_pmc_boot42_camel "pmcBoot42 $EXCL"
run E_booter_load     "booter_load $EXCL"
run E_fwsec_frts      "FWSEC_FRTS $EXCL"
run E_wpr2_meta       "GspFwWprMeta $EXCL"
run F_nva083          "NVA083_ALLOCATION_PARAMETERS $EXCL"
run F_nva083_class    "NVA083_GRID_DISPLAYLESS $EXCL"

# Language-restricted sweeps: a C hit is probably vendored NVIDIA/nouveau
# headers; a hit in these languages is probably a reimplementation.
for lang in rust go python cpp zig csharp; do
  run "G_lang_${lang}" "NV_VGPU_MSG_FUNCTION language:$lang $EXCL"
done

# ---- G: the queries that would actually prove approach C -------------------
# A GSP/RM identifier sitting next to a VMM device-model construct.

run H_qemu_memregion  "MemoryRegionOps NV_PMC_BOOT $EXCL"
run H_qemu_bar        "pci_register_bar nvidia_bar_read $EXCL"
run H_gsp_vfio        "rpc_message_header_v vfio $EXCL"
run H_gsp_kvm         "GSP_MSG_QUEUE_ELEMENT KVM_SET $EXCL"
run H_fakedev         "path:hw/fakedev nvidia"
run H_pci_replay      "path:pci-replay nvidia"
# Anyone building a responder has to answer, not send, these:
run H_responder       "NV_VGPU_MSG_FUNCTION respond $EXCL"
run H_serve           "NV_VGPU_MSG_FUNCTION handle_rpc $EXCL"

echo
echo "=== Repos seen across ALL queries, excluding ones already investigated ==="
cat "$OUT"/*.txt 2>/dev/null | cut -d: -f1 | sort -u | grep -vE \
  '^(NVIDIA/|torvalds/linux|tinygrad/|google/gvisor|microsoft/vattention|0xf4b1/bsod-kernel-fuzzing|yonsei-sslab/moneta|alunwrd/miku-os|hodgesds/narf|eunomia-bpf/gpu_ext|mbilker/vgpu_unlock-rs|mikex86/LibreCuda|thundergolfer/rstrace)'
echo "=== (anything printed above is a genuinely new lead) ==="
