# Arma device model

## 1. Purpose & philosophy

Arma is a tool for producing **PMI images** (Portable Machine Images). A PMI
image is a machine in a box: it defines both the **platform** — think:
motherboard — and the **firmware** that boots on it, both fixed in the image.
PMI is a general specification; Arma implements a deliberately **curated
subset**, guided by this philosophy:

> Provide a **modern baseline platform**, expressed in devicetree, for
> virtualized operating systems — one that avoids legacy hardware wherever
> possible while remaining **broadly implementable** across hypervisor backends
> (KVM, HVF, WHP) and architectures (x86-64, aarch64; with the unavoidable
> architecture-specific variance).

This document specifies the **platform** half: the base DTB and its slots that
Arma emits. The firmware payload — which Arma also emits — is out of scope for
this device-model document.

## 2. Hardware taxonomy

So, what precisely does this mean? The image defines the **platform** — a
virtual motherboard, its chipset, clocks, buses, and the empty sockets and slots
— and the VMM plugs in the **resources**: the CPU, the memory, and the devices.
The guest boots on the assembled machine.

So a guest's hardware is one of two kinds:

- **Platform** — the motherboard itself.
- **Plugged** — what the VMM installs onto the board: CPU, memory, and devices.

Two more facets pin each piece down. **Defined by** is who authors it:
image-defined hardware is fixed into the base by the image; VMM-defined hardware
is chosen by the host at launch. **Defined in** is how the guest learns of it —
the base DTB, a DTB **overlay** the VMM merges on (CPU, memory), or runtime
**discovery** (devices, never in the DTB).

| Device                 | Kind     | Defined by | Defined in |
| ---------------------- | -------- | ---------- | ---------- |
| interrupt controller   | Platform | Image      | base DTB   |
| timer                  | Platform | Image      | base DTB   |
| PCIe host bridge       | Platform | Image      | base DTB   |
| virtio-mmio transports | Platform | Image      | base DTB   |
| poweroff / reset       | Platform | Image      | base DTB   |
| serial port            | Platform | Image      | base DTB   |
| CPU                    | Plugged  | VMM        | overlay    |
| memory                 | Plugged  | VMM        | overlay    |
| virtio devices         | Plugged  | VMM        | discovery  |

What the VMM plugs into the virtual board is defined through one of two ways.

**CPU and memory are defined via the overlay.** The VMM sizes the CPU count and
the memory and describes them back to the guest by authoring a DTB overlay. Arma
never emits these: the image defines the sockets, the VMM fills them.

**Devices are defined via slots and discovery.** A device plugs into a slot on
the board and is discovered at runtime, never from the DTB:

- a **virtio-mmio transport** is one slot — a fixed MMIO window plus an IRQ,
  declared on the board; the guest probes its magic register to see whether a
  backend is plugged (empty ⇒ DeviceID 0).

- the **PCIe host bridge** offers many slots as capacity (bus/BAR/MSI); the
  guest enumerates config space to find what is plugged.

Because the board is fixed by the image, slot _capacity_ is fixed at build time
(Arma defaults + CLI); _occupancy_ is purely runtime — the VMM fills slots but
never adds them.

## 3. The overlay

The overlay is the VMM-authored devicetree layer merged onto Arma's base at
launch — where the host's resource choices live, sized per tenant request rather
than baked into the image. Per the PMI `merged` extension's allowlist, an
overlay may contribute only:

- the entire **`/cpus`** subtree — the container and every `cpu@N` (its `reg`,
  `status`, `enable-method`, and `compatible`; never `phandle`/`linux,phandle`);
- **`/memory@*`** nodes (`device_type = "memory"`, plus `reg`);
- a **`/distance-map`** (NUMA distances); and
- **`numa-node-id`** on a node the base already declares — the only property the
  overlay may attach outside the three paths above.

So **Arma's base emits none of it**: no `/cpus` node at all (not even the
container), no `/memory@*`, no `/distance-map`, no `numa-node-id`. The base is
the fixed platform the image defines; the overlay is the host's variable
contribution — host-authored input the guest validates against this allowlist
before merging.

## 4. Platform devices

The base DTB declares every platform device a machine needs to boot, taken here
from **most central to most peripheral**. Two rules hold throughout:

- **Addresses and interrupts are Arma's to assign.** A device's `reg` and
  `interrupts` are values Arma picks and the guest reads from the DTB — never
  hardcoded. The contract fixes each device's _binding and required properties_,
  not its address (the example addresses below are illustrative), except a few
  **architecturally fixed** addresses, which are called out. Arma guarantees the
  regions are non-overlapping.

- **Nothing is hidden.** No device may be exposed to the guest that is not
  represented in the base or overlay — so anything a machine needs to boot, even
  a legacy controller, is expressed here, or it does not exist.

Each device names the binding it conforms to; that conformance is part of the
contract.

### Interrupt controller

The most central device: every interrupting device names it via
`interrupt-parent`, and every MSI-capable device via `msi-parent`. It is
image-defined and architecture-specific — a different, but in each case real
(dt-schema), binding per architecture.

#### aarch64 — GICv3 with a GICv2m frame for MSI

Conforms to `arm,gic-v3.yaml`, with the MSI frame conforming to `arm,gic.yaml`.

```dts
gic: interrupt-controller@8000000 {         // address illustrative
    compatible = "arm,gic-v3";
    #interrupt-cells = <3>;                 // <SPI|PPI, number, flags>
    interrupt-controller;
    reg = <0x0 0x8000000 0x0 0x10000>,      // GIC distributor
          <0x0 0x8100000 0x0 0x2000000>;    // GIC redistributor (one region)
};

v2m: msi-controller@a100000 {                // top-level node; devices use
    compatible = "arm,gic-v2m-frame";        //   msi-parent = <&v2m>
    msi-controller;
    reg = <0x0 0xa100000 0x0 0x10000>;
    arm,msi-base-spi = <64>;
    arm,msi-num-spis = <32>;
};
```

MSI is routed through a **GICv2m frame** because Apple's `hv_gic` has no ITS.
The frame is a **top-level node, not a child of the GIC**: `arm,gic-v3.yaml`
admits only an ITS (`arm,gic-v3-its`, with `#msi-cells`) as a GIC child, so an
`arm,gic-v2m-frame` is conformant only standalone. The redistributor is one
fixed region sized for ≤256 vCPUs.

#### x86-64 — Local APIC + IO-APIC

The only standardized x86 interrupt-controller bindings are `intel,ce4100-lapic`
and `intel,ce4100-ioapic` — two separate nodes:

```dts
lapic: interrupt-controller@fee00000 {      // ARCH-FIXED at 0xFEE00000
    compatible = "intel,ce4100-lapic";
    reg = <0x0 0xfee00000 0x0 0x1000>;
    interrupt-controller;
    #interrupt-cells = <2>;
};

ioapic: interrupt-controller@fec00000 {     // ARCH-FIXED at 0xFEC00000
    compatible = "intel,ce4100-ioapic";
    #interrupt-cells = <2>;                  // <pin, sense>
    interrupt-controller;
    reg = <0x0 0xfec00000 0x0 0x1000>;
};
```

The LAPIC and IO-APIC are **separate nodes** (the IO-APIC is not packed into the
LAPIC's `reg`), at their **architecturally fixed** addresses. Both bindings
require `interrupt-controller` and `#interrupt-cells = <2>` on the node, so each
carries them; devices attach to the IO-APIC (`interrupt-parent = <&ioapic>`).

### Timer

The kernel's clock source and clock event. Architecture-specific — and on x86 it
is not a DTB node at all.

#### aarch64 — ARM architected (generic) timer

Conforms to `arm,arch_timer.yaml`.

```dts
timer {
    compatible = "arm,armv8-timer";
    interrupt-parent = <&gic>;
    interrupts = <1 13 0xff08>,    // secure physical (PPI 13)
                 <1 14 0xff08>,    // non-secure physical (PPI 14)
                 <1 11 0xff08>,    // virtual (PPI 11)
                 <1 10 0xff08>;    // hypervisor (PPI 10)
    always-on;
};
```

The arch timer is a CPU system-register device: it has **no `reg`** and is
reached only through its four per-CPU PPIs (secure-phys, non-secure-phys,
virtual, hypervisor, in that order), routed to the GIC. `always-on` marks it as
never losing context, which holds under virtualization.

#### x86-64 — no timer node

x86 has accumulated several timekeeping devices: the PIT (8254 interval timer),
the RTC periodic interrupt, the HPET, the Local APIC timer, and the TSC. For a
modern guest all but the TSC fall away — the PIT, RTC, and HPET are legacy
timers it does not need, and the Local APIC timer, the clock event a modern
guest does use, is part of the LAPIC already declared as the interrupt
controller. That leaves the TSC as the clock source.

The TSC has no node because it is not a platform device: the guest discovers it
and its frequency through `CPUID`, so it belongs to the CPU profile. No x86
timer node is emitted, and nothing is hidden — the clock event lives in the
declared LAPIC, and the clock source is a CPU feature.

### Power: poweroff, reset, and CPU bringup

A machine must turn itself off, reset, and bring its secondary CPUs online.
aarch64 folds all three into one firmware interface; x86 keeps them separate,
and one of the three is not a device at all.

#### aarch64 — PSCI

Conforms to `arm,psci.yaml`. PSCI (Power State Coordination Interface) is the
single aarch64 interface for all three functions: `SYSTEM_OFF` (poweroff),
`SYSTEM_RESET` (reset), and `CPU_ON` (secondary-CPU bringup).

```dts
psci {
    compatible = "arm,psci-1.0", "arm,psci-0.2";
    method = "hvc";    // PSCI calls trap to the hypervisor
};
```

`method = "hvc"` routes PSCI calls to the hypervisor as hypercalls rather than
`smc` calls to firmware. Bringup spans the base/overlay split: the base declares
this node, and each overlay-authored `cpu@N` references it with
`enable-method = "psci"`.

#### x86-64 — syscon poweroff/reset; bringup is architectural

x86 has no unified power interface, so the three functions separate:

- **CPU bringup is not a device.** Secondary CPUs start through the
  architectural INIT–SIPI–SIPI sequence driven via the Local APIC already
  declared as the interrupt controller — there is no node to add, and nothing is
  hidden.

- **Poweroff and reset are MMIO registers**, expressed with the generic
  `syscon-poweroff` and `syscon-reboot` bindings: a write of `value` to the
  node's register triggers the action. The legacy x86 idioms — ACPI PM1 control,
  port `0xCF9`, the 8042 controller, triple-fault — are all avoided.

```dts
poweroff@9010000 {
    compatible = "syscon-poweroff";
    reg = <0x0 0x9010000 0x0 0x4>;
    value = <0x34>;
};

reboot@9020000 {
    compatible = "syscon-reboot";
    reg = <0x0 0x9020000 0x0 0x4>;
    value = <0x1>;
};
```

Each node carries its own `reg`: the older `regmap` phandle into a `syscon` node
is deprecated, and a bare generic `syscon` is not conformant anyway — that
binding requires a vendor-specific compatible, vocabulary a legacy-free platform
has no reason to invent.

### Serial port

A minimal UART, primarily for early-boot diagnostics before richer devices come
up. The hardware is a **16550 over MMIO** (`ns16550a`): the 8250 driver that
backs it is built into every mainstream x86 and aarch64 kernel, whereas PL011 is
arm-only (its driver depends on the ARM AMBA bus). MMIO, not port I/O, so there
is no legacy x86 `0x3f8`. Conforms to `serial/8250.yaml`.

#### aarch64

```dts
aliases {
    serial0 = "/serial@9000000";
};

chosen {
    stdout-path = "serial0:115200n8";
};

serial@9000000 {
    compatible = "ns16550a";
    reg = <0x0 0x9000000 0x0 0x1000>;
    reg-shift = <2>;
    reg-io-width = <4>;
    clock-frequency = <3686400>;
    current-speed = <115200>;
    interrupt-parent = <&gic>;
    interrupts = <0 1 4>;
};
```

The interrupt is a GIC SPI — the GIC's 3-cell `<type, number, flags>`, here SPI
1, level-high. `clock-frequency` is the UART reference clock; `current-speed`
is the firmware-configured line speed. When `--serial` is selected, Arma also
sets `/chosen/stdout-path = "serial0:115200n8"` and prepends `earlycon` to the
kernel command line. Linux consumes the DT stdout-path for early printk, then
the image's own `console=` choice (for example `console=hvc0` or
`console=ttyS0,115200n8`) decides the normal console.

#### x86-64

```dts
aliases {
    serial0 = "/serial@9000000";
};

chosen {
    stdout-path = "serial0:115200n8";
};

serial@9000000 {
    compatible = "ns16550a";
    reg = <0x0 0x9000000 0x0 0x1000>;
    reg-shift = <2>;
    reg-io-width = <4>;
    clock-frequency = <3686400>;
    current-speed = <115200>;
    interrupt-parent = <&ioapic>;
    interrupts = <4 1>;
};
```

The interrupt is an IO-APIC line — the 2-cell `<pin, sense>`, here pin 4.
`clock-frequency` is the UART reference clock; `current-speed` is the
firmware-configured line speed. When `--serial` is selected, Arma also sets
`/chosen/stdout-path = "serial0:115200n8"` and prepends `earlycon` to the kernel
command line. `dtb2acpi` mirrors the DT stdout-path into SPCR, so Linux consumes
the same firmware-console choice through ACPI. The image's own `console=`
choice (for example `console=hvc0` or `console=ttyS0,115200n8`) decides the
normal console.

### virtio-mmio transport

A virtio device attaches here without a PCIe bus — the lightweight transport of
the microVM profile. Each transport is **one slot**: a fixed MMIO window plus an
interrupt, declared on the board whether or not a backend is plugged. The guest
reads the window's magic-value and device-ID registers to learn what, if
anything, is plugged — an empty slot reports DeviceID 0 — so occupancy is a
runtime fact, never a DTB `status`. The base declares a fixed number of these
windows as the slot capacity (an Arma default, overridable by CLI); Arma assigns
each its own window and IRQ. Conforms to `virtio/mmio.yaml`.

#### aarch64

```dts
virtio_mmio@a000000 {
    compatible = "virtio,mmio";
    reg = <0x0 0xa000000 0x0 0x200>;
    interrupt-parent = <&gic>;
    interrupts = <0 16 1>;
};
```

The interrupt is a GIC SPI — the 3-cell `<type, number, flags>`, here SPI 16.
Each transport gets its own line.

#### x86-64

```dts
virtio_mmio@a000000 {
    compatible = "virtio,mmio";
    reg = <0x0 0xa000000 0x0 0x200>;
    interrupt-parent = <&ioapic>;
    interrupts = <16 1>;
};
```

The interrupt is an IO-APIC line — the 2-cell `<pin, sense>`, here pin 16. Each
transport gets its own line.

### PCIe host bridge

The general device-attach point — the traditional profile's counterpart to the
virtio-mmio slots, offering many slots as capacity (a bus range, MMIO BAR
windows, MSI vectors) rather than one window apiece. The base declares the
bridge; the devices behind it are found by enumerating config space, never from
the DTB — so, as with virtio-mmio, capacity is declared and occupancy is
discovered. Three deliberate choices keep it modern and legacy-free:

- **ECAM config space.** Config access is the memory-mapped ECAM window
  (`pci-host-ecam-generic`) — discoverable and MMIO. On aarch64 it is the sole
  config path; on x86 it serves extended config, while base config still reaches
  the same bridge through the architectural `0xcf8`/`0xcfc` ports (see below).

- **MSI only, no INTx.** Devices interrupt via MSI/MSI-X; the legacy INTx wires
  — and the `interrupt-map` swizzle that routes them — are omitted, so a plugged
  device must be MSI-capable (virtio-pci and its peers are).

- **64-bit only — one window, no 32-bit, no I/O.** A single 64-bit
  non-prefetchable BAR window (the legacy 32-bit window and PCI I/O-port window
  are both dropped); plugged devices expose 64-bit BARs. Its size and placement
  are the `--pci-window`/`--min-addr-space` knobs (§6): a fixed `2^B` block near
  the top of the `2^X` space — by default 16 GiB at `[32 GiB, 48 GiB)` in a 64
  GiB space.

Conforms to `host-generic-pci.yaml`.

#### aarch64

```dts
pcie@10000000 {
    compatible = "pci-host-ecam-generic";
    device_type = "pci";
    reg = <0x0 0x10000000 0x0 0x1000000>;                            // ECAM, 16 buses
    bus-range = <0x0 0x0f>;
    #address-cells = <3>;
    #size-cells = <2>;
    ranges = <0x03000000 0x8 0x00000000  0x8 0x00000000  0x4 0x00000000>;   // 64-bit MMIO window (illustrative); base/size from --pci-window/--min-addr-space (§6, per-arch defaults)
    dma-coherent;
    msi-parent = <&v2m>;
};
```

Two properties appear only on aarch64. `msi-parent = <&v2m>` routes MSI to the
GICv2m frame — the bridge's sole interrupt path. `dma-coherent` declares device
DMA as cache-coherent with the CPU, which aarch64 must state explicitly.

#### x86-64

```dts
pcie@10000000 {
    compatible = "pci-host-ecam-generic";
    device_type = "pci";
    reg = <0x0 0x10000000 0x0 0x1000000>;                            // ECAM, 16 buses
    bus-range = <0x0 0x0f>;
    #address-cells = <3>;
    #size-cells = <2>;
    ranges = <0x03000000 0x8 0x00000000  0x8 0x00000000  0x4 0x00000000>;   // 64-bit MMIO window (illustrative); base/size from --pci-window/--min-addr-space (§6, per-arch defaults)
};
```

The same node without those two. MSI on x86 is architectural — delivered to the
Local APIC — so there is no `msi-parent` and no interrupt property at all; and
DMA is coherent by architecture, so `dma-coherent` is unnecessary.

x86 also reaches this bridge's _base_ config space (the standard 256-byte
header) through the architectural `0xcf8`/`0xcfc` ports — the architecture
mandates them and no ACPI table or flag can disable the kernel's probe of them,
so ECAM (via the generated MCFG) serves only _extended_ config. Those ports are
this bridge's x86 config interface, not a separate device: they belong to the
declared `/pci` node, the way ECAM's window does on aarch64.

## 5. The root node

For completeness, the node that contains everything above. It is identical on
both architectures — the architecture appears only in the children — and carries
the platform's addressing and identity.

```dts
/ {
    #address-cells = <2>;
    #size-cells = <2>;
    compatible = "arma,v1";
    model = "Arma Virtual Platform";

    /* the platform devices above */
};
```

- **`#address-cells` / `#size-cells` = `<2>`** — 64-bit addressing; this is why
  every device `reg` above is a two-cell `<hi lo>` pair.

- **`compatible = "arma,v1"`** — the platform's identity in the base, not a
  driver match (guests boot generically without it). Its versioning and
  vendor-prefix policy belong to the platform-identity spec, not here.

- **`model = "Arma Virtual Platform"`** — the human-readable name, shown in the
  guest boot log and `/proc/device-tree/model`.

## 6. Command line (provisional)

> Provisional — a placeholder until the CLI is implemented, collected here so
> the whole option set is visible in one place. `arma build` turns a guest
> kernel and a set of platform choices into a PMI.

- **`--kernel <path>`** _(required)_ — guest kernel: an x86-64 `bzImage` or an
  aarch64 `Image`. The architecture is inferred from it; there is no `--arch`.
- **`--config <path>`** — kernel build config. If given, used as-is (Arma does
  not read the kernel's embedded config); if omitted, Arma falls back to the
  kernel's embedded config (`CONFIG_IKCONFIG`) and errors if that is absent too.
  Drives slot inference and drivability checks.
- **`--initrd <path>`** — initial userspace. A complete `cpio` newc archive
  (`070701`), uncompressed or compressed with gzip or zstd, is used verbatim.
  These are the same compression formats Arma supports for kernel ingestion.
  Compressed inputs are decoded to validate the archive and checksums, not
  recompressed or replaced; the guest kernel therefore needs `CONFIG_RD_GZIP`
  or `CONFIG_RD_ZSTD`, respectively. Malformed/truncated streams or archives
  (including missing trailers) are rejected. Zero padding and concatenated
  archives/members/frames are accepted; other compression formats are not.
  A static ELF binary is wrapped in a newc archive at `/init`; dynamically
  linked executables remain unsupported.
- **`--cmdline <string>`** _(required)_ — kernel command line. Arma never
  supplies a default.
- **`--profile <profile>`** — vCPU ISA baseline, written to `cpu:profile`; the
  VMM validates it against the host. Defaults to RHEL 9's baseline so a stock
  RHEL guest runs — `x86-64-v2` (x86-64) or `armv8.0-a` (aarch64) — raised to
  the kernel's build floor if higher (so a v3-built kernel, e.g. RHEL 10, lands
  on `x86-64-v3` automatically). Override to require more.
- **`--serial`** — declare the serial port. Absent ⇒ no UART node.
- **`--mmio-slots <N>`** — virtio-mmio transport count (see Slot composition).
- **`--pci-slots <N>`** — PCIe slot count; `0` ⇒ no host bridge **and no 64-bit
  window**. PCIe is 64-bit-only (see Slot composition).
- **`--pci-window <B>`** — 64-bit BAR window size **in bits** (window = `2^B`
  bytes). Default **`37`** (128 GiB) on x86-64, **`34`** (16 GiB) on aarch64.
  The x86 default already fits an 80 GB datacenter GPU; raise it for multi-GPU
  (e.g. `38` = 256 GiB).
- **`--min-addr-space <X>`** — minimum guest-physical address bits (space =
  `2^X` bytes) — the compatibility watermark the VMM must provide. Default
  **`39`** (512 GiB) on x86-64, **`36`** (64 GiB; HVF-compatible) on aarch64.
  Invariant **`X ≥ B+2`** (window ≤ 25% of the space); Arma rejects a smaller
  `X`.
- **`<output>`** _(positional, required)_ — the PMI to write.

### Slot composition

`--mmio-slots` and `--pci-slots` size the device-attach surface, resolved
against the kernel support read from the config (`--config` if given, else the
kernel's embedded config):

- **Neither given** — Arma defaults to **16 slots total**, split by support: 8 +
  8 if the kernel builds both virtio-mmio and PCI, or all 16 to whichever single
  one it builds.

- **Either given** — Arma uses exactly what is asked (a missing flag is `0`) and
  **fails** if asked to declare a transport the kernel cannot drive.

Either way, Arma **fails if the kernel supports neither transport** — a guest
with no device-attach surface cannot be used.

Support is read from the config as: virtio-mmio ⇔ `CONFIG_VIRTIO_MMIO`; PCI ⇔
`CONFIG_PCI` + `CONFIG_VIRTIO_PCI` (and, on aarch64, the ECAM host driver
`CONFIG_PCI_HOST_GENERIC`; on x86 base config reaches the bridge through the
architectural `0xcf8`/`0xcfc` ports regardless).

### PCI window and address space

The 64-bit BAR window (`--pci-window B`) is a fixed `2^B` block near the top of
the `2^X` address space (`--min-addr-space X`), placed at
`[2^X − 2^(B+1), 2^X − 2^B)` — naturally aligned, with nothing emitted above it.
`X` is the **compatibility watermark** (the `MAXPHYADDR` the VMM must enable to
launch), and `X ≥ B+2` keeps the window ≤ 25% of the space. Guest RAM fills
below the window and, on hosts with more address bits than `X`, above `2^X` — so
RAM scales with the host while the image stays fixed.

Defaults are per-arch:

- **aarch64** `X=36` / `B=34` — 64 GiB space, 16 GiB window. HVF-compatible
  (36-bit IPA); ~32 GiB low RAM on a 36-bit host.
- **x86-64** `X=39` / `B=37` — 512 GiB space, 128 GiB window. Needs a 39-bit
  host (universal on modern x86) and fits an 80 GB GPU out of the box; ~256 GiB
  low RAM on a 39-bit host. A bigger window forces a bigger `X`, hence a wider
  host.

### Layout check — `arma check <pmi>`

A second subcommand that **evaluates a built PMI's guest-physical layout** and
prints it — a read-only linter over the emitted base DTB and the PMI's load map
(it changes nothing). A clean `check` is part of what "sane output" means: every
shipped image should pass it.

### Command line edit — `arma cmdline <dtb> [cmdline]`

Reads or rewrites `/chosen/bootargs` in a DTB file. With no `cmdline` argument it
prints the current command line; with one it rewrites the property in place
(verbatim). `bootargs` is decoupled from guest-physical placement — editing it
disturbs no addresses, the device map, or the initrd extent — so this retunes a
**detached** base DTB (delivered out-of-band as a standalone file) without
rebuilding the PMI. It does not re-apply the `--serial` `earlycon` prefix; the
operator owns the full command line at this point.

It renders the **full address map**, with the **islands visually demarcated** —
the device island(s), guest RAM, the PCIe BAR window and its burned buddy, and
the loaded payload (tatu, kernel, initramfs, dtb) — and flags layout problems:

- **Fragmentation** — scattered device regions, gaps inside the device island,
  RAM split into more pieces than the architecture forces.
- **Alignment** — any RAM↔device boundary not on 2 MiB; a device island whose
  edges aren't 2 MiB-aligned; a BAR window not `2^B`-aligned.
- **Invariants** — window ≤ 25% (`X ≥ B+2`); window/burned at
  `[2^X − 2^(B+1), 2^X − 2^B)` with nothing emitted above it; all regions
  non-overlapping and within `2^X`; the declared watermark `X`.

The full map it prints is the per-device layout the rest of this section
describes, assembled and measured for a concrete `(X, B, slots, profile)`.
