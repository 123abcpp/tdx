// SPDX-License-Identifier: Apache-2.0

mod linux;

use crate::tdvf::TdxFirmwareEntry;
use crate::tdvf;

use errno::Error;
use kvm_bindings::{kvm_enable_cap, CpuId, KVM_CAP_MAX_VCPUS, KVM_CAP_SPLIT_IRQCHIP};
use linux::{Capabilities, Cmd, CmdId, CpuidConfig, InitVm, TdxError};

use bitflags::bitflags;
use kvm_ioctls::{Kvm, VmFd};
use std::arch::x86_64;

// Defined in linux/arch/x86/include/uapi/asm/kvm.h
const KVM_X86_TDX_VM: u64 = 2;

/// Handle to the TDX VM file descriptor
pub struct TdxVm {
    pub fd: VmFd,
}

impl TdxVm {
    /// Create a new TDX VM with KVM
    pub fn new(kvm_fd: &Kvm, max_vcpus: u64) -> Result<Self, TdxError> {
        let vm_fd = kvm_fd.create_vm_with_type(KVM_X86_TDX_VM)?;

        // TDX requires that MAX_VCPUS and SPLIT_IRQCHIP be set
        let mut cap: kvm_enable_cap = kvm_enable_cap {
            cap: KVM_CAP_MAX_VCPUS,
            ..Default::default()
        };
        cap.args[0] = max_vcpus;
        vm_fd.enable_cap(&cap).unwrap();

        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = 24;
        vm_fd.enable_cap(&cap).unwrap();

        Ok(Self { fd: vm_fd })
    }

    /// Retrieve information about the Intel TDX module
    pub fn get_capabilities(&self) -> Result<TdxCapabilities, TdxError> {
        let caps = Capabilities::default();
        let mut cmd: Cmd = Cmd::from(&caps);

        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(TdxCapabilities {
            attributes: Attributes {
                fixed0: AttributesFlags::from_bits_truncate(caps.attrs_fixed0),
                fixed1: AttributesFlags::from_bits_truncate(caps.attrs_fixed1),
            },
            xfam: Xfam {
                fixed0: XFAMFlags::from_bits_truncate(caps.xfam_fixed0),
                fixed1: XFAMFlags::from_bits_truncate(caps.xfam_fixed1),
            },
            supported_gpaw: caps.supported_gpaw,
            cpuid_configs: Vec::from(caps.cpuid_configs),
        })
    }

    /// Do additional VM initialization that is specific to Intel TDX
    pub fn init_vm(&self, kvm_fd: &Kvm, caps: &TdxCapabilities) -> Result<CpuId, TdxError> {
        let cpuid = kvm_fd
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let mut cpuid_entries: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid.as_slice().to_vec();

        // resize to 256 entries to make sure that InitVm is 8KB
        cpuid_entries.resize(256, kvm_bindings::kvm_cpuid_entry2::default());

        // hex for Ob1100000001011111111 based on the XSAVE state-components architecture
        let xcr0_mask = 0x602ff;
        // hex for 0b11111110100000000 based on the XSAVE state-components architecture
        let xss_mask = 0x1FD00;

        let xfam_fixed0 = caps.xfam.fixed0.bits();
        let xfam_fixed1 = caps.xfam.fixed1.bits();

        // patch cpuid
        for entry in cpuid_entries.as_mut_slice() {
            // mandatory patches for TDX based on XFAM values reported by TdxCapabilities
            match entry.function {
                // XSAVE features and state-components
                0xD => {
                    if entry.index == 0 {
                        // XSAVE XCR0 LO
                        entry.eax &= (xfam_fixed0 as u32) & (xcr0_mask as u32);
                        entry.eax |= (xfam_fixed1 as u32) & (xcr0_mask as u32);
                        // XSAVE XCR0 HI
                        entry.edx &= ((xfam_fixed0 & xcr0_mask) >> 32) as u32;
                        entry.edx |= ((xfam_fixed1 & xcr0_mask) >> 32) as u32;
                    } else if entry.index == 1 {
                        // XSAVE XCR0 LO
                        entry.ecx &= (xfam_fixed0 as u32) & (xss_mask as u32);
                        entry.ecx |= (xfam_fixed1 as u32) & (xss_mask as u32);
                        // XSAVE XCR0 HI
                        entry.edx &= ((xfam_fixed0 & xss_mask) >> 32) as u32;
                        entry.edx |= ((xfam_fixed1 & xss_mask) >> 32) as u32;
                    }
                }
                0x8000_0008 => {
                    // host physical address bits supported
                    let phys_bits = unsafe { x86_64::__cpuid(0x8000_0008).eax } & 0xff;
                    entry.eax = (entry.eax & 0xffff_ff00) | (phys_bits & 0xff);
                }
                0x4000_0001 => {
                    const KVM_FEATURE_CLOCKSOURCE_BIT: u8 = 0;
                    const KVM_FEATURE_CLOCKSOURCE2_BIT: u8 = 3;
                    const KVM_FEATURE_CLOCKSOURCE_STABLE_BIT: u8 = 24;
                    const KVM_FEATURE_ASYNC_PF_BIT: u8 = 4;
                    const KVM_FEATURE_ASYNC_PF_VMEXIT_BIT: u8 = 10;
                    const KVM_FEATURE_STEAL_TIME_BIT: u8 = 5;

                    entry.eax &= !(1 << KVM_FEATURE_CLOCKSOURCE_BIT
                        | 1 << KVM_FEATURE_CLOCKSOURCE2_BIT
                        | 1 << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT
                        | 1 << KVM_FEATURE_ASYNC_PF_BIT
                        | 1 << KVM_FEATURE_ASYNC_PF_VMEXIT_BIT
                        | 1 << KVM_FEATURE_STEAL_TIME_BIT);
                }
                _ => (),
            }
        }

        let mut cmd = Cmd::from(&InitVm::new(&cpuid_entries));
        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        let ret = CpuId::from_entries(cpuid_entries.as_slice()).unwrap();
        Ok(ret)
    }

    /// Encrypt a memory continuous region
    pub fn init_mem_region(
        &self,
        section: &TdxFirmwareEntry,
        source_addr: u64,
    ) -> Result<(), TdxError> {
        const TDVF_SECTION_ATTRIBUTES_MR_EXTEND: u32 = 1u32 << 0;
        let mem_region = linux::TdxInitMemRegion {
            source_addr,
            gpa: section.memory_address,
            nr_pages: section.memory_data_size / 4096,
        };

        let mut cmd = Cmd::from(&mem_region);

        // determines if we also extend the measurement
        cmd.flags = if section.attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND > 0 {
            1
        } else {
            0
        };

        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    pub fn init_mem_region_raw(
        &self,
        source_addr: u64,
        gpa: u64,
        nr_pages: u64,
        extend: bool,
    ) -> Result<(), TdxError> {
        let mem_region = linux::TdxInitMemRegion {
            source_addr,
            gpa,
            nr_pages,
        };

        let mut cmd = Cmd::from(&mem_region);

        // determines if we also extend the measurement
        cmd.flags = extend as u32;

        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    /// Complete measurement of the initial TD contents and mark it ready to run
    pub fn finalize(&self) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: CmdId::FinalizeVm as u32,
            ..Default::default()
        };
        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct AttributesFlags: u64 {
        /// TD Under Debug (TUD) group

        /// Bit 0. Guest TD runs in off-TD debug mode
        const DEBUG = 1;

        /// Bits 3:1. Reserved for future TUD flags
        const TUD_RESERVED = 0x7 << 1;

        /// TD Under Profiling (TUP) group

        /// Bit 4. The TD participates in HGS+ operation
        const HGS_PLUS_PROF = 1 << 4;

        /// Bit 5. The TD participates in system profiling using performance monitoring
        /// counters
        const PERF_PROF = 1 << 5;

        /// Bit 6. The TD participates in system profiling using core out-of-band
        /// telemetry
        const PMT_PROF = 1 << 6;

        /// Bits 15:7. Reserved for future TUP flags
        const TUP_RESERVED = 0x1FF << 7;

        /// Security (SEC) group

        /// Bits 22:16. Reserved for future SEC flags that will indicate positive impact on
        /// TD security
        const SEC_RESERVED_P = 0x7F << 16;

        /// Bits 23:26. Reserved for future SEC flags that will indicate negative impact on
        /// TD security
        const SEC_RESERVED_N = 0xF << 23;

        /// Bit 27. TD is allowed to use Linear Address Space Separation
        const LASS = 1 << 27;

        /// Bit 28. Disable EPT violation conversion to #VE on guest TD access of
        /// PENDING pages
        const SEPT_VE_DISABLE = 1 << 28;

        /// Bit 29. TD is migratable (using a Migration TD)
        const MIGRATABLE = 1 << 29;

        /// Bit 30. TD is allowed to use Supervisor Protection Keys
        const PKS = 1 << 30;

        /// Bit 31. TD is allowed to use Key Locker
        const KL = 1 << 31;

        /// RESERVED Group

        /// Bits 55:32. Reserved for future expansion of the SEC group
        const SEC_EXP_RESERVED = 0xFFFFFF << 32;

        /// OTHER group

        /// Bits 61:32. Reserved for future OTHER flags
        const OTHER_RESERVED = 0x3FFFFFFF << 32;

        /// Bit 62. The TD is a TDX Connet Provisioning Agent
        const TPA = 1 << 62;

        /// Bit 63. TD is allowed to use Perfmon and PERF_METRICS capabilities
        const PERFMON = 1 << 63;
    }

    #[derive(Debug)]
    pub struct XFAMFlags: u64 {
        /// Bit 0. Always enabled
        const FP = 1;

        /// Bit 1. Always enabled
        const SSE = 1 << 1;

        /// Bit 2. Execution is directly controlled by XCR0
        const AVX = 1 << 2;

        /// Bits 4:3. Being deprecated
        const MPX = 0x3 << 3;

        /// Bits 7:5. Execution is directly contrtolled by XCR0. May be enabled only if
        /// AVX is enabled
        const AVX512 = 0x7 << 5;

        /// Bit 8. Execution is controlled by IA32_RTIT_CTL
        const PT = 1 << 8;

        /// Bit 9. Execution is controlled by CR4.PKE
        const PK = 1 << 9;

        /// Bit 10. Execution is controlled by IA32_PASID MSR
        const ENQCMD = 1 << 10;

        /// Bits 12:11. Execution is controlled by CR4.CET
        const CET = 0x3 << 11;

        /// Bit 13. Hardware Duty Cycle is controlled by package-scope IA32_PKG_HDC_CTL
        /// and LP-scope IA32_PM_CTL1 MSRs
        const HDC = 1 << 13;

        /// Bit 14. Execution is controlled by CR4.UINTR
        const ULI = 1 << 14;

        /// Bit 15. Execution is controlled by IA32_LBR_CTL
        const LBR = 1 << 15;

        /// Bit 16. Execution of Hardware-Controlled Performance State is controlled by
        /// IA32_HWP MSRs
        const HWP = 1 << 16;

        /// Bits 18:17. Advanced Matrix Extensions (AMX) is directly controlled by XCR0
        const AMX = 0x3 << 17;
    }
}

/// Reflects the Intel TDX module capabilities and configuration and CPU
/// capabilities
#[derive(Debug)]
pub struct Attributes {
    pub fixed0: AttributesFlags,
    pub fixed1: AttributesFlags,
}

/// Determines the set of extended features available for use by the guest TD
#[derive(Debug)]
pub struct Xfam {
    pub fixed0: XFAMFlags,
    pub fixed1: XFAMFlags,
}

/// Provides information about the Intel TDX module
#[derive(Debug)]
pub struct TdxCapabilities {
    pub attributes: Attributes,
    pub xfam: Xfam,

    /// supported Guest Physical Address Width
    pub supported_gpaw: u32,

    pub cpuid_configs: Vec<CpuidConfig>,
}

/// Manually create the wrapper for KVM_MEMORY_ENCRYPT_OP since `kvm_ioctls` doesn't
/// support `.encrypt_op` for vcpu fds
use vmm_sys_util::*;
ioctl_iowr_nr!(
    KVM_MEMORY_ENCRYPT_OP,
    kvm_bindings::KVMIO,
    0xba,
    std::os::raw::c_ulong
);

pub struct TdxVcpu<'a> {
    pub fd: &'a mut kvm_ioctls::VcpuFd,
}

impl<'a> TdxVcpu<'a> {
    pub fn init(&self, hob_address: u64) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: linux::CmdId::InitVcpu as u32,
            flags: 0,
            data: hob_address as *const u64 as _,
            error: 0,
            _unused: 0,
        };
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(self.fd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            // can't return `ret` because it will just return -1 and not give the error
            // code. `cmd.error` will also just be 0.
            return Err(TdxError::from(errno::Error::last()));
        }
        Ok(())
    }
}

impl<'a>
    TryFrom<(
        &'a mut CpuId,
        &'a mut kvm_ioctls::VcpuFd,
        &'a mut kvm_ioctls::Kvm,
    )> for TdxVcpu<'a>
{
    type Error = TdxError;

    fn try_from(
        value: (
            &'a mut CpuId,
            &'a mut kvm_ioctls::VcpuFd,
            &'a mut kvm_ioctls::Kvm,
        ),
    ) -> Result<Self, Self::Error> {
        // need to enable the X2APIC bit for CPUID[0x1] so that the kernel can call
        // KVM_SET_MSRS(MSR_IA32_APIC_BASE) without failing
        let mut cpuid = value.0.clone();
        for entry in cpuid.as_mut_slice().iter_mut() {
            if entry.index == 0x1 {
                entry.ecx &= 1 << 21;
            }
        }
        value.1.set_cpuid2(&cpuid)?;
        Ok(Self { fd: value.1 })
    }
}

pub fn set_cpuid_with_x2apic(cpuid: &mut CpuId, vcpufd: &kvm_ioctls::VcpuFd) -> Result<(), Error> {
    for entry in cpuid.as_mut_slice().iter_mut() {
        if entry.index == 0x1 {
            entry.ecx &= 1 << 21;
        }
    }
    vcpufd.set_cpuid2(cpuid)?;
    return Ok(());
}

pub fn init_vcpu(vcpufd: &kvm_ioctls::VcpuFd, hob_address: u64) -> Result<(), TdxError> {
    let mut cmd = Cmd {
        id: linux::CmdId::InitVcpu as u32,
        flags: 0,
        data: hob_address as *const u64 as _,
        error: 0,
        _unused: 0,
    };
    let ret = unsafe { ioctl::ioctl_with_mut_ptr(vcpufd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
    if ret < 0 {
        // can't return `ret` because it will just return -1 and not give the error
        // code. `cmd.error` will also just be 0.
        return Err(TdxError::from(errno::Error::last()));
    }
    Ok(())
}

/// Round number down to multiple
pub fn align_down(n: usize, m: usize) -> usize {
    n / m * m
}

/// Round number up to multiple
pub fn align_up(n: usize, m: usize) -> usize {
    align_down(n + m - 1, m)
}

/// Reserve a new memory region of the requested size to be used for maping from the given fd (if
/// any)
pub fn mmap_reserve(size: usize, fd: i32) -> *mut libc::c_void {
    let mut flags = libc::MAP_PRIVATE;
    flags |= libc::MAP_ANONYMOUS;
    unsafe { libc::mmap(0 as _, size, libc::PROT_NONE, flags, fd, 0) }
}

/// Activate memory in a reserved region from the given fd (if any), to make it accessible.
pub fn mmap_activate(
    ptr: *mut libc::c_void,
    size: usize,
    fd: i32,
    map_flags: u32,
    map_offset: i64,
) -> *mut libc::c_void {
    let noreserve = map_flags & (1 << 3);
    let readonly = map_flags & (1 << 0);
    let shared = map_flags & (1 << 1);
    let sync = map_flags & (1 << 2);
    let prot = libc::PROT_READ | (if readonly == 1 { 0 } else { libc::PROT_WRITE });
    let mut map_synced_flags = 0;
    let mut flags = libc::MAP_FIXED;

    flags |= if fd == -1 { libc::MAP_ANONYMOUS } else { 0 };
    flags |= if shared >= 1 {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    flags |= if noreserve >= 1 {
        libc::MAP_NORESERVE
    } else {
        0
    };

    if shared >= 1 && sync >= 1 {
        map_synced_flags = libc::MAP_SYNC | libc::MAP_SHARED_VALIDATE;
    }

    unsafe { libc::mmap(ptr, size, prot, flags | map_synced_flags, fd, map_offset) }
}

/// A mmap() abstraction to map guest RAM, simplifying the flag handling, taking care of
/// alignment requirements and installing guard pages.
pub fn ram_mmap(size: u64, fd: i32) -> u64 {
    const ALIGN: u64 = 4096;
    const GUARD_PAGE_SIZE: u64 = 4096;
    let mut total = size + ALIGN;
    let guard_addr = mmap_reserve(total as usize, -1);
    if guard_addr == libc::MAP_FAILED {
        panic!("MMAP activate failed");
    }
    assert!(ALIGN.is_power_of_two());
    assert!(ALIGN >= GUARD_PAGE_SIZE);

    let offset = align_up(guard_addr as usize, ALIGN as usize) - guard_addr as usize;

    let addr = mmap_activate(guard_addr.wrapping_add(offset), size as usize, fd, 0, 0);

    if addr == libc::MAP_FAILED {
        unsafe { libc::munmap(guard_addr, total as usize) };
        panic!("MMAP activate failed");
    }

    if offset > 0 {
        unsafe { libc::munmap(guard_addr, offset as usize) };
    }

    total -= offset as u64;
    if total > size + GUARD_PAGE_SIZE {
        unsafe {
            libc::munmap(
                addr.wrapping_add(size as usize)
                    .wrapping_add(GUARD_PAGE_SIZE as usize),
                (total - size - GUARD_PAGE_SIZE) as usize,
            )
        };
    }

    addr as u64
}

// NOTE(jakecorrenti): This IOCTL needs to get re-implemented manually. We need to check if KVM_CAP_MEMORY_MAPPING
// and KVM_CAP_GUEST_MEMFD are supported on the host, but those values are not present in rust-vmm/kvm-{ioctls, bindings}
ioctl_io_nr!(KVM_CHECK_EXTENSION, kvm_bindings::KVMIO, 0x03);

pub fn check_extension(i: u32) -> bool {
    let kvm = Kvm::new().unwrap();
    (unsafe { ioctl::ioctl_with_val(&kvm, KVM_CHECK_EXTENSION(), i.into()) }) > 0
}

// FIXME: All of the following code is not currently upstream at rust-vmm/kvm-ioctls. Therefore, we need to implement it ourselves.
// The work is currently ongoing as of 06/06/2024 and can be found at this link: https://github.com/rust-vmm/kvm-ioctls/pull/264
#[repr(C)]
#[derive(Debug)]
pub struct KvmCreateGuestMemfd {
    pub size: u64,
    pub flags: u64,
    pub reserved: [u64; 6],
}

ioctl_iowr_nr!(
    KVM_CREATE_GUEST_MEMFD,
    kvm_bindings::KVMIO,
    0xd4,
    KvmCreateGuestMemfd
);

pub fn create_guest_memfd(vmfd: &kvm_ioctls::VmFd, section: &tdvf::TdxFirmwareEntry) -> i32 {
    let gmem = KvmCreateGuestMemfd {
        size: section.memory_data_size,
        flags: 0,
        reserved: [0; 6],
    };
    linux_ioctls::create_guest_memfd(&vmfd, &gmem)
}

#[repr(C)]
#[derive(Debug)]
pub struct KvmUserspaceMemoryRegion2 {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub guest_memfd_offset: u64,
    pub guest_memfd: u32,
    pub pad1: u32,
    pub pad2: [u64; 14],
}

ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION2,
    kvm_bindings::KVMIO,
    0x49,
    KvmUserspaceMemoryRegion2
);

pub fn set_user_memory_region2(
    vmfd: &kvm_ioctls::VmFd,
    slot: u32,
    userspace_address: u64,
    section: &tdvf::TdxFirmwareEntry,
) {
    const KVM_MEM_GUEST_MEMFD: u32 = 1 << 2;
    let mem_region = KvmUserspaceMemoryRegion2 {
        slot,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: section.memory_address,
        memory_size: section.memory_data_size,
        userspace_addr: userspace_address,
        guest_memfd_offset: 0,
        guest_memfd: create_guest_memfd(vmfd, section) as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    linux_ioctls::set_user_memory_region2(vmfd, &mem_region)
}

#[repr(C)]
#[derive(Debug)]
pub struct KvmMemoryAttributes {
    pub address: u64,
    pub size: u64,
    pub attributes: u64,
    pub flags: u64,
}

ioctl_iow_nr!(
    KVM_SET_MEMORY_ATTRIBUTES,
    kvm_bindings::KVMIO,
    0xd2,
    KvmMemoryAttributes
);

pub fn set_memory_attributes(vmfd: &kvm_ioctls::VmFd, section: &tdvf::TdxFirmwareEntry) {
    const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
    let attr = KvmMemoryAttributes {
        address: section.memory_address,
        size: section.memory_data_size,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE,
        flags: 0,
    };
    linux_ioctls::set_memory_attributes(vmfd, &attr)
}

pub mod linux_ioctls {
    use super::*;

    pub fn create_guest_memfd(fd: &kvm_ioctls::VmFd, gmem: &KvmCreateGuestMemfd) -> i32 {
        unsafe { ioctl::ioctl_with_ref(fd, KVM_CREATE_GUEST_MEMFD(), gmem) }
    }

    pub fn set_user_memory_region2(fd: &kvm_ioctls::VmFd, mem_region: &KvmUserspaceMemoryRegion2) {
        let ret = unsafe { ioctl::ioctl_with_ref(fd, KVM_SET_USER_MEMORY_REGION2(), mem_region) };
        if ret != 0 {
            panic!("Error: set_user_memory_region2: {}", errno::Error::last())
        }
    }

    pub fn set_memory_attributes(fd: &kvm_ioctls::VmFd, attr: &KvmMemoryAttributes) {
        let ret = unsafe { ioctl::ioctl_with_ref(fd, KVM_SET_MEMORY_ATTRIBUTES(), attr) };
        if ret != 0 {
            panic!("Error: set_memory_attributes: {}", errno::Error::last())
        }
    }
}