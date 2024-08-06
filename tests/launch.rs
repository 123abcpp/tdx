// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;
use vmm_sys_util::*;

use tdx::launch::*;
use tdx::tdvf;

// one page of `hlt`
const CODE: &[u8; 4096] = &[
    0xf4; 4096 // hlt
];

#[test]
fn launch() {
    const KVM_CAP_GUEST_MEMFD: u32 = 234;
    const KVM_CAP_MEMORY_MAPPING: u32 = 236;
    const CODE_MEM_ADDRESS: usize = 0x1000;

    // create vm
    let mut kvm_fd = Kvm::new().unwrap();
    let mut tdx_vm = TdxVm::new(&kvm_fd, 100).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let mut cpuid = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();

    // create vcpu
    let mut vcpufd = tdx_vm.fd.create_vcpu(10).unwrap();
    let tdx_vcpu = TdxVcpu::try_from((&mut cpuid, &mut vcpufd, &mut kvm_fd)).unwrap();
    let mut firmware = std::fs::File::open("./tests/data/OVMF.inteltdx.fd").unwrap();
    let sections = tdvf::parse_sections(&mut firmware).unwrap();
    let hob_section = tdvf::get_hob_section(&sections).unwrap();
    tdx_vcpu.init(hob_section.memory_address).unwrap();

    // code for the guest to run
    let userspace_addr = ram_mmap(CODE.len() as u64, -1);
    let userspace_addr =
        unsafe { std::slice::from_raw_parts_mut(userspace_addr as *mut u8, CODE.len()) };
    userspace_addr[..CODE.len()].copy_from_slice(&CODE[..]);
    let userspace_addr = userspace_addr as *const [u8] as *const u8 as u64;
    // let code_addr_space: &mut [u8] =
    //     unsafe { std::slice::from_raw_parts_mut(userspace_addr as *mut u8, CODE.len()) };
    // code_addr_space[..CODE.len()].copy_from_slice(&CODE[..]);
    // let userspace_addr = code_addr_space as *const [u8] as *const u8 as u64;

    let code_gmem = KvmCreateGuestMemfd {
        size: CODE.len() as u64,
        flags: 0,
        reserved: [0; 6],
    };
    let code_gmem = linux_ioctls::create_guest_memfd(&tdx_vm.fd, &code_gmem);
    if code_gmem < 0 {
        panic!("create guest memfd for code failed");
    }

    let code_mem_region = KvmUserspaceMemoryRegion2 {
        slot: 22,
        flags: 1u32 << 2,
        guest_phys_addr: CODE_MEM_ADDRESS as u64,
        memory_size: CODE.len() as u64,
        userspace_addr,
        guest_memfd_offset: 0,
        guest_memfd: code_gmem as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    linux_ioctls::set_user_memory_region2(&tdx_vm.fd, &code_mem_region);

    let attr = KvmMemoryAttributes {
        address: CODE_MEM_ADDRESS as u64,
        size: CODE.len() as u64,
        attributes: 1u64 << 3,
        flags: 0,
    };
    linux_ioctls::set_memory_attributes(&tdx_vm.fd, &attr);
    tdx_vm
        .init_mem_region_raw(
            &tdx_vcpu.fd,
            userspace_addr,
            CODE_MEM_ADDRESS as u64,
            CODE.len() as u64 / 4096,
            false,
        )
        .expect("INIT_MEM_REGION on code failed");

    // map memory to guest
    if !check_extension(KVM_CAP_GUEST_MEMFD) {
        panic!("KVM_CAP_GUEST_MEMFD isn't supported, which is required by TDX");
    }

    for (slot, section) in sections.iter().enumerate() {
        let userspace_address = ram_mmap(section.memory_data_size, -1);
        set_user_memory_region2(&tdx_vm.fd, slot as u32, userspace_address, &section);
        set_memory_attributes(&tdx_vm.fd, &section);

        tdx_vm
            .init_mem_region(&tdx_vcpu.fd, &section, userspace_address)
            .unwrap();
    }

    // finalize measurement
    tdx_vm.finalize().unwrap();

    loop {
        match tdx_vcpu.fd.run().expect("run failed") {
            kvm_ioctls::VcpuExit::Hlt => {
                break;
            }
            _ => panic!("Unexpected exit reason: {:?}", errno::Error::last()),
        }
    }
}
