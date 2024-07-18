#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum EfiMemoryType {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiUnacceptedMemoryType,
    EfiMaxMemoryType,
}

pub const EFI_HOB_HANDOFF_TABLE_VERSION: u32 = 0x0009;

pub const EFI_HOB_TYPE_HANDOFF: u16 = 0x0001;
pub const EFI_HOB_TYPE_MEMORY_ALLOCATION: u16 = 0x0002;
pub const EFI_HOB_TYPE_RESOURCE_DESCRIPTOR: u16 = 0x0003;
pub const EFI_HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
pub const EFI_HOB_TYPE_FV: u16 = 0x0005;
pub const EFI_HOB_TYPE_CPU: u16 = 0x0006;
pub const EFI_HOB_TYPE_MEMORY_POOL: u16 = 0x0007;
pub const EFI_HOB_TYPE_FV2: u16 = 0x0009;
pub const EFI_HOB_TYPE_LOAD_PEIM_UNUSED: u16 = 0x000A;
pub const EFI_HOB_TYPE_UEFI_CAPSULE: u16 = 0x000B;
pub const EFI_HOB_TYPE_FV3: u16 = 0x000C;
pub const EFI_HOB_TYPE_UNUSED: u16 = 0xFFFE;
pub const EFI_HOB_TYPE_END_OF_HOB_LIST: u16 = 0xFFFF;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobGenericHeader {
    pub hob_type: u16,
    pub hob_length: u16,
    pub reserved: u32,
}

type EfiPhysicalAddress = u64;
type EfiBootMode = u32;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobHandoffInfoTable {
    pub header: EfiHobGenericHeader,
    pub version: u32,
    pub boot_mode: EfiBootMode,
    pub efi_memory_top: EfiPhysicalAddress,
    pub efi_memory_bottom: EfiPhysicalAddress,
    pub efi_free_memory_top: EfiPhysicalAddress,
    pub efi_free_memory_bottom: EfiPhysicalAddress,
    pub efi_end_of_hob_list: EfiPhysicalAddress,
}

pub const EFI_RESOURCE_SYSTEM_MEMORY: u32 = 0x00000000;
pub const EFI_RESOURCE_MEMORY_MAPPED_IO: u32 = 0x00000001;
pub const EFI_RESOURCE_IO: u32 = 0x00000002;
pub const EFI_RESOURCE_FIRMWARE_DEVICE: u32 = 0x00000003;
pub const EFI_RESOURCE_MEMORY_MAPPED_IO_PORT: u32 = 0x00000004;
pub const EFI_RESOURCE_MEMORY_RESERVED: u32 = 0x00000005;
pub const EFI_RESOURCE_IO_RESERVED: u32 = 0x00000006;
pub const EFI_RESOURCE_MEMORY_UNACCEPTED: u32 = 0x00000007;
pub const EFI_RESOURCE_MAX_MEMORY_TYPE: u32 = 0x00000008;

pub const EFI_RESOURCE_ATTRIBUTE_PRESENT: u32 = 0x00000001;
pub const EFI_RESOURCE_ATTRIBUTE_INITIALIZED: u32 = 0x00000002;
pub const EFI_RESOURCE_ATTRIBUTE_TESTED: u32 = 0x00000004;
pub const EFI_RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC: u32 = 0x00000008;
pub const EFI_RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC: u32 = 0x00000010;
pub const EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_1: u32 = 0x00000020;
pub const EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_2: u32 = 0x00000040;
pub const EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED: u32 = 0x00000080;
pub const EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTED: u32 = 0x00000100;
pub const EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED: u32 = 0x00000200;
pub const EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE: u32 = 0x00000400;
pub const EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE: u32 = 0x00000800;
pub const EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE: u32 = 0x00001000;
pub const EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE: u32 = 0x00002000;
pub const EFI_RESOURCE_ATTRIBUTE_16_BIT_IO: u32 = 0x00004000;
pub const EFI_RESOURCE_ATTRIBUTE_32_BIT_IO: u32 = 0x00008000;
pub const EFI_RESOURCE_ATTRIBUTE_64_BIT_IO: u32 = 0x00010000;
pub const EFI_RESOURCE_ATTRIBUTE_UNCACHED_EXPORTED: u32 = 0x00020000;
pub const EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED: u32 = 0x00040000;
pub const EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTABLE: u32 = 0x00080000;
pub const EFI_RESOURCE_ATTRIBUTE_READ_PROTECTABLE: u32 = 0x00100000;
pub const EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTABLE: u32 = 0x00200000;
pub const EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTABLE: u32 = 0x00400000;
pub const EFI_RESOURCE_ATTRIBUTE_PERSISTENT: u32 = 0x00800000;
pub const EFI_RESOURCE_ATTRIBUTE_PERSISTABLE: u32 = 0x01000000;
pub const EFI_RESOURCE_ATTRIBUTE_MORE_RELIABLE: u32 = 0x02000000;

pub const EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE: u32 = 
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_TESTED;

pub const EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED: u32 = 
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_TESTED;

pub const EFI_RESOURCE_ATTRIBUTE_TDVF_MMIO: u32 = 
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE;

pub type EfiResourceType = u32;
pub type EfiResourceAttributeType = u32;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobResourceDescriptor {
    pub header: EfiHobGenericHeader,
    pub owner: EfiGuid,
    pub resource_type: EfiResourceType,
    pub resource_attribute: EfiResourceAttributeType,
    pub physical_start: EfiPhysicalAddress,
    pub resource_length: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobGuidType {
    pub header: EfiHobGenericHeader,
    pub name: EfiGuid,
    // guid specific data follows
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobFirmwareVolume {
    pub header: EfiHobGenericHeader,
    pub base_address: EfiPhysicalAddress,
    pub length: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobFirmwareVolume2 {
    pub header: EfiHobGenericHeader,
    pub base_address: EfiPhysicalAddress,
    pub length: u64,
    pub fv_name: EfiGuid,
    pub file_name: EfiGuid,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobFirmwareVolume3 {
    pub header: EfiHobGenericHeader,
    pub base_address: EfiPhysicalAddress,
    pub length: u64,
    pub authentication_status: u32,
    pub extracted_fv: bool,
    pub fv_name: EfiGuid,
    pub file_name: EfiGuid,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobCpu {
    pub header: EfiHobGenericHeader,
    pub size_of_memory_space: u8,
    pub size_of_io_space: u8,
    reserved: [u8; 6],
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobMemoryPool {
    pub header: EfiHobGenericHeader,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EfiHobUefiCapsule {
    pub header: EfiHobGenericHeader,
    pub base_address: EfiPhysicalAddress,
    pub length: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct HobPayloadInfoTable {
    pub header: EfiHobGenericHeader, // normal GUID HOB header
    pub name: EfiGuid,               // TD_HOB_PAYLOAD_ENTRYPOINT_GUID

    // TD_PAYLOAD_IMAGE_TYPE
    pub image_type: u32,

    // Reserved field
    reserved: u32,

    // Guest physical address of the payload entrypoint.
    pub entrypoint: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PayloadImageType {
    // Payload Binary is a PE/COFF or ELF executable image as payload.
    // Entrypoint can be found by parsing the image header.
    // This type image does not follow Linux boot protocol.
    // A payload HOB is used to pass data from TdShim to payload.
    ExecutablePayload,

    // Payload Binary is bzImage, follow Linux boot protocol.
    // The first 512 bytes are boot_param. (zero page)
    // The entrypoint is start address of loaded 64bit Linux kernel
    //   plus 0x200
    BzImage,

    // Payload Binary is vmlinux, follow Linux boot protocol.
    // It's an ELF64 binary image.
    VmLinux,

    // Payload Binary is VMM loaded vmLinux, follow Linux boot protocol.
    // The entrypoint is defined at HOB_PAYLOAD_INFO_TABLE.Entrypoint.
    RawVmLinux,
}

pub const HOB_PAYLOAD_INFO_GUID: EfiGuid = EfiGuid {
    data1: 0xb96fa412,
    data2: 0x461f,
    data3: 0x4be3,
    data4: [0x8c, 0x0d, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0],
};

pub const EFI_HOB_OWNER_ZERO: EfiGuid = EfiGuid {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
};

pub const TD_E820_TABLE_HOB_GUID: EfiGuid = EfiGuid {
    data1: 0x8f8072ea,
    data2: 0x3486,
    data3: 0x4b47,
    data4: [0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73],
};
