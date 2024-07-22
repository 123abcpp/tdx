// SPDX-License-Identifier: Apache-2.0

use crate::launch::ram_mmap;
use std::io::{Read, Seek, SeekFrom};
use uefi::*;
use uuid::Uuid;

#[allow(dead_code)]
mod uefi;
const EXPECTED_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const EXPECTED_METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

#[repr(packed)]
#[derive(Default, Debug)]
struct TdvfDescriptor {
    /// Signature should equal "TDVF" in bytes
    signature: [u8; 4],

    /// Size of the structure
    length: u32,

    /// Version of the structure. It must be 1
    version: u32,

    /// Number of section entries
    number_of_section_entry: u32,
}

#[repr(packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdvfSection {
    /// The offset to the raw section in the binary image
    pub data_offset: u32,

    /// The size of the raw section in the image. If it is zero, the VMM shall allocate zero memory
    /// from MemoryAddress to (MemoryAddress + MemoryDataSize). If it is zero, then the DataOffset
    /// shall also be zero
    pub raw_data_size: u32,

    /// The guest physical address of the section loaded. It must be 4k aligned. Zero means no
    /// action for the VMM.
    pub memory_address: u64,

    /// The size of the section to be loaded. It must be 4k aligned. It must be at least
    /// RawDataSize if non-zero. If MemoryDataSize is greater than RawDataSize, the VMM shall fill
    /// zero up to the MemoryDataSize. Zero means no action for the VMM.
    pub memory_data_size: u64,

    /// The type of the TDVF section
    pub section_type: TdvfSectionType,

    /// The attribute of the section
    pub attributes: u32,
}

#[repr(packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdxFirmwareEntry {
    /// The offset to the raw section in the binary image
    pub data_offset: u32,

    /// The size of the raw section in the image. If it is zero, the VMM shall allocate zero memory
    /// from MemoryAddress to (MemoryAddress + MemoryDataSize). If it is zero, then the DataOffset
    /// shall also be zero
    pub raw_data_size: u32,

    /// The guest physical address of the section loaded. It must be 4k aligned. Zero means no
    /// action for the VMM.
    pub memory_address: u64,

    /// The size of the section to be loaded. It must be 4k aligned. It must be at least
    /// RawDataSize if non-zero. If MemoryDataSize is greater than RawDataSize, the VMM shall fill
    /// zero up to the MemoryDataSize. Zero means no action for the VMM.
    pub memory_data_size: u64,

    /// The type of the TDVF section
    pub section_type: TdvfSectionType,

    /// The attribute of the section
    pub attributes: u32,

    /// The pointer of the section in the hypervisor if raw_data_size is not 0.
    pub mem_ptr: u64,
}

#[repr(u32)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum TdvfSectionType {
    /// Boot Firmware Volume
    Bfv,

    /// Configuration Firmware Volume
    Cfv,

    /// Trust Domain Hand Off Block
    TdHob,

    /// Temporary Memory
    TempMem,

    ///Permanent Memory
    PermMem,

    ///Payload
    Payload,

    ///Payload Parameter
    PayloadPara,

    /// Reserved
    #[default]
    Reserved = 0xFFFFFFFF,
}

#[repr(packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdxRamEntry {
    /// The guest physical address of the ram part
    pub address: u64,

    ///The length of the ram part
    pub length: u64,

    ///The ram part current type
    pub ram_type: TdxRamType,
}

#[repr(u32)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum TdxRamType {
    RamUnaccepted,
    RamAdded,
    /// Reserved
    #[default]
    Reserved = 0xFFFFFFFF,
}

#[repr(packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdvfHob {
    pub hob_addr: u64,
    pub ptr: u64,
    pub size: u64,

    pub current: u64,
    pub end: u64,
}

#[derive(Debug)]
pub enum Error {
    TableSeek(std::io::Error),
    TableRead(std::io::Error),
    UuidCreate(uuid::Error),
    InvalidDescriptorSignature,
    InvalidDescriptorSize,
    InvalidDescriptorVersion,
    TdHobOverrun(u64),
    UnknownTdxRamType(TdxRamType),
    InvalidSectionAddress(u64, u64),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::TableSeek(ref err) => write!(
                f,
                "Error attempting to seek to a byte offset in a stream: {}",
                err
            ),
            Self::TableRead(ref err) => write!(
                f,
                "Error attempting to read exact number of bytes to completely fill a buffer: {}",
                err
            ),
            Self::UuidCreate(ref err) => write!(f, "Error attempting to create a UUID: {}", err),
            Self::InvalidDescriptorSignature => {
                write!(f, "TDX Metadata Descriptor signature is invalid")
            }
            Self::InvalidDescriptorVersion => {
                write!(f, "TDX Metadata Descriptor version is invalid")
            }
            Self::InvalidDescriptorSize => write!(f, "TDX Metadata Descriptor size is invalid"),
            Self::TdHobOverrun(size) => write!(f, "TD_HOB overrun, size = 0x{:X}", size),
            Self::UnknownTdxRamType(ram_type) => write!(f, "Unknown tdx ram type {:?}", ram_type),
            Self::InvalidSectionAddress(address, size) => write!(
                f,
                "Failed to reserve ram for TDVF, invalid section address {:x}, size:{:x}",
                address, size
            ),
        }
    }
}

/// Locate the GUID at the footer of the OVMF flash file
fn locate_table_footer_guid(fd: &mut std::fs::File) -> Result<Uuid, Error> {
    // there are 32 bytes between the footer GUID and the bottom of the flash file, so we need to
    // move -48 bytes from the bottom of the file to read the 16 byte GUID
    fd.seek(SeekFrom::End(-0x30)).map_err(Error::TableSeek)?;

    let mut table_footer_guid: [u8; 16] = [0; 16];
    fd.read_exact(&mut table_footer_guid)
        .map_err(Error::TableRead)?;

    Uuid::from_slice_le(table_footer_guid.as_slice()).map_err(Error::UuidCreate)
}

/// Locate the size of the entry table in the OVMF flash file
fn locate_table_size(fd: &mut std::fs::File) -> Result<u16, Error> {
    // from the bottom of the file, there is 32 bytes between the footer GUID, 16 bytes for the
    // GUID, and there are 2 bytes for the size of the entry table. We need to move -50 bytes from
    // the bottom of the file to read those 2 bytes.
    fd.seek(SeekFrom::End(-0x32)).map_err(Error::TableSeek)?;

    let mut table_size: [u8; 2] = [0; 2];
    fd.read_exact(&mut table_size).map_err(Error::TableRead)?;

    Ok(u16::from_le_bytes(table_size))
}

/// Reads the entry table into the provided table vector
fn read_table_contents(
    fd: &mut std::fs::File,
    table: &mut Vec<u8>,
    table_size: u16,
) -> Result<(), Error> {
    // table_size + the 32 bytes between the footer GUID and the EOF
    let table_start = -(table_size as i64 + 0x20);
    fd.seek(SeekFrom::End(table_start))
        .map_err(Error::TableSeek)?;
    fd.read_exact(table.as_mut_slice())
        .map_err(Error::TableRead)?;
    Ok(())
}

/// Try to calculate the offset from the bottom of the flash file for the TDX Metadata GUID offset
fn calculate_tdx_metadata_guid_offset(
    table: &mut [u8],
    table_size: usize,
) -> Result<Option<u32>, Error> {
    // starting from the end of the table and after the footer guid and table size bytes (16 + 2)
    let mut offset = table_size - 18;
    while offset >= 18 {
        // entries are laid out as follows:
        //
        // - data (arbitrary bytes identified by the guid)
        // - length from start of data to end of guid (2 bytes)
        // - guid (16 bytes)

        // move backwards through the table to locate the entry guid
        let entry_uuid =
            Uuid::from_slice_le(&table[offset - 16..offset]).map_err(Error::UuidCreate)?;
        // move backwards through the table to locate the entry size
        let entry_size =
            u16::from_le_bytes(table[offset - 18..offset - 16].try_into().unwrap()) as usize;

        // Avoid going through an infinite loop if the entry size is 0
        if entry_size == 0 {
            break;
        }

        offset -= entry_size;

        let expected_uuid = Uuid::parse_str(EXPECTED_METADATA_GUID).map_err(Error::UuidCreate)?;
        if entry_uuid == expected_uuid && entry_size == 22 {
            return Ok(Some(u32::from_le_bytes(
                table[offset..offset + 4].try_into().unwrap(),
            )));
        }
    }

    Ok(None)
}

/// Calculate the offset from the bottom of the file where the TDX Metadata offset block is
/// located
pub fn calculate_tdvf_descriptor_offset(fd: &mut std::fs::File) -> Result<u32, Error> {
    let located = locate_table_footer_guid(fd)?;
    let expected = Uuid::parse_str(EXPECTED_TABLE_FOOTER_GUID).map_err(Error::UuidCreate)?;

    // we found the table footer guid
    if located == expected {
        // find the table size
        let table_size = locate_table_size(fd)?;

        let mut table: Vec<u8> = vec![0; table_size as usize];
        read_table_contents(fd, &mut table, table_size)?;

        // starting from the top and go backwards down the table.
        // starting after the footer GUID and the table length
        if let Ok(Some(offset)) =
            calculate_tdx_metadata_guid_offset(&mut table, table_size as usize)
        {
            return Ok(offset);
        }
    }

    // if we get here then the firmware doesn't support exposing the offset through the GUID table
    fd.seek(SeekFrom::End(-0x20)).map_err(Error::TableSeek)?;

    let mut descriptor_offset: [u8; 4] = [0; 4];
    fd.read_exact(&mut descriptor_offset)
        .map_err(Error::TableRead)?;

    Ok(u32::from_le_bytes(descriptor_offset))
}

/// Parse the entries table and return the TDVF sections
pub fn parse_sections(fd: &mut std::fs::File) -> Result<Vec<TdxFirmwareEntry>, Error> {
    let offset = calculate_tdvf_descriptor_offset(fd)?;
    fd.seek(SeekFrom::End(-(offset as i64)))
        .map_err(Error::TableSeek)?;
    let mut descriptor: TdvfDescriptor = Default::default();
    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            &mut descriptor as *mut _ as *mut u8,
            std::mem::size_of::<TdvfDescriptor>(),
        )
    })
    .map_err(Error::TableRead)?;

    if &descriptor.signature != b"TDVF" {
        return Err(Error::InvalidDescriptorSignature);
    }

    let metadata_size = std::mem::size_of::<TdvfDescriptor>()
        + std::mem::size_of::<TdvfSection>() * descriptor.number_of_section_entry as usize;
    if descriptor.length as usize != metadata_size {
        return Err(Error::InvalidDescriptorSize);
    }

    if descriptor.version != 1 {
        return Err(Error::InvalidDescriptorVersion);
    }

    let mut sections = Vec::new();
    sections.resize_with(
        descriptor.number_of_section_entry as usize,
        TdvfSection::default,
    );

    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            sections.as_mut_ptr() as *mut u8,
            descriptor.number_of_section_entry as usize * std::mem::size_of::<TdvfSection>(),
        )
    })
    .map_err(Error::TableRead)?;

    let mut entries = Vec::new();
    for section in sections {
        let mut entry = TdxFirmwareEntry::default();
        entry.data_offset = section.data_offset;
        entry.raw_data_size = section.raw_data_size;
        entry.memory_address = section.memory_address;
        entry.memory_data_size = section.memory_data_size;
        entry.section_type = section.section_type;
        entry.attributes = section.attributes;
        entries.push(entry);
    }

    Ok(entries)
}

pub fn handle_firmware_entries(
    ram_entries: &mut Vec<TdxRamEntry>,
    entries: &mut Vec<TdxFirmwareEntry>,
    firmware_ptr: u64,
) -> Result<(), Error> {
    for entry in entries {
        match entry.section_type {
            TdvfSectionType::Bfv | TdvfSectionType::Cfv => {
                entry.mem_ptr = firmware_ptr + entry.data_offset as u64;
            }
            TdvfSectionType::TdHob | TdvfSectionType::TempMem => {
                entry.mem_ptr = ram_mmap(entry.memory_data_size, -1);
                accept_ram_range(ram_entries, entry.memory_address, entry.memory_data_size);
            }
            TdvfSectionType::PayloadPara | TdvfSectionType::Payload | TdvfSectionType::PermMem => {
                if find_ram_range(ram_entries, entry.memory_address, entry.memory_data_size)
                    .is_none()
                {
                    return Err(Error::InvalidSectionAddress(
                        entry.memory_address,
                        entry.memory_data_size,
                    ));
                }
            }
            _ => (),
        }
    }
    return Ok(());
}
/// Given the sections in the TDVF table, return the HOB (Hand-off Block) section
pub fn get_hob_section(sections: &Vec<TdxFirmwareEntry>) -> Option<&TdxFirmwareEntry> {
    for section in sections {
        match section.section_type {
            TdvfSectionType::TdHob => {
                return Some(section);
            }
            _ => continue,
        }
    }
    None
}

pub fn find_ram_range(
    entries: &mut Vec<TdxRamEntry>,
    address: u64,
    length: u64,
) -> Option<&mut TdxRamEntry> {
    for entry in entries {
        if address + length <= entry.address || entry.address + entry.length <= address {
            continue;
        }

        //The to-be-accepted ram range must be fully contained by one RAM entry.
        if entry.address > address || entry.address + entry.length < address + length {
            return None;
        }

        let ram_type = entry.ram_type;
        if ram_type == TdxRamType::RamAdded {
            return None;
        }

        return Some(entry);
    }
    return None;
}

pub fn add_ram_entry(
    entries: &mut Vec<TdxRamEntry>,
    address: u64,
    length: u64,
    ram_type: TdxRamType,
) {
    entries.push(TdxRamEntry {
        address: address,
        length: length,
        ram_type: ram_type,
    })
}

pub fn accept_ram_range(entries: &mut Vec<TdxRamEntry>, address: u64, length: u64) {
    let ram = find_ram_range(entries, address, length);
    if ram.is_none() {
        return;
    }
    if let Some(entry) = ram {
        let tmp_address = entry.address;
        let tmp_length = entry.length;
        entry.address = address;
        entry.length = length;
        entry.ram_type = TdxRamType::RamAdded;
        let head_length = address - tmp_address;
        if head_length > 0 {
            let head_start = tmp_address;
            add_ram_entry(entries, head_start, head_length, TdxRamType::RamUnaccepted);
        }

        let tail_start = address + length;
        if tail_start < tmp_address + tmp_length {
            let tail_length = tmp_address + tmp_length - tail_start;
            add_ram_entry(entries, tail_start, tail_length, TdxRamType::RamUnaccepted);
        }
    }
}

#[inline]
pub fn tdvf_align(hob: &mut TdvfHob, alignment: u64) {
    let current = hob.current as u64;
    let aligned = (current + alignment - 1) & !(alignment - 1);
    hob.current = aligned;
}

pub fn tdvf_get_area(tdvf_hob: &mut TdvfHob, size: u64) -> Result<u64, Error> {
    if tdvf_hob.current + size > tdvf_hob.end {
        return Err(Error::TdHobOverrun(size));
    }
    let ret = tdvf_hob.current;
    tdvf_hob.current += size;
    tdvf_align(tdvf_hob, 8);
    return Ok(ret);
}

pub fn tdvf_hob_add_memory_resources(
    ram_entries: Vec<TdxRamEntry>,
    hob: &mut TdvfHob,
) -> Result<(), Error> {
    let mut attr: EfiResourceAttributeType;
    let mut resource_type: EfiResourceType;

    for entry in ram_entries {
        let ram_type = entry.ram_type;
        if ram_type == TdxRamType::RamUnaccepted {
            resource_type = EFI_RESOURCE_MEMORY_UNACCEPTED;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED;
        } else if ram_type == TdxRamType::RamAdded {
            resource_type = EFI_RESOURCE_SYSTEM_MEMORY;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE;
        } else {
            return Err(Error::UnknownTdxRamType(entry.ram_type));
        }

        let region =
            tdvf_get_area(hob, core::mem::size_of::<EfiHobResourceDescriptor>() as u64).unwrap();
        let mut descriptor = unsafe { *(region as *const EfiHobResourceDescriptor) };
        descriptor.header.hob_type = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR;
        descriptor.header.hob_length = core::mem::size_of::<EfiHobResourceDescriptor>() as u16;
        descriptor.header.reserved = 0;
        descriptor.owner = EFI_HOB_OWNER_ZERO;
        descriptor.resource_type = resource_type;
        descriptor.resource_attribute = attr;
        descriptor.physical_start = entry.address;
        descriptor.resource_length = entry.length;
    }

    return Ok(());
}

#[allow(unused_assignments)]
pub fn hob_create(
    ram_entries: Vec<TdxRamEntry>,
    hob_section: TdxFirmwareEntry,
) -> Result<(), Error> {
    let mut hob = TdvfHob {
        hob_addr: hob_section.memory_address,
        size: hob_section.memory_data_size,
        ptr: hob_section.mem_ptr,
        current: hob_section.mem_ptr,
        end: hob_section.mem_ptr + hob_section.memory_data_size,
    };

    let hit = tdvf_get_area(
        &mut hob,
        core::mem::size_of::<EfiHobHandoffInfoTable>() as u64,
    )
    .unwrap();

    let mut info_table = unsafe { *(hit as *const EfiHobHandoffInfoTable) };
    info_table = EfiHobHandoffInfoTable::default();
    info_table.header = EfiHobGenericHeader {
        hob_type: EFI_HOB_TYPE_HANDOFF,
        hob_length: core::mem::size_of::<EfiHobHandoffInfoTable>() as u16,
        reserved: 0,
    };
    info_table.version = EFI_HOB_HANDOFF_TABLE_VERSION;

    tdvf_hob_add_memory_resources(ram_entries, &mut hob).unwrap();

    let last_hob =
        tdvf_get_area(&mut hob, core::mem::size_of::<EfiHobGenericHeader>() as u64).unwrap();
    let mut header = unsafe { *(last_hob as *const EfiHobGenericHeader) };
    header.hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
    header.hob_length = core::mem::size_of::<EfiHobGenericHeader>() as u16;
    header.reserved = 0;

    info_table.efi_end_of_hob_list = hob.hob_addr + (hob.current - hob.ptr);

    return Ok(());
}
