// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
//! Bounded, panic-free ELF64/AArch64 process-image parser for M57.

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PAGE_SIZE: u64 = 4096;
pub const MAX_LOAD_SEGMENTS: usize = 4;

/// One validated load segment. Mapping code may not observe an unvalidated entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub virtual_address: u64,
    pub flags: u32,
}

/// A bounded executable image passed to the M48 mapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    pub entry: u64,
    pub segments: [Option<LoadSegment>; MAX_LOAD_SEGMENTS],
    pub segment_count: usize,
}

/// Named refusal returned before any page-table mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Truncated,
    UnsupportedHeader,
    InvalidProgramHeaders,
    TooManyLoadSegments,
    InvalidSegment,
    WritableExecutable,
    OverlappingSegments,
    EntryNotExecutable,
    MappingRejected,
}

/// The only side-effecting boundary: an M48 implementation maps validated segments.
pub trait SegmentMapper {
    fn map_segment(&mut self, segment: &LoadSegment) -> Result<(), LoadError>;
}

fn bytes<const N: usize>(image: &[u8], offset: usize) -> Result<[u8; N], LoadError> {
    let end = offset.checked_add(N).ok_or(LoadError::Truncated)?;
    let slice = image.get(offset..end).ok_or(LoadError::Truncated)?;
    <[u8; N]>::try_from(slice).map_err(|_| LoadError::Truncated)
}

fn u16_at(image: &[u8], offset: usize) -> Result<u16, LoadError> {
    Ok(u16::from_le_bytes(bytes(image, offset)?))
}

fn u32_at(image: &[u8], offset: usize) -> Result<u32, LoadError> {
    Ok(u32::from_le_bytes(bytes(image, offset)?))
}

fn u64_at(image: &[u8], offset: usize) -> Result<u64, LoadError> {
    Ok(u64::from_le_bytes(bytes(image, offset)?))
}

fn overlaps(left: &LoadSegment, right: &LoadSegment) -> bool {
    let left_end = left.virtual_address.saturating_add(left.memory_size);
    let right_end = right.virtual_address.saturating_add(right.memory_size);
    left.virtual_address < right_end && right.virtual_address < left_end
}

fn parse_segment(image: &[u8], offset: usize) -> Result<Option<LoadSegment>, LoadError> {
    if u32_at(image, offset)? != PT_LOAD {
        return Ok(None);
    }
    let flags = u32_at(image, offset.checked_add(4).ok_or(LoadError::Truncated)?)?;
    let file_offset = u64_at(image, offset.checked_add(8).ok_or(LoadError::Truncated)?)?;
    let virtual_address = u64_at(image, offset.checked_add(16).ok_or(LoadError::Truncated)?)?;
    let file_size = u64_at(image, offset.checked_add(32).ok_or(LoadError::Truncated)?)?;
    let memory_size = u64_at(image, offset.checked_add(40).ok_or(LoadError::Truncated)?)?;
    let file_end = file_offset
        .checked_add(file_size)
        .ok_or(LoadError::InvalidSegment)?;
    let virtual_end = virtual_address
        .checked_add(memory_size)
        .ok_or(LoadError::InvalidSegment)?;
    if memory_size == 0
        || file_size > memory_size
        || file_end > image.len() as u64
        || virtual_end <= virtual_address
        || virtual_address % PAGE_SIZE != 0
        || memory_size % PAGE_SIZE != 0
        || flags & !(PF_R | PF_W | PF_X) != 0
    {
        return Err(LoadError::InvalidSegment);
    }
    if flags & PF_W != 0 && flags & PF_X != 0 {
        return Err(LoadError::WritableExecutable);
    }
    Ok(Some(LoadSegment {
        file_offset,
        file_size,
        memory_size,
        virtual_address,
        flags,
    }))
}

/// Parse and validate a bounded ELF64 little-endian AArch64 `ET_EXEC` image.
pub fn parse_elf(image: &[u8]) -> Result<LoadPlan, LoadError> {
    if image.len() < ELF_HEADER_SIZE
        || image.get(0..4) != Some(&[0x7f, b'E', b'L', b'F'])
        || image.get(4) != Some(&2)
        || image.get(5) != Some(&1)
        || u16_at(image, 16)? != 2
        || u16_at(image, 18)? != 183
    {
        return Err(LoadError::UnsupportedHeader);
    }
    let entry = u64_at(image, 24)?;
    let table_offset =
        usize::try_from(u64_at(image, 32)?).map_err(|_| LoadError::InvalidProgramHeaders)?;
    let entry_size = usize::from(u16_at(image, 54)?);
    let entry_count = usize::from(u16_at(image, 56)?);
    if entry_size != PROGRAM_HEADER_SIZE {
        return Err(LoadError::InvalidProgramHeaders);
    }
    let table_size = entry_size
        .checked_mul(entry_count)
        .ok_or(LoadError::InvalidProgramHeaders)?;
    let table_end = table_offset
        .checked_add(table_size)
        .ok_or(LoadError::InvalidProgramHeaders)?;
    if table_end > image.len() {
        return Err(LoadError::InvalidProgramHeaders);
    }
    let mut plan = LoadPlan {
        entry,
        segments: [None; MAX_LOAD_SEGMENTS],
        segment_count: 0,
    };
    for header_index in 0..entry_count {
        let offset = table_offset
            .checked_add(
                header_index
                    .checked_mul(entry_size)
                    .ok_or(LoadError::InvalidProgramHeaders)?,
            )
            .ok_or(LoadError::InvalidProgramHeaders)?;
        if let Some(segment) = parse_segment(image, offset)? {
            if plan.segment_count >= MAX_LOAD_SEGMENTS {
                return Err(LoadError::TooManyLoadSegments);
            }
            for prior in plan.segments.iter().flatten() {
                if overlaps(prior, &segment) {
                    return Err(LoadError::OverlappingSegments);
                }
            }
            let slot = plan
                .segments
                .get_mut(plan.segment_count)
                .ok_or(LoadError::TooManyLoadSegments)?;
            *slot = Some(segment);
            plan.segment_count = plan
                .segment_count
                .checked_add(1)
                .ok_or(LoadError::TooManyLoadSegments)?;
        }
    }
    let entry_is_executable = plan.segments.iter().flatten().any(|segment| {
        let end = segment.virtual_address.saturating_add(segment.memory_size);
        segment.flags & PF_X != 0 && segment.virtual_address <= entry && entry < end
    });
    if plan.segment_count == 0 || !entry_is_executable {
        return Err(LoadError::EntryNotExecutable);
    }
    Ok(plan)
}

/// Map a fully validated plan; parsing failures cause no mapper calls.
pub fn load_elf(image: &[u8], mapper: &mut impl SegmentMapper) -> Result<u64, LoadError> {
    let plan = parse_elf(image)?;
    for segment in plan.segments.iter().flatten() {
        mapper
            .map_segment(segment)
            .map_err(|_| LoadError::MappingRejected)?;
    }
    Ok(plan.entry)
}
