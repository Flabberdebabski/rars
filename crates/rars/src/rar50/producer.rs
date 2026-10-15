//! Advisory producer identification, separate from user comments and files.

use super::{Archive, FileHeader, FHFL_CRC32, HEAD_SERVICE, HFL_DATA};

pub(crate) const NAME: &[u8] = b"RARS";
pub(crate) const FLAGS: u64 = HFL_DATA | 0x0004; // Discard unknown blocks on update.
pub(crate) const DATA: &[u8] =
    concat!("rars/", env!("CARGO_PKG_VERSION"), "\nmarker-schema=1\n").as_bytes();

/// Only a recognized, intact producer record may be replaced during a preserving
/// rewrite. Unknown schemas and metadata still require an explicit lossy rewrite.
pub(crate) fn is_replaceable(service: &FileHeader, archive: &Archive) -> bool {
    if service.name != NAME
        || service.block.header_type != HEAD_SERVICE
        || service.block.flags != FLAGS
        || service.block.extra_area_size.is_some()
        || service.file_flags != FHFL_CRC32
        || !service.rewrite_metadata_complete
        || service.encrypted
        || service.compression_info != 0
        || service.attributes != 0
        || service.host_os != 0
        || service.modification_time().is_some()
        || service.file_times.is_some()
        || service.data_crc32.is_none()
        || service.unpacked_size > 128
        || service.block.data_size != Some(service.unpacked_size)
        || service.block.data_range.len() as u64 != service.unpacked_size
    {
        return false;
    }
    let mut data = Vec::new();
    if service.write_to(archive, None, &mut data).is_err() {
        return false;
    }
    data.strip_prefix(b"rars/")
        .and_then(|data| data.strip_suffix(b"\nmarker-schema=1\n"))
        .is_some_and(|version| {
            !version.is_empty()
                && version
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(byte))
        })
}
