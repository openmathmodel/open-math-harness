//! The window's file operations in one working directory of the project:
//! list, download, mkdir, rename and remove (uploads are in `uploads.rs`).
//! Every path is resolved beneath the working directory with no link
//! followed, and the last component is acted on through its opened parent,
//! never by name from the root again.
//! Listings obtain an entry's metadata together with its optional birth time
//! in one no-follow statx observation. If statx is unavailable, the ordinary
//! stat observation still lists it, without inventing a creation time.

use std::os::fd::{AsFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use nucleus_projects_interface::{
    CHUNK_BYTES, Chunk, Entry, Kind, Listing, MAX_FILE_BYTES, PAGE_ENTRIES, segments,
};
use nucleus_protocol::{Error, ErrorCode};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat, Statx, StatxFlags};
use sha2::{Digest, Sha256};

use crate::home::{Home, errno, fresh_name, open_beneath, open_dir};

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, message.into())
}

/// The parent of `path` (opened) and its last name. `path` must name
/// something beneath the working directory, not the directory itself.
pub fn parent(dir: impl AsFd, path: &str) -> Result<(OwnedFd, &str), Error> {
    let parts = segments(path)?;
    let Some((name, above)) = parts.split_last() else {
        return Err(invalid("the path names the working directory itself"));
    };
    let above = above.join("/");
    let parent = open_dir(dir, &above).map_err(|e| errno(&format!("{above:?}"), e))?;
    Ok((parent, name))
}

/// Refuses to rename or remove the repository's own `.git`, which would
/// destroy it.
fn protected(path: &str) -> Result<(), Error> {
    if path == ".git" {
        return Err(invalid("the working directory's .git is not removed or renamed here"));
    }
    Ok(())
}

fn millis(stat: &rustix::fs::Stat) -> u64 {
    let seconds = u64::try_from(stat.st_mtime).unwrap_or(0);
    let nanos = stat.st_mtime_nsec;
    seconds.saturating_mul(1000).saturating_add(nanos / 1_000_000)
}

/// A change this recent may share its timestamp with a later one: a filesystem
/// stamps writes in coarse ticks, so the metadata alone cannot tell them apart.
const RACY_NANOS: i128 = 2_000_000_000;

/// Separates a revision's metadata from its content digest. Neither part
/// contains it, so the split is unambiguous.
const DIGEST_SEPARATOR: char = '~';

/// Descriptor metadata: device, inode, size, nanosecond mtime and ctime.
fn metadata(stat: &Stat) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec
    )
}

/// Whether the modification or change time of `stat` is within [`RACY_NANOS`]
/// of now, or ahead of it: the metadata of such a file may not show its next write.
fn racy(stat: &Stat) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as i128);
    let stamp = |seconds: i64, nanos: u64| i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    let floor = now - RACY_NANOS;
    stamp(stat.st_mtime, stat.st_mtime_nsec) >= floor || stamp(stat.st_ctime, stat.st_ctime_nsec) >= floor
}

/// A file's revision as a reader sees it: its metadata, and while that is
/// racy, the digest of its content (`digest` is called only then). An
/// observation, not a lock against the project's shell writers.
pub fn revision(stat: &Stat, digest: impl FnOnce() -> Result<String, Error>) -> Result<String, Error> {
    let mut revision = metadata(stat);
    if racy(stat) {
        revision.push(DIGEST_SEPARATOR);
        revision.push_str(&digest()?);
    }
    Ok(revision)
}

/// Whether the opened file still is `expected`: the same metadata and, when
/// `expected` carries a digest, the same content.
pub fn unchanged(fd: impl AsFd, stat: &Stat, expected: &str) -> Result<bool, Error> {
    let (recorded, digest) = match expected.split_once(DIGEST_SEPARATOR) {
        Some((recorded, digest)) => (recorded, Some(digest)),
        None => (expected, None),
    };
    if recorded != metadata(stat) {
        return Ok(false);
    }
    match digest {
        None => Ok(true),
        Some(digest) => Ok(digest_of(fd)? == digest),
    }
}

/// The SHA-256 of an open file's content, in hex.
pub fn digest_of(fd: impl AsFd) -> Result<String, Error> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut offset = 0u64;
    loop {
        match rustix::io::pread(&fd, &mut buffer, offset) {
            Ok(0) => break,
            Ok(n) => {
                hash.update(&buffer[..n]);
                offset += n as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(errno("the file's content", e)),
        }
    }
    Ok(hex(&hash.finalize()))
}

/// Lowercase hexadecimal of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn kind(mode: u32) -> Kind {
    match FileType::from_raw_mode(mode) {
        FileType::RegularFile => Kind::File,
        FileType::Directory => Kind::Dir,
        FileType::Symlink => Kind::Link,
        _ => Kind::Other,
    }
}

fn created(stat: &Statx) -> Option<u64> {
    if stat.stx_mask & StatxFlags::BTIME.bits() == 0 {
        return None;
    }
    let seconds = u64::try_from(stat.stx_btime.tv_sec).ok()?;
    seconds.checked_mul(1000)?.checked_add(u64::from(stat.stx_btime.tv_nsec) / 1_000_000)
}

/// All displayed fields come from one observation of the name. In particular,
/// never add a second pathname lookup's birth time to an earlier stat: another
/// process may have replaced the name with a different inode between them.
fn entry(dir: impl AsFd, name: &std::ffi::CStr, shown: String) -> Result<Entry, rustix::io::Errno> {
    let required = StatxFlags::TYPE | StatxFlags::SIZE | StatxFlags::MTIME;
    if let Ok(stat) =
        rustix::fs::statx(&dir, name, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::BASIC_STATS | StatxFlags::BTIME)
        && stat.stx_mask & required.bits() == required.bits()
    {
        let seconds = u64::try_from(stat.stx_mtime.tv_sec).unwrap_or(0);
        return Ok(Entry {
            name: shown,
            kind: kind(u32::from(stat.stx_mode)),
            size: stat.stx_size,
            modified: seconds
                .saturating_mul(1000)
                .saturating_add(u64::from(stat.stx_mtime.tv_nsec) / 1_000_000),
            created: created(&stat),
        });
    }
    let stat = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(Entry {
        name: shown,
        kind: kind(stat.st_mode),
        size: u64::try_from(stat.st_size).unwrap_or(0),
        modified: millis(&stat),
        created: None,
    })
}

/// Where an entry stands in listing order: directories first, then by name
/// (as shown, a name that is not UTF-8 with U+FFFD), then by the name's bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Place {
    rank: u8,
    shown: String,
    name: Vec<u8>,
}

impl Place {
    /// The cursor a page ends at: opaque to the caller, `<rank>/<name>`.
    fn cursor(&self) -> String {
        format!("{}/{}", self.rank, self.shown)
    }

    /// Whether the entry comes after `cursor`.
    fn after(&self, cursor: &(u8, String)) -> bool {
        (self.rank, &self.shown) > (cursor.0, &cursor.1)
    }
}

fn parse_cursor(cursor: &str) -> Result<(u8, String), Error> {
    match cursor.split_once('/') {
        Some(("0", name)) => Ok((0, name.to_owned())),
        Some(("1", name)) => Ok((1, name.to_owned())),
        _ => Err(invalid(format!("{cursor:?} is not the `next` of a listing"))),
    }
}

/// One page of `path`: the first [`PAGE_ENTRIES`] entries after `after`, in
/// listing order. Each page reads the whole directory anew and keeps only
/// the entries that may still be in it, never more than a page and one, so a
/// directory of any size is listed page by page in bounded memory; pages are
/// observations, not one snapshot.
pub fn list(dir: impl AsFd, path: &str, after: Option<&str>) -> Result<Listing, Error> {
    segments(path)?;
    let after = after.map(parse_cursor).transpose()?;
    let opened = open_dir(dir, path).map_err(|e| errno(&format!("{path:?}"), e))?;
    let reading = |e: rustix::io::Errno| errno(&format!("{path:?}"), e);
    let mut kept: std::collections::BinaryHeap<Place> = std::collections::BinaryHeap::new();
    for entry in rustix::fs::Dir::read_from(&opened).map_err(reading)? {
        let entry = entry.map_err(reading)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let shown = String::from_utf8_lossy(name).into_owned();
        let directory = match entry.file_type() {
            FileType::Unknown => {
                match rustix::fs::statat(&opened, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(stat) => FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
                    Err(_) => continue, // removed since it was listed
                }
            }
            known => known == FileType::Directory,
        };
        let place = Place { rank: if directory { 0 } else { 1 }, shown, name: name.to_vec() };
        if after.as_ref().is_some_and(|after| !place.after(after)) {
            continue;
        }
        if kept.len() > PAGE_ENTRIES && kept.peek().is_some_and(|last| place >= *last) {
            continue;
        }
        kept.push(place);
        if kept.len() > PAGE_ENTRIES + 1 {
            kept.pop();
        }
    }
    let mut places = kept.into_sorted_vec();
    let more = places.len() > PAGE_ENTRIES;
    places.truncate(PAGE_ENTRIES);
    let next = if more { places.last().map(Place::cursor) } else { None };
    let mut entries = Vec::with_capacity(places.len());
    for place in places {
        let Ok(name) = std::ffi::CString::new(place.name) else { continue };
        let Ok(entry) = entry(&opened, name.as_c_str(), place.shown) else {
            continue; // removed since it was listed
        };
        entries.push(entry);
    }
    Ok(Listing { entries, next })
}

pub fn download(dir: impl AsFd, path: &str, offset: u64) -> Result<Chunk, Error> {
    if segments(path)?.is_empty() {
        return Err(invalid("a file path is required"));
    }
    // Non-blocking, so a FIFO planted under the name cannot hang the host.
    let fd = open_beneath(dir, path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())
        .map_err(|e| errno(&format!("{path:?}"), e))?;
    let stat = rustix::fs::fstat(&fd).map_err(|e| errno(&format!("{path:?}"), e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(invalid(format!("{path:?} is not a regular file")));
    }
    let size = u64::try_from(stat.st_size).unwrap_or(0);
    if size > MAX_FILE_BYTES {
        return Err(invalid(format!("{path:?} is larger than {MAX_FILE_BYTES} bytes")));
    }
    if offset > size {
        return Err(invalid(format!("offset {offset} is past the end of {path:?} ({size} bytes)")));
    }
    // Before the chunk is read: a later change then shows in the chunk's
    // revision only if it also changed the content the digest was taken from.
    let revision = revision(&stat, || digest_of(&fd))?;
    let want = usize::try_from((size - offset).min(CHUNK_BYTES as u64)).unwrap_or(CHUNK_BYTES);
    let mut data = vec![0u8; want];
    let mut read = 0;
    while read < want {
        match rustix::io::pread(&fd, &mut data[read..], offset + read as u64) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(errno(&format!("{path:?}"), e)),
        }
    }
    let after = rustix::fs::fstat(&fd).map_err(|e| errno(path, e))?;
    if metadata(&stat) != metadata(&after) || read != want {
        return Err(Error::new(ErrorCode::ServiceError, "The file changed while it was read."));
    }
    data.truncate(read);
    let end = offset + read as u64;
    Ok(Chunk {
        data_base64: base64::engine::general_purpose::STANDARD.encode(&data),
        size,
        modified: millis(&stat),
        revision,
        next_offset: (end < size).then_some(end),
    })
}

pub fn mkdir(dir: impl AsFd, path: &str) -> Result<(), Error> {
    let (parent, name) = parent(dir, path)?;
    rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o777)).map_err(|e| errno(&format!("{path:?}"), e))
}

pub fn rename(dir: impl AsFd, from: &str, to: &str) -> Result<(), Error> {
    protected(from)?;
    protected(to)?;
    let (from_parent, from_name) = parent(&dir, from)?;
    let (to_parent, to_name) = parent(&dir, to)?;
    rustix::fs::renameat_with(&from_parent, from_name, &to_parent, to_name, RenameFlags::NOREPLACE)
        .map_err(|e| errno(&format!("{from:?} to {to:?}"), e))
}

/// Removes a file, a link (not its target) or a whole tree. The entry is
/// first renamed into the folder's trash, at once and atomically, then deleted
/// there on a thread of its own, so a large tree does not hold the call.
pub fn remove(home: &Home, dir: impl AsFd, path: &str) -> Result<(), Error> {
    protected(path)?;
    let (parent, name) = parent(dir, path)?;
    rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| errno(&format!("{path:?}"), e))?;
    let trash = home.staging("trash")?;
    let doomed = fresh_name("removed");
    rustix::fs::renameat_with(&parent, name, &trash, doomed.as_str(), RenameFlags::NOREPLACE)
        .map_err(|e| errno(&format!("{path:?}"), e))?;
    std::thread::spawn(move || empty_trash(trash, &doomed));
    Ok(())
}

/// Deletes one entry of the trash. Through the trash directory's own
/// descriptor, so whatever replaces its name meanwhile is not what goes.
fn empty_trash(trash: OwnedFd, name: &str) {
    let trash = cap_std::fs::Dir::from_std_file(std::fs::File::from(trash));
    let removed = match trash.symlink_metadata(name) {
        Ok(meta) if meta.is_dir() => trash.remove_dir_all(name),
        Ok(_) => trash.remove_file(name),
        Err(e) => Err(e),
    };
    if let Err(e) = removed {
        eprintln!("nucleus-project: a removed entry stays in the trash: {e}");
    }
}

/// Deletes what an earlier run left in the trash and the upload and bundle
/// staging areas: fail and restart clean.
pub fn clear_staging(home: &Home) {
    for area in ["trash", "uploads", crate::bundles::AREA] {
        let Ok(fd) = home.staging(area) else { continue };
        let dir = cap_std::fs::Dir::from_std_file(std::fs::File::from(fd));
        let Ok(entries) = dir.entries() else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let _ = match entry.file_type() {
                Ok(kind) if kind.is_dir() => dir.remove_dir_all(&name),
                _ => dir.remove_file(&name),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn creation_time_requires_the_birth_time_mask_and_a_representable_timestamp() {
        let file = tempfile::tempfile().unwrap();
        let mut stat = rustix::fs::statx(&file, "", AtFlags::EMPTY_PATH, StatxFlags::BASIC_STATS).unwrap();
        stat.stx_btime.tv_sec = 123;
        stat.stx_btime.tv_nsec = 456_000_000;
        stat.stx_mask |= StatxFlags::BTIME.bits();
        assert_eq!(created(&stat), Some(123_456));
        stat.stx_mask &= !StatxFlags::BTIME.bits();
        assert_eq!(created(&stat), None, "unreported birth time is not replaced by mtime or ctime");
        stat.stx_mask |= StatxFlags::BTIME.bits();
        stat.stx_btime.tv_sec = -1;
        assert_eq!(created(&stat), None, "pre-epoch time is not clamped to a fictitious creation time");
        stat.stx_btime.tv_sec = i64::MAX;
        assert_eq!(created(&stat), None, "a time outside the wire's millisecond range is unavailable");
    }
}
