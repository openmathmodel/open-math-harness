//! Chunked uploads. A file being uploaded is staged in the folder's
//! `.nucleus/uploads`, outside every working tree, and appears at its
//! destination only with its last chunk, renamed there atomically: never a
//! partial file where the person or an agent can see it.
//!
//! A conditional save (`expected_revision` with `upload_id`) compares the
//! destination's revision (`files::revision`: descriptor metadata, device,
//! inode, size, nanosecond mtime and ctime, plus a content digest while the
//! file is too recent for that metadata to show a later write) at the first
//! chunk and again before publishing, answers `conflict` for a change it
//! observes, and then publishes by rename:
//! a shell write or a replacement of the path between that check and the
//! rename can still race it. It is no lock: the project's processes, all of
//! the projects' user, take part in no transaction. Its replacement keeps the
//! mode bits but not the inode, hard links, ACLs or extended attributes.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use base64::Engine;
use nucleus_projects_interface::{
    CHUNK_BYTES, Dir, MAX_FILE_BYTES, MAX_UPLOADS, UPLOAD_IDLE_MS, UploadRequest, Uploaded,
};
use nucleus_protocol::{Error, ErrorCode};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};

use crate::files::{hex, parent, revision, unchanged};
use crate::home::{Home, errno, fresh_name, open_beneath};

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, message.into())
}

struct Upload {
    staged: String,
    file: std::fs::File,
    size: u64,
    touched: Instant,
    /// The digest of everything written so far, which is the published content.
    hash: Sha256,
    expected_revision: Option<String>,
    replace: bool,
}

/// The uploads in progress, by working directory and path.
#[derive(Default)]
pub struct Uploads {
    table: HashMap<(String, String, String), Upload>,
}

/// Whether `name` in `parent` may be what an upload publishes to.
fn destination(parent: impl AsFd, name: &str, replace: bool) -> Result<(), Error> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(errno(&format!("{name:?}"), e)),
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
            Err(invalid(format!("{name:?} is a directory, which an upload never replaces")))
        }
        Ok(_) if !replace => Err(invalid(format!("{name:?} exists; upload it with replace to overwrite it"))),
        Ok(_) => Ok(()),
    }
}

impl Uploads {
    /// One chunk of an upload into the working directory `dir`, opened as
    /// `working`.
    pub fn chunk(
        &mut self,
        home: &Home,
        dir: &Dir,
        working: &OwnedFd,
        request: UploadRequest,
    ) -> Result<Uploaded, Error> {
        self.expire(home);
        match (&request.expected_revision, &request.upload_id) {
            (None, None) => {}
            (Some(version), Some(id))
                if request.replace
                    && !version.is_empty()
                    && version.len() <= 256
                    && !id.is_empty()
                    && id.len() <= 64
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') => {}
            _ => return Err(invalid("a conditional save requires replace, expected_revision and upload_id")),
        }
        if request.path == ".git" {
            return Err(invalid("the working directory's .git is not replaced here"));
        }
        // Base64 of a full chunk, padded; a longer text cannot decode to one.
        if request.data_base64.len() > CHUNK_BYTES.div_ceil(3) * 4 {
            return Err(invalid(format!("a chunk is at most {CHUNK_BYTES} bytes")));
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(&request.data_base64)
            .map_err(|e| invalid(format!("data_base64: {e}")))?;
        if data.len() > CHUNK_BYTES {
            return Err(invalid(format!("a chunk is at most {CHUNK_BYTES} bytes")));
        }
        let key = (dir.id(), request.path.clone(), request.upload_id.clone().unwrap_or_default());
        if request.offset == 0 {
            if let Some(old) = self.table.remove(&key) {
                discard(home, &old);
            }
            if self.table.len() >= MAX_UPLOADS {
                return Err(Error::new(
                    ErrorCode::LimitExceeded,
                    format!("{MAX_UPLOADS} uploads are in progress in this project already"),
                ));
            }
            let (above, name) = parent(working, &request.path)?;
            if let Some(expected) = &request.expected_revision
                && checked_destination(&above, name, expected)?.is_none()
            {
                return Ok(Uploaded { size: 0, revision: None, conflict: true });
            }
            destination(&above, name, request.replace)?;
            let staging = home.staging("uploads")?;
            let staged = fresh_name("upload");
            let file = open_beneath(
                &staging,
                &staged,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o666),
            )
            .map_err(|e| errno("the upload's staging file", e))?;
            self.table.insert(
                key.clone(),
                Upload {
                    staged,
                    file: file.into(),
                    size: 0,
                    touched: Instant::now(),
                    hash: Sha256::new(),
                    expected_revision: request.expected_revision.clone(),
                    replace: request.replace,
                },
            );
        }
        let Some(upload) = self.table.get_mut(&key) else {
            return Err(invalid(format!(
                "no upload of {:?} is in progress here; start again at offset 0",
                request.path
            )));
        };
        if request.expected_revision != upload.expected_revision || request.replace != upload.replace {
            return Err(invalid("an upload's save condition cannot change between chunks"));
        }
        if request.offset != upload.size {
            return Err(invalid(format!(
                "the next chunk of {:?} starts at offset {}",
                request.path, upload.size
            )));
        }
        let size = upload.size + data.len() as u64;
        let written = if size > MAX_FILE_BYTES {
            Err(invalid(format!("a file is at most {MAX_FILE_BYTES} bytes")))
        } else {
            upload.file.write_all(&data).map_err(|e| Error::new(ErrorCode::ServiceError, e.to_string()))
        };
        if let Err(e) = written {
            if let Some(failed) = self.table.remove(&key) {
                discard(home, &failed);
            }
            return Err(e);
        }
        upload.hash.update(&data);
        upload.size = size;
        upload.touched = Instant::now();
        if !request.last {
            return Ok(Uploaded { size, revision: None, conflict: false });
        }
        let Some(done) = self.table.remove(&key) else {
            return Err(invalid("the upload is no longer available"));
        };
        let published = publish(home, working, &request, &done);
        if !matches!(&published, Ok(Some(_))) {
            discard(home, &done);
        }
        published.map(|revision| Uploaded { size, conflict: revision.is_none(), revision })
    }

    /// Drops the uploads nobody sent a chunk of for [`UPLOAD_IDLE_MS`].
    fn expire(&mut self, home: &Home) {
        let idle = Duration::from_millis(UPLOAD_IDLE_MS);
        let stale: Vec<_> =
            self.table.iter().filter(|(_, u)| u.touched.elapsed() >= idle).map(|(k, _)| k.clone()).collect();
        for key in stale {
            if let Some(upload) = self.table.remove(&key) {
                discard(home, &upload);
            }
        }
    }
}

/// Makes the staged file durable and renames it to its destination, never
/// over another file unless asked and never over a directory.
fn publish(
    home: &Home,
    working: &OwnedFd,
    request: &UploadRequest,
    upload: &Upload,
) -> Result<Option<String>, Error> {
    upload.file.sync_all().map_err(|e| Error::new(ErrorCode::ServiceError, e.to_string()))?;
    let (above, name) = parent(working, &request.path)?;
    if let Some(expected) = &request.expected_revision {
        let Some(mode) = checked_destination(&above, name, expected)? else { return Ok(None) };
        rustix::fs::fchmod(&upload.file, mode).map_err(|e| errno(name, e))?;
    }
    destination(&above, name, request.replace)?;
    let staging = home.staging("uploads")?;
    let flags = if request.replace { RenameFlags::empty() } else { RenameFlags::NOREPLACE };
    rustix::fs::renameat_with(&staging, upload.staged.as_str(), &above, name, flags)
        .map_err(|e| errno(&format!("{:?}", request.path), e))?;
    // A failure after publication has an unknown outcome; it is never safe to replay it.
    let stat =
        rustix::fs::fstat(&upload.file).map_err(|e| Error::new(ErrorCode::UnknownOutcome, e.to_string()))?;
    revision(&stat, || Ok(hex(&upload.hash.clone().finalize()))).map(Some)
}

/// Check the opened file, without following links, against the revision the
/// save was based on. Publication still has a small check-to-rename window
/// against arbitrary shell writes; this is not a filesystem CAS.
fn checked_destination(parent: impl AsFd, name: &str, expected: &str) -> Result<Option<Mode>, Error> {
    let fd =
        match open_beneath(parent, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())
        {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => return Ok(None),
            Err(e) => return Err(errno(name, e)),
        };
    let stat = rustix::fs::fstat(&fd).map_err(|e| errno(name, e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || !unchanged(&fd, &stat, expected)? {
        return Ok(None);
    }
    Ok(Some(Mode::from_raw_mode(stat.st_mode & 0o777)))
}

fn discard(home: &Home, upload: &Upload) {
    if let Ok(staging) = home.staging("uploads") {
        let _ = rustix::fs::unlinkat(&staging, upload.staged.as_str(), AtFlags::empty());
    }
}
