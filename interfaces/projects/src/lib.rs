//! The `projects` and `files` interfaces, version 8: the person's projects
//! and their files.
//!
//! # Layout
//!
//! A project `p` is a folder, `projects/<p>/` in the person's workspace,
//! of the one Linux user every project's processes run as. The folder holds
//! the project's repository at `repo/`, where every session of the project
//! works; anything else there (the services' staging areas, the discovery
//! workers' workspaces) is outside it. A [`Dir`] names the one directory
//! the `files` actions work in: the repository, id `<p>`. Nucleus keeps no
//! worktrees: git worktrees, branches and other repositories in a project's
//! folder are git's and the person's, ordinary directories to Nucleus.
//!
//! # Who serves what
//!
//! The `projects` service (the router) runs as the runtime's own identity
//! and reads no project's files. It provides `projects` and `files` (and
//! the project-scoped `fs`, `shell`, `pdf`, `diffs`, `skills` and `jobs`) to
//! the window and the session agents, and forwards each call to the project's
//! host process, an ordinary process of the projects' user whose root is
//! the project's folder. Every resource names its project first
//! (`["projects", p, …]`), so a capability on `["projects", p]` reaches that
//! project and no other; the router strips that prefix ([`Dir::in_home`])
//! for the host.
//!
//! # `projects` (router)
//!
//! | Action | Resource | Payload | Result | Effect |
//! | --- | --- | --- | --- | --- |
//! | `list` | `["projects"]`, or `["projects", p]` for `p` alone | [`ListProjects`] | [`ProjectList`] | observation |
//! | `create` | [`project_resource`] | `{}` | [`Project`] | reversible mutation |
//! | `stop` | [`project_resource`] | `{}` | `{}` | irreversible |
//! | `begin_archive` | [`project_resource`] | `{}` | `{}` | reversible mutation |
//! | `archive` | [`project_resource`] | `{}` | `{}` | reversible mutation |
//! | `unarchive` | [`project_resource`] | `{}` | `{}` | reversible mutation |
//! | `delete` | [`project_resource`] | `{}` | [`Deletion`] | irreversible |
//! | `purge` | [`project_resource`] | `{}` | `{}` | irreversible |
//!
//! # `files` (router, and the host as is)
//!
//! Every action's resource is a [`Dir::resource`]; the paths in its payload
//! are relative to that directory ([`segments`]), and no symbolic link is
//! followed anywhere on them.
//!
//! | Action | Payload | Result | Effect |
//! | --- | --- | --- | --- |
//! | `list` | [`ListRequest`] | [`Listing`] | observation |
//! | `download` | [`DownloadRequest`] | [`Chunk`] | observation |
//! | `upload` | [`UploadRequest`] | [`Uploaded`] | irreversible (it may replace a file) |
//! | `mkdir` | [`PathRequest`] | `{}` | reversible mutation |
//! | `rename` | [`RenameRequest`] | `{}` | reversible mutation (never replaces) |
//! | `remove` | [`PathRequest`] | `{}` | irreversible |
//! | `git_state` | [`Empty`] | [`GitState`] | observation |
//! | `git_initialize` | [`GitInitialize`] | [`Empty`] | reversible mutation |
//! | `git_remote` | [`GitRemote`] | [`Empty`] | reversible mutation |
//! | `bundle_out` | [`BundleOut`] | [`Bundle`] | reversible mutation |
//! | `bundle_read` | [`BundleRead`] | [`BundleChunk`] | observation |
//! | `bundle_write` | [`BundleWrite`] | [`Bundle`] | reversible mutation |
//! | `bundle_import` | [`BundleImport`] | [`Imported`] | reversible mutation |
//!
//! The `git_state` and `bundle_*` actions move commits between the
//! repository and the platform, which keeps the GitHub credentials, as git
//! bundles. `git_state` reports HEAD, the branches (`refs/heads/*`) and the
//! tracking refs (`refs/remotes/omm/*`), by name. `bundle_out` stages a bundle
//! of `commit` that carries exactly
//! [`OUTGOING_REF`], without the commits reachable from the `basis` the
//! repository has (others are skipped); `bundle_read` serves it in chunks
//! and removes it after the last. `bundle_write` stages a bundle the
//! platform sends, which carries exactly [`INCOMING_REF`], chunk by chunk;
//! `bundle_import` fetches it into `refs/remotes/omm/<branch>`, or with
//! `review` `refs/omm/reviews/<branch>` (never HEAD, the index, the working
//! tree or a local branch), checks that the
//! ref is then `oid`, and removes it whatever happens. Bundles are streamed to
//! disk; one untouched for [`BUNDLE_IDLE_MS`] is dropped.
//!
//! # The host (`nucleus-project`), private to the router
//!
//! One endpoint with the `files` actions and `init` and `delete`
//! ([`host_interface`]), on resources relative to the project's folder:
//! `[]` and `["repo"]`. `delete` removes the folder itself, with
//! everything in it.
//!
//! `list` is paged by name: a page holds at most `limit` projects
//! ([`DEFAULT_PROJECT_PAGE`], at most [`MAX_PROJECT_PAGE`]) after `after`,
//! and `next` is the `after` of the next page. A project being deleted is
//! listed with `deleting`.
//!
//! `create` makes the project's folder and its repository (`git init`), as
//! the projects' user; a failure removes the folder again.
//! `stop` ends every process of the project at once, whoever started it
//! (its hosts, its sessions' agents and their plugins, its jobs, its swarm
//! members and workers' commands), and answers once none is left; what
//! keeps records of them (sessions, jobs, runs) sees them end.
//! `begin_archive` disables new execution while its caller stops those
//! services; `archive` then marks the preserved folder archived. An
//! unfinished archive cannot be unarchived. `unarchive` restores the active
//! folder name without starting work.
//!
//! Deleting a project takes two of its actions, with the other services'
//! `forget` between them, which this service never calls: the deletion is
//! its caller's work (the UI service's), since those services start after
//! this one and use its endpoints. `delete` begins it: the project's folder
//! takes its deleting name, after which none of its processes starts, its
//! job records go and its hosts stop; it answers `deleting`, or `deleted`
//! when nothing of the project is left (also for a project that never was).
//! `purge`, on a project being deleted, ends every process of it and has its
//! host remove its folder, and answers once the folder is gone, which may
//! take minutes (a large folder); asked while a purge is under way it
//! answers with it. A project being deleted is listed with `deleting` until
//! its folder is gone, so a project of the same name starts empty.
//!
//! None of these actions is a tool: they are the window's, a person's own
//! operations. This crate defines data and the names' rules only.

use std::collections::BTreeMap;

use nucleus_protocol::{
    ActionDecl, ActionName, EffectClass, EndpointName, Error, ErrorCode, InterfaceDecl, ResourcePath,
};
use serde::{Deserialize, Serialize};

pub const PROJECTS_ENDPOINT: &str = "projects";
pub const FILES_ENDPOINT: &str = "files";
pub const VERSION: u32 = 8;

pub const ACTION_LIST: &str = "list";
pub const ACTION_CREATE: &str = "create";
pub const ACTION_STOP: &str = "stop";
pub const ACTION_BEGIN_ARCHIVE: &str = "begin_archive";
pub const ACTION_ARCHIVE: &str = "archive";
pub const ACTION_UNARCHIVE: &str = "unarchive";
/// The router's `delete` of a project (its beginning); the host's of the
/// project's folder.
pub const ACTION_DELETE: &str = "delete";
/// The router's end of a project's deletion: its processes and folder go.
pub const ACTION_PURGE: &str = "purge";
pub const ACTION_DOWNLOAD: &str = "download";
pub const ACTION_UPLOAD: &str = "upload";
pub const ACTION_MKDIR: &str = "mkdir";
pub const ACTION_RENAME: &str = "rename";
pub const ACTION_REMOVE: &str = "remove";
pub const ACTION_GIT_STATE: &str = "git_state";
pub const ACTION_GIT_REMOTE: &str = "git_remote";
pub const ACTION_GIT_INITIALIZE: &str = "git_initialize";
pub const ACTION_BUNDLE_OUT: &str = "bundle_out";
pub const ACTION_BUNDLE_READ: &str = "bundle_read";
pub const ACTION_BUNDLE_WRITE: &str = "bundle_write";
pub const ACTION_BUNDLE_IMPORT: &str = "bundle_import";
/// Host only: an empty repository in a new project folder.
pub const ACTION_INIT: &str = "init";

/// The directory of the person's workspace holding the projects, and the
/// first segment of every resource of these interfaces.
pub const PROJECTS: &str = "projects";
/// A project's repository, in its folder: where every session of the project works.
pub const REPOSITORY: &str = "repo";
/// The project every VM is created with (`activate` makes it once), where a
/// window's sessions go when it names no project.
pub const DEFAULT_PROJECT: &str = "default";

/// Longest project name, in bytes.
pub const MAX_NAME_BYTES: usize = 40;
/// Projects in one page of `list` when the caller gives no `limit`, and the
/// most in one page.
pub const DEFAULT_PROJECT_PAGE: usize = 100;
pub const MAX_PROJECT_PAGE: usize = 1000;
/// Longest repository URL `git_remote` takes, in bytes.
pub const MAX_REMOTE_URL_BYTES: usize = 2048;
/// The longest a git operation may take: the deadline of `create`.
pub const GIT_TIMEOUT_MS: u64 = 120_000;

/// Longest path in a `files` payload, and longest segment of one, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_SEGMENT_BYTES: usize = 255;
/// Most entries in one page of `list`. A directory has no bound on its
/// entries: it is listed page by page.
pub const PAGE_ENTRIES: usize = 1000;
/// Most bytes of file content in one `download` or `upload` chunk (decoded).
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Largest file `download` serves and `upload` accepts.
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Uploads in progress at once in one project.
pub const MAX_UPLOADS: usize = 8;
/// An upload with no chunk for this long is dropped.
pub const UPLOAD_IDLE_MS: u64 = 600_000;

/// Most bytes of a bundle in one `bundle_read` or `bundle_write` chunk (decoded).
pub const BUNDLE_CHUNK_BYTES: usize = 512 * 1024;
/// A staged bundle no call touched for this long is dropped.
pub const BUNDLE_IDLE_MS: u64 = 600_000;
/// The one ref of a bundle the platform sends.
pub const INCOMING_REF: &str = "refs/omm/incoming";
/// The one ref of a bundle `bundle_out` makes.
pub const OUTGOING_REF: &str = "refs/omm/outgoing";
/// Where `bundle_import` puts a branch: `<TRACKING_PREFIX><branch>`.
pub const TRACKING_PREFIX: &str = "refs/remotes/omm/";

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidInput, message.into())
}

/// Git ref syntax, without a product-specific length or ASCII-only restriction.
/// A branch cannot be interpreted as a command-line option.
pub fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '/', '.'])
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name.bytes().any(|b| b <= b' ' || b == 127 || b"~^:?*[\\".contains(&b))
        && !name.split('/').any(|part| part.starts_with('.') || part.ends_with(".lock"))
}

/// Whether `oid` is a full object id: 40 lowercase hex digits.
pub fn valid_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `id` is a staged bundle's id: `b-` and 32 lowercase hex digits.
pub fn valid_bundle_id(id: &str) -> bool {
    id.strip_prefix("b-")
        .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Whether `name` is a project name: 1–40 bytes of lowercase
/// letters, digits and `-`, starting with a letter or digit. No `_`, no `.`,
/// nothing a shell or git would read as an option. It is the kernel's rule
/// for a project's identity ([`nucleus_protocol::valid_project`]).
pub fn valid_name(name: &str) -> bool {
    nucleus_protocol::valid_project(name) && name.len() <= MAX_NAME_BYTES
}

fn name(name: &str, what: &str) -> Result<String, Error> {
    if valid_name(name) {
        Ok(name.to_owned())
    } else {
        Err(invalid(format!(
            "{what} name {name:?}: 1-{MAX_NAME_BYTES} lowercase letters, digits and '-', starting with a letter or digit"
        )))
    }
}

/// The resource of a whole project: `["projects", <project>]`.
pub fn project_resource(project: &str) -> Result<ResourcePath, Error> {
    ResourcePath::new([PROJECTS.to_owned(), name(project, "project")?])
}

/// The project a resource names: its second segment, after `projects`.
pub fn project_of(resource: &ResourcePath) -> Result<&str, Error> {
    match resource.segments() {
        [root, project, ..] if root == PROJECTS && valid_name(project) => Ok(project),
        _ => Err(invalid(format!("{resource} names no project: expected [\"{PROJECTS}\", project, …]"))),
    }
}

/// The one directory of a project the `files` actions work in: its
/// repository.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dir {
    project: String,
}

impl Dir {
    /// The repository of `project`.
    pub fn repository(project: &str) -> Result<Self, Error> {
        Ok(Self { project: name(project, "project")? })
    }

    /// Parses an id: `<project>`.
    pub fn parse(id: &str) -> Result<Self, Error> {
        Self::repository(id)
    }

    /// The inverse of [`Self::resource`]: a working directory's resource and
    /// nothing else (not the project, not a path beneath the directory).
    pub fn from_resource(resource: &ResourcePath) -> Result<Self, Error> {
        match resource.segments() {
            [root, project, main] if root == PROJECTS && main == REPOSITORY => Self::repository(project),
            _ => Err(invalid(format!(
                "{resource} names no working directory: expected [\"{PROJECTS}\", project, \"{REPOSITORY}\"]"
            ))),
        }
    }

    /// The inverse of [`Self::in_home`], for a host given a folder-relative
    /// resource: `["repo"]` of `project`.
    pub fn from_home_resource(project: &str, resource: &ResourcePath) -> Result<Self, Error> {
        match resource.segments() {
            [main] if main == REPOSITORY => Self::repository(project),
            _ => Err(invalid(format!("{resource} names no working directory: expected [\"{REPOSITORY}\"]"))),
        }
    }

    pub fn id(&self) -> String {
        self.project.clone()
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    /// The directory's segments inside the project's folder.
    pub fn in_home(&self) -> Vec<&str> {
        vec![REPOSITORY]
    }

    /// The directory relative to the project's folder, `/`-separated: what
    /// the project's `diffs` calls the repository.
    pub fn path(&self) -> String {
        self.in_home().join("/")
    }

    /// The resource of every call about this directory.
    pub fn resource(&self) -> ResourcePath {
        let segments = [PROJECTS, self.project.as_str()].into_iter().chain(self.in_home());
        // Valid by construction: the names were checked.
        ResourcePath::new(segments).unwrap_or_default()
    }
}

/// The segments of a `/`-separated path relative to a working directory.
/// Refused unless every segment is a plain name: not empty, `.` or `..`, no
/// NUL, at most [`MAX_SEGMENT_BYTES`], the whole at most [`MAX_PATH_BYTES`].
/// `""` is the directory itself (no segments).
pub fn segments(path: &str) -> Result<Vec<&str>, Error> {
    if path.len() > MAX_PATH_BYTES {
        return Err(invalid(format!("the path is over {MAX_PATH_BYTES} bytes")));
    }
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts {
        if part.is_empty() || *part == "." || *part == ".." || part.contains('\0') {
            return Err(invalid(format!("{path:?} must be a relative path of plain names")));
        }
        if part.len() > MAX_SEGMENT_BYTES {
            return Err(invalid(format!("a name in {path:?} is over {MAX_SEGMENT_BYTES} bytes")));
        }
    }
    Ok(parts)
}

/// Payload of an action that takes nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// Payload of `list`: the page after the project `after` (none: the first),
/// of at most `limit` projects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListProjects {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl ListProjects {
    /// The page's size: `limit`, [`DEFAULT_PROJECT_PAGE`] without, refused
    /// past [`MAX_PROJECT_PAGE`] or at 0.
    pub fn page(&self) -> Result<usize, Error> {
        match self.limit {
            None => Ok(DEFAULT_PROJECT_PAGE),
            Some(limit) if (1..=MAX_PROJECT_PAGE).contains(&limit) => Ok(limit),
            Some(limit) => {
                Err(invalid(format!("limit {limit}: a page holds 1 to {MAX_PROJECT_PAGE} projects")))
            }
        }
    }
}

/// Result of `list`: one page of projects, by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectList {
    pub projects: Vec<Project>,
    /// Pass it as `after` for the next page; absent on the last one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    /// The repository's [`Dir`] id.
    pub dir: String,
    /// It is being deleted: nothing of it starts, until `purge` removed it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleting: bool,
    /// Files are preserved, but no project work starts until unarchived.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub archived: bool,
    /// New execution is disabled while the caller stops the project's work.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub archiving: bool,
}

/// Result of `delete`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deletion {
    pub state: DeletionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionState {
    /// It is being deleted: nothing of it starts; `purge` removes it.
    Deleting,
    /// Nothing of it is left.
    Deleted,
}

impl Project {
    /// The project `name`, with its directory's id.
    pub fn named(name: &str) -> Result<Self, Error> {
        Ok(Project {
            name: name.to_owned(),
            dir: Dir::repository(name)?.id(),
            deleting: false,
            archived: false,
            archiving: false,
        })
    }
}

/// Payload of `files list`. `after`: the `next` of the previous page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Dir,
    /// A symbolic link, never followed.
    Link,
    /// Anything else: a socket, a FIFO, a device.
    Other,
}

/// One directory entry. `size` is the entry's own (a link's, not its
/// target's); timestamps are in milliseconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub modified: u64,
    /// The current VM inode's birth time, absent when the host or filesystem
    /// cannot report it. Atomic replacement (including editor saves) may
    /// change it; it is not the original local file's creation time. Neither
    /// modification nor inode-change time substitutes for a missing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<u64>,
}

/// One page of a directory, at most [`PAGE_ENTRIES`]: directories first,
/// then by name. Each page is read anew from the directory (pages are
/// observations, not one snapshot); a directory of any size is listed page
/// by page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub entries: Vec<Entry>,
    /// Opaque; pass it as `after` for the next page; absent on the last one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequest {
    pub path: String,
    pub offset: u64,
}

/// One chunk of a file: at most [`CHUNK_BYTES`] from the requested offset.
/// `size` and `modified` describe the file when the chunk was read; when
/// they change between chunks the file changed. `next_offset` is `None` on
/// the last chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub data_base64: String,
    pub size: u64,
    pub modified: u64,
    /// Opaque: descriptor metadata, including inode and nanosecond change
    /// time, plus a content digest while the file changed too recently for
    /// that metadata to be trusted.
    pub revision: String,
    pub next_offset: Option<u64>,
}

/// One chunk of an upload. `offset` 0 starts (or restarts) the upload of
/// `path`; every later chunk continues at the size the previous answer gave.
/// The chunk with `last` publishes the file, replacing an existing one only
/// with `replace`.
///
/// A conditional save (the Files editor) sends on every chunk the `revision`
/// it read (`expected_revision`) and an `upload_id` of its own, so
/// simultaneous saves of one path stay apart. The project's host checks the
/// destination, opened without following a link, when the upload starts and
/// again just before the atomic rename: one that changed, is gone or is not a
/// regular file answers `conflict: true` and nothing is published. A
/// published save keeps the old file's permission bits and answers the new
/// `revision`. It is an optimistic check, not a compare-and-swap against the
/// project's other writers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    pub path: String,
    pub offset: u64,
    pub data_base64: String,
    pub last: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replace: bool,
    /// Conditional editor save. Both fields must be present on every chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
}

/// What an upload holds after the chunk: its size so far, or its final size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uploaded {
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// The destination changed; nothing was published and staging was discarded.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conflict: bool,
}

/// Payload of `mkdir` and `remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRequest {
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    pub from: String,
    pub to: String,
}

/// A ref of [`GitState`]: its name without the prefix, and the object it
/// names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRef {
    pub name: String,
    pub oid: String,
}

/// Result of `git_state`. `head` is the branch HEAD is on (none when
/// detached), `head_oid` its commit (none before the first commit);
/// `branches` are `refs/heads/*` and `tracking` `refs/remotes/omm/*`, each by
/// name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState {
    pub head: Option<String>,
    pub head_oid: Option<String>,
    pub branches: Vec<GitRef>,
    pub tracking: Vec<GitRef>,
}

/// Payload of `bundle_out`: the commit to send, and commits the receiver
/// has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleOut {
    pub commit: String,
    pub basis: Vec<String>,
}

/// A staged bundle: its id (`b-` and 32 hex digits) and its size so far
/// (or in all).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle: String,
    pub size: u64,
}

/// Payload of `bundle_read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRead {
    pub bundle: String,
    pub offset: u64,
}

/// One chunk of a staged bundle: at most [`BUNDLE_CHUNK_BYTES`] from the
/// requested offset; `size` is the whole bundle's. `next_offset` is `None`
/// on the last chunk, after which the bundle is gone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleChunk {
    pub data_base64: String,
    pub size: u64,
    pub next_offset: Option<u64>,
}

/// One chunk of a bundle the platform sends. Offset 0 without `bundle` starts
/// one; every later chunk names it and continues at the size the previous
/// answer gave. `last` completes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleWrite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    pub offset: u64,
    pub data_base64: String,
    pub last: bool,
}

/// Payload of `bundle_import`: the complete staged `bundle`, the branch whose
/// tracking ref it updates, and the commit that ref must then name. With `review`,
/// use `refs/omm/reviews/<branch>` instead of `refs/remotes/omm/<branch>`;
/// neither mode changes working files or local branches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleImport {
    pub bundle: String,
    pub branch: String,
    pub oid: String,
    /// Keep review snapshots outside ordinary remote branch tracking refs.
    #[serde(default)]
    pub review: bool,
}

/// Configure the fixed `omm` tracking remote without credentials or network access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRemote {
    pub url: String,
}

/// Populate a new repository from an already-fetched tracking branch, without replacing work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitInitialize {
    pub branch: String,
    pub oid: String,
}

/// Result of `bundle_import`: what the tracking ref names now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    pub oid: String,
}

const PROJECT_ACTIONS: &[(&str, EffectClass)] = &[
    (ACTION_LIST, EffectClass::Observation),
    (ACTION_CREATE, EffectClass::ReversibleMutation),
    (ACTION_STOP, EffectClass::Irreversible),
    (ACTION_BEGIN_ARCHIVE, EffectClass::ReversibleMutation),
    (ACTION_ARCHIVE, EffectClass::ReversibleMutation),
    (ACTION_UNARCHIVE, EffectClass::ReversibleMutation),
    (ACTION_DELETE, EffectClass::Irreversible),
    (ACTION_PURGE, EffectClass::Irreversible),
];

const FILE_ACTIONS: &[(&str, EffectClass)] = &[
    (ACTION_LIST, EffectClass::Observation),
    (ACTION_DOWNLOAD, EffectClass::Observation),
    (ACTION_UPLOAD, EffectClass::Irreversible),
    (ACTION_MKDIR, EffectClass::ReversibleMutation),
    (ACTION_RENAME, EffectClass::ReversibleMutation),
    (ACTION_REMOVE, EffectClass::Irreversible),
    (ACTION_GIT_STATE, EffectClass::Observation),
    (ACTION_GIT_REMOTE, EffectClass::ReversibleMutation),
    (ACTION_GIT_INITIALIZE, EffectClass::ReversibleMutation),
    (ACTION_BUNDLE_OUT, EffectClass::ReversibleMutation),
    (ACTION_BUNDLE_READ, EffectClass::Observation),
    (ACTION_BUNDLE_WRITE, EffectClass::ReversibleMutation),
    (ACTION_BUNDLE_IMPORT, EffectClass::ReversibleMutation),
];

const HOST_ACTIONS: &[(&str, EffectClass)] =
    &[(ACTION_INIT, EffectClass::ReversibleMutation), (ACTION_DELETE, EffectClass::Irreversible)];

fn declare<'a>(
    endpoint: EndpointName,
    actions: impl IntoIterator<Item = &'a (&'a str, EffectClass)>,
) -> Result<InterfaceDecl, Error> {
    Ok(InterfaceDecl {
        endpoint,
        version: VERSION,
        description: String::new(),
        actions: actions
            .into_iter()
            .map(|(action, effect)| Ok((ActionName::new(*action)?, ActionDecl::internal(*effect))))
            .collect::<Result<BTreeMap<_, _>, Error>>()?,
    })
}

/// The `projects` interface under `endpoint`. No action is a tool.
pub fn projects_interface(endpoint: EndpointName) -> Result<InterfaceDecl, Error> {
    declare(endpoint, PROJECT_ACTIONS)
}

/// The `files` interface under `endpoint`. No action is a tool.
pub fn files_interface(endpoint: EndpointName) -> Result<InterfaceDecl, Error> {
    declare(endpoint, FILE_ACTIONS)
}

/// The project host's one endpoint: the folder, repository and files of its
/// project.
pub fn host_interface(endpoint: EndpointName) -> Result<InterfaceDecl, Error> {
    declare(endpoint, HOST_ACTIONS.iter().chain(FILE_ACTIONS))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn directory_entry_creation_time_is_optional_on_the_wire() {
        use nucleus_protocol::Payload;

        // Existing runtimes send no created field; existing consumers ignore
        // the optional field sent by a newer host.
        #[derive(Serialize, Deserialize)]
        struct PreviousEntry {
            name: String,
            kind: Kind,
            size: u64,
            modified: u64,
        }
        let previous =
            PreviousEntry { name: "proof.lean".into(), kind: Kind::File, size: 12, modified: 1234 };
        let old_payload = Payload::encode(&previous).unwrap();
        let mut entry: Entry = old_payload.decode().unwrap();
        assert_eq!(entry.created, None);
        assert_eq!(Payload::encode(&entry).unwrap(), old_payload, "a missing value stays absent");
        entry.created = Some(1000);
        let payload = Payload::encode(&entry).unwrap();
        assert_eq!(payload.decode::<Entry>().unwrap(), entry);
        assert_eq!(payload.decode::<PreviousEntry>().unwrap().modified, previous.modified);
    }

    /// A dir id and its resources name the same directory every way; nothing
    /// outside the grammar parses, so no id names a path that leaves the
    /// projects root or reaches another project.
    #[test]
    fn dir_ids_and_resources_name_one_directory_each() {
        for (id, path) in [("p", "repo"), ("p-1", "repo")] {
            let dir = Dir::parse(id).unwrap();
            assert_eq!((dir.id(), dir.path()), (id.to_owned(), path.to_owned()));
            assert_eq!(dir.resource().segments().join("/"), format!("projects/{}/{path}", dir.project()));
            assert_eq!(Dir::from_resource(&dir.resource()).unwrap(), dir);
            let home_relative = ResourcePath::new(dir.in_home()).unwrap();
            assert_eq!(Dir::from_home_resource(dir.project(), &home_relative).unwrap(), dir);
            assert_eq!(project_of(&dir.resource()).unwrap(), dir.project());
        }
        for bad in ["", "P", "-p", "p_", "_w", "p_w", "p_w_x", "p.w", "p/w", "..", "p_..", &"a".repeat(41)] {
            assert!(Dir::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Project::named("p").unwrap().dir, "p");
        for bad in [
            vec!["projects", "p"],
            vec!["projects", "p", "repo", "src"],
            vec!["projects", "P", "repo"],
            vec!["chat", "p", "repo"],
        ] {
            let resource = ResourcePath::new(bad.clone()).unwrap();
            assert!(Dir::from_resource(&resource).is_err(), "{bad:?}");
        }
        assert!(project_of(&ResourcePath::new(["projects"]).unwrap()).is_err());
        assert!(segments("a/../b").is_err() && segments("/a").is_err() && segments("a//b").is_err());
        assert_eq!(segments("a/b c/é").unwrap(), ["a", "b c", "é"]);
    }

    /// Every branch name these actions take is one git takes and none reads
    /// as an option.
    #[test]
    fn branch_names_are_plain_git_ref_names() {
        for good in ["main", "feature/x-1", "v1.2_rc", "a/b/c", "@"] {
            assert!(valid_branch(good), "{good:?}");
        }
        let long = "a/".repeat(150) + "end";
        assert!(valid_branch(&long) && valid_branch("feature/café"));
        for bad in [
            "", "-x", "/x", ".x", "x/", "x.", "x.lock", "a..b", "a//b", "a@{1}", "a/.b", "a b", "x.lock/y",
            "a~1", "a^", "a:b",
        ] {
            assert!(!valid_branch(bad), "{bad:?}");
        }
        assert!(valid_oid(&"0a".repeat(20)) && !valid_oid(&"0A".repeat(20)) && !valid_oid("0a"));
    }
}
