//! Deletion authority is a receipt for an object we created, not a torrent path.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub index: usize,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ownership {
    pub token: String,
    pub files: Vec<Claim>,
}

/// The ledger's format. A newer one than this build knows is read as "keep everything".
const LEDGER_VERSION: u32 = 2;

/// Volume or device, file index or inode, and creation time (see `win32.rs`, `unix.rs`).
pub type Identity = [u64; 5];

/// Which object each handed-over file is, for the files whose filesystem tells.
pub fn identities(
    files: &[mdm_torrent::authorized_storage::PreparedFile],
) -> Vec<(usize, Identity)> {
    files
        .iter()
        .filter_map(|f| identity(&f.file).ok().map(|id| (f.index, id)))
        .collect()
}

/// Whether a file now at a torrent's path is another object than the one the engine holds:
/// only files both sides can identify are compared.
pub fn swapped(held: &[(usize, Identity)], now: &[(usize, Identity)]) -> bool {
    now.iter()
        .any(|(i, id)| held.iter().any(|(j, was)| i == j && was != id))
}

/// The object shown in the existing-files question, captured before consent.
#[derive(Clone, Debug)]
pub struct Consent {
    path: PathBuf,
    identity: Option<Identity>,
}

pub fn consent_for(paths: &[PathBuf]) -> Vec<Consent> {
    paths
        .iter()
        .map(|path| Consent {
            path: key(path),
            identity: identity_at(path).ok(),
        })
        .collect()
}

#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    token: String,
    /// Files MDM never deletes: present when the torrent was added (the person agreed to use
    /// them), or whose identity could not be had.
    #[serde(default)]
    protected: Vec<usize>,
    /// Permission to reuse a particular pre-existing object, independently of deletion.
    #[serde(default)]
    consented: Vec<Receipt>,
    #[serde(default)]
    files: Vec<Receipt>,
    #[serde(default)]
    directories: Vec<Receipt>,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    index: usize,
    path: PathBuf,
    identity: Identity,
}

#[cfg(unix)]
use crate::unix::{
    remove_owned_torrent_file, torrent_file_identity as identity,
    torrent_file_identity_at as identity_at,
};
#[cfg(windows)]
use crate::win32::{
    remove_owned_torrent_file, torrent_file_identity as identity,
    torrent_file_identity_at as identity_at,
};

/// Resolve existing ancestors too, so aliases and case differences cannot evade a claim.
pub fn key(path: &Path) -> PathBuf {
    let mut ancestor = path.to_owned();
    let mut tail = Vec::new();
    while !ancestor.exists() {
        let Some(name) = ancestor.file_name().map(|s| s.to_owned()) else {
            break;
        };
        tail.push(name);
        if !ancestor.pop() {
            break;
        }
    }
    let mut resolved = ancestor.canonicalize().unwrap_or(ancestor);
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        resolved = PathBuf::from(resolved.to_string_lossy().to_lowercase());
    }
    resolved
}

fn claimed(set: &BTreeSet<PathBuf>, path: &Path) -> bool {
    path.ancestors().any(|p| set.contains(p))
        || set
            .range(path.to_owned()..)
            .next()
            .is_some_and(|p| p.starts_with(path))
}

/// The drive or mount a path is on, for comparing without touching the disk. On Windows the
/// drive; elsewhere every path starts at `/`, so the mount's own folder stands for it: the one
/// under `/mnt`, `/media/<user>`, `/run/media/<user>` or `/Volumes`, where disks that sleep or
/// leave are mounted. Anything else is the main disk.
fn root_of(path: &Path) -> Option<String> {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    #[cfg(windows)]
    {
        parts.into_iter().next()
    }
    #[cfg(not(windows))]
    {
        let at = |i: usize| parts.get(i).map(String::as_str);
        let depth = match (at(1), at(2)) {
            (Some("mnt" | "volumes"), _) => 3,
            (Some("media"), _) => 4,
            (Some("run"), Some("media")) => 5,
            _ => 1,
        };
        Some(parts.into_iter().take(depth).collect::<Vec<_>>().join("/"))
    }
}

pub fn conflicts(paths: &[PathBuf], claims: &[PathBuf], canonical: bool) -> Vec<PathBuf> {
    let normalize = |path: &PathBuf| {
        if canonical {
            return key(path);
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            PathBuf::from(path.to_string_lossy().to_lowercase())
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            path.clone()
        }
    };
    // Looking at a claim means opening it: leave alone those on another drive than any of the
    // paths asked about, so a sleeping USB stick or a network share is not woken for nothing.
    let roots: std::collections::HashSet<_> = paths.iter().filter_map(|p| root_of(p)).collect();
    let near: Vec<&PathBuf> = claims
        .iter()
        .filter(|c| !canonical || root_of(c).is_some_and(|r| roots.contains(&r)))
        .collect();
    let set: BTreeSet<_> = near.iter().map(|p| normalize(p)).collect();
    let identities: std::collections::HashSet<_> = if canonical {
        near.iter().filter_map(|p| identity_at(p).ok()).collect()
    } else {
        Default::default()
    };
    paths
        .iter()
        .filter(|p| {
            claimed(&set, &normalize(p))
                || (canonical && identity_at(p).is_ok_and(|id| identities.contains(&id)))
        })
        .cloned()
        .collect()
}

impl Ownership {
    pub fn validate(&self, bytes: &[u8], hash: &str) -> io::Result<()> {
        let meta = mdm_torrent::librqbit::torrent_from_bytes(bytes).map_err(io::Error::other)?;
        let files = mdm_torrent::files_from_bytes(bytes).map_err(io::Error::other)?;
        let count = files.iter().filter(|f| !f.padding).count();
        if !meta.info_hash.as_string().eq_ignore_ascii_case(hash)
            || count != self.files.len()
            || self.files.iter().any(|claim| {
                files
                    .get(claim.index)
                    .is_none_or(|f| f.padding || (count != 1 && f.path != claim.path))
            })
        {
            return Err(io::Error::other(crate::i18n::t(
                // i18n: error when the saved record of a torrent's files differs from the .torrent file
                "The torrent ownership record does not match its file list",
            )));
        }
        Ok(())
    }
    pub fn new(meta: &mdm_torrent::Meta) -> Self {
        Self {
            token: mdm_ipc::random_token(),
            files: meta
                .files
                .iter()
                .enumerate()
                .filter(|(_, f)| !f.padding)
                .map(|(index, f)| Claim {
                    index,
                    path: f.path.clone(),
                })
                .collect(),
        }
    }

    /// An older row or lost ledger has no deletion authority. A stable recovery
    /// token permits fresh user consent to survive another restart without guessing ownership.
    pub fn recover(bytes: &[u8], hash: &str) -> io::Result<Self> {
        if hash.len() != 40 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            token: format!("{hash:0<64}").to_lowercase(),
            files: mdm_torrent::files_from_bytes(bytes)
                .map_err(io::Error::other)?
                .into_iter()
                .enumerate()
                .filter(|(_, f)| !f.padding)
                .map(|(index, f)| Claim {
                    index,
                    path: f.path,
                })
                .collect(),
        })
    }

    pub fn paths(&self, folder: &Path, dest: &Path) -> Vec<PathBuf> {
        self.files
            .iter()
            .map(|f| {
                if self.files.len() == 1 {
                    dest.to_owned()
                } else {
                    folder.join(&f.path)
                }
            })
            .collect()
    }

    fn ledger_path(&self, data: &Path) -> PathBuf {
        data.join("ownership").join(format!("{}.json", self.token))
    }

    pub fn forget(&self, data: &Path) -> io::Result<()> {
        self.check_token()?;
        match std::fs::remove_file(self.ledger_path(data)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn initialize(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        existing: &[Consent],
    ) -> io::Result<()> {
        let paths = self.paths(folder, dest);
        let mut protected = Vec::new();
        let mut consented = Vec::new();
        for (file, path) in self.files.iter().zip(paths) {
            let consent = existing.iter().find(|c| c.path == key(&path));
            if path.symlink_metadata().is_ok() || consent.is_some() {
                protected.push(file.index);
                if let Some(id) = consent.and_then(|c| c.identity) {
                    consented.push(Receipt {
                        index: file.index,
                        path: file.path.clone(),
                        identity: id,
                    });
                }
            }
        }
        self.save(
            data,
            &Ledger {
                version: LEDGER_VERSION,
                token: self.token.clone(),
                protected,
                consented,
                ..Default::default()
            },
        )
    }

    /// What the ledger says. A ledger that is missing (a crash between saving the list and
    /// writing it, a list restored without its `ownership` folder), unreadable, from a newer
    /// version or for another token proves nothing, so every file is kept and the download
    /// still starts and finishes.
    fn load(&self, data: &Path) -> io::Result<Ledger> {
        self.check_token()?;
        let keep_everything = || Ledger {
            version: LEDGER_VERSION,
            token: self.token.clone(),
            protected: self.files.iter().map(|f| f.index).collect(),
            ..Default::default()
        };
        let bytes = match std::fs::read(self.ledger_path(data)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(keep_everything()),
            Err(e) => return Err(e),
        };
        Ok(match serde_json::from_slice::<Ledger>(&bytes) {
            Ok(ledger) if ledger.token == self.token && ledger.version == LEDGER_VERSION => ledger,
            _ => keep_everything(),
        })
    }

    fn save(&self, data: &Path, ledger: &Ledger) -> io::Result<()> {
        self.check_token()?;
        let path = self.ledger_path(data);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let bytes = serde_json::to_vec(ledger).map_err(io::Error::other)?;
        // Nothing changed: no rewrite and no flush (a start of a big torrent saves its record
        // each time).
        if std::fs::read(&path).is_ok_and(|old| old == bytes) {
            return Ok(());
        }
        let temp = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temp, path)
    }

    fn check_token(&self) -> io::Result<()> {
        if self.token.len() != 64 || !self.token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(io::Error::other(crate::i18n::t(
                // i18n: error when the saved record of a torrent's files cannot be read as one
                "The torrent ownership record is invalid",
            )));
        }
        Ok(())
    }

    /// Make every file of the torrent ours before the engine gets the storage: each one is
    /// created here, empty, with `create_new`, and its identity recorded. The engine opens
    /// whatever is at a path for writing and sets its length, so a file that is neither ours
    /// nor agreed to at Add (one saved there since, or replaced while the torrent was stopped)
    /// stops the start: it would be cut and filled with torrent data. Unticked files count:
    /// the engine opens them too and writes the parts of pieces they share.
    pub fn prepare(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
    ) -> io::Result<Vec<mdm_torrent::authorized_storage::PreparedFile>> {
        self.prepare_consented(data, folder, dest, Vec::new())
    }

    /// Fresh consent transfers the exact open objects shown in the question. The engine
    /// receives these handles, not permission to reopen whatever later occupies their names.
    pub fn prepare_consented(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        fresh: Vec<mdm_torrent::authorized_storage::PreparedFile>,
    ) -> io::Result<Vec<mdm_torrent::authorized_storage::PreparedFile>> {
        use mdm_torrent::authorized_storage::PreparedFile;
        use std::collections::{HashMap, HashSet};
        let mut ledger = self.load(data)?;
        let mut opened = Vec::new();
        // What the ledger already says, looked up by file, and what this start adds to it:
        // a torrent of 50 000 files must not cost a scan of the ledger for each of them.
        let mut owned: HashMap<usize, Vec<Identity>> = HashMap::new();
        for r in ledger.files.iter().chain(&ledger.consented) {
            owned.entry(r.index).or_default().push(r.identity);
        }
        let mut protected: HashSet<usize> = ledger.protected.iter().copied().collect();
        let mut new_files: Vec<Receipt> = Vec::new();
        let mut new_consented: Vec<Receipt> = Vec::new();
        let mut new_protected: Vec<usize> = Vec::new();
        let mut new_directories: Vec<Receipt> = Vec::new();
        // Files whose earlier receipts a fresh agreement or a new object replaces.
        let mut reset: HashSet<usize> = HashSet::new();
        let result = (|| {
            let mut paths = Vec::new();
            // Validate every path before opening or allocating anything, even unticked and
            // deletion-protected entries. The engine opens every non-padding file.
            for claim in &self.files {
                mdm_torrent::check_relative_path(&claim.path).map_err(|_| {
                    io::Error::other(crate::i18n::t(
                        // i18n: unsafe path found in a saved torrent ownership record
                        "The torrent ownership record contains an unsafe path",
                    ))
                })?;
                let path = if self.files.len() == 1 {
                    dest.to_owned()
                } else {
                    folder.join(&claim.path)
                };
                if self.files.len() != 1 && !key(path.parent().unwrap()).starts_with(key(folder)) {
                    return Err(io::Error::other(crate::i18n::t(
                        // i18n: a torrent's folder is a link or junction leading outside its destination
                        "A torrent file's folder points outside its destination",
                    )));
                }
                paths.push(path);
            }
            let mut fresh: HashMap<_, _> = fresh.into_iter().map(|f| (f.index, f)).collect();
            let mut missing = Vec::new();
            let mut unknown = Vec::new();
            for (claim, path) in self.files.iter().zip(paths) {
                if let Some(file) = fresh.remove(&claim.index) {
                    if file.path != path {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    if protected.insert(claim.index) {
                        new_protected.push(claim.index);
                    }
                    // The object the person agreed to, replacing what was recorded for it.
                    owned.remove(&claim.index);
                    reset.insert(claim.index);
                    if let Ok(id) = identity(&file.file) {
                        owned.entry(claim.index).or_default().push(id);
                        new_consented.push(Receipt {
                            index: claim.index,
                            path: claim.path.clone(),
                            identity: id,
                        });
                    }
                    opened.push(file);
                    continue;
                }
                match path.symlink_metadata() {
                    Ok(metadata) => {
                        if !metadata.is_file() || metadata.file_type().is_symlink() {
                            return Err(io::ErrorKind::InvalidInput.into());
                        }
                        // Open without create/truncate/set_len, then identify this handle.
                        // A name replacement before open cannot borrow the old object's grant.
                        let file = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)?;
                        let id = identity(&file).ok();
                        let allowed = id.is_some_and(|id| {
                            owned.get(&claim.index).is_some_and(|ids| ids.contains(&id))
                        });
                        let file = PreparedFile {
                            index: claim.index,
                            path,
                            file,
                        };
                        // An empty file holds nothing the torrent could cut or overwrite (a
                        // placeholder, or one MDM made before it could record it), so it is
                        // used without asking. It stays the person's: it is never deleted.
                        let empty = !allowed && file.file.metadata().is_ok_and(|m| m.len() == 0);
                        if empty {
                            if protected.insert(claim.index) {
                                new_protected.push(claim.index);
                            }
                            owned.remove(&claim.index);
                            reset.insert(claim.index);
                            if let Some(id) = id {
                                owned.entry(claim.index).or_default().push(id);
                                new_consented.push(Receipt {
                                    index: claim.index,
                                    path: claim.path.clone(),
                                    identity: id,
                                });
                            }
                            opened.push(file);
                        } else if allowed {
                            opened.push(file);
                        } else {
                            unknown.push(file);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push((claim, path)),
                    Err(e) => return Err(e),
                }
            }
            if !fresh.is_empty() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if !unknown.is_empty() {
                return Err(consent_error(unknown));
            }
            // No foreign file remains unchecked. Allocate only with create_new; an object
            // winning this race needs its own consent, never a silent overwrite.
            for (claim, path) in missing {
                if self.files.len() != 1 && !key(path.parent().unwrap()).starts_with(key(folder)) {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                Self::mkdirs(folder, path.parent().unwrap(), &mut new_directories)?;
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => {
                        match identity(&file) {
                            Ok(id) => {
                                owned.entry(claim.index).or_default().push(id);
                                reset.insert(claim.index);
                                new_files.push(Receipt {
                                    index: claim.index,
                                    path: claim.path.clone(),
                                    identity: id,
                                });
                            }
                            Err(_) => {
                                // No identity on this filesystem: the file is never deleted
                                // by MDM, and each start asks before writing to it.
                                if protected.insert(claim.index) {
                                    new_protected.push(claim.index);
                                }
                            }
                        }
                        opened.push(PreparedFile {
                            index: claim.index,
                            path,
                            file,
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        let file = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)?;
                        return Err(consent_error(vec![PreparedFile {
                            index: claim.index,
                            path,
                            file,
                        }]));
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })();
        // What was made or agreed to is recorded even when the start stops after it, so that
        // deleting the torrent finds it.
        ledger.files.retain(|r| !reset.contains(&r.index));
        ledger.consented.retain(|r| !reset.contains(&r.index));
        ledger.files.extend(new_files);
        ledger.consented.extend(new_consented);
        ledger.protected.extend(new_protected);
        ledger.directories.extend(new_directories);
        self.save(data, &ledger)?;
        result.map(|()| opened)
    }

    fn mkdirs(root: &Path, path: &Path, made: &mut Vec<Receipt>) -> io::Result<()> {
        if path.exists() {
            return Ok(());
        }
        if path != root {
            let parent = path.parent().ok_or_else(|| {
                io::Error::other(crate::i18n::t(
                    // i18n: error when a torrent's output folder path cannot be used
                    "The output folder is invalid",
                ))
            })?;
            Self::mkdirs(root, parent, made)?;
        }
        match std::fs::create_dir(path) {
            Ok(()) => {
                if let Ok(id) = identity_at(path) {
                    made.push(Receipt {
                        index: usize::MAX,
                        path: path
                            .strip_prefix(root)
                            .map_err(io::Error::other)?
                            .to_owned(),
                        identity: id,
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Before MDM moves the files itself: which of them are still the objects it made or the
    /// person agreed to use (their identity matches the record). Only those may be re-recorded
    /// afterwards ([`Self::rebind`]): a file someone put in their place is not.
    pub fn verified(&self, data: &Path, folder: &Path, dest: &Path) -> io::Result<Vec<usize>> {
        let ledger = self.load(data)?;
        let mut ours = Vec::new();
        for (claim, path) in self.files.iter().zip(self.paths(folder, dest)) {
            let recorded = ledger
                .files
                .iter()
                .chain(&ledger.consented)
                .filter(|r| r.index == claim.index)
                .any(|r| {
                    path.symlink_metadata()
                        .is_ok_and(|m| m.file_type().is_file())
                        && identity_at(&path).ok() == Some(r.identity)
                });
            if recorded {
                ours.push(claim.index);
            }
        }
        Ok(ours)
    }

    /// MDM has moved the files itself. A copy to another drive and the original deleted give a
    /// file another volume and index, so the record would call MDM's own file a stranger's:
    /// record the identities the `verified` files have now, at their new place.
    pub fn rebind(
        &self,
        data: &Path,
        verified: &[usize],
        folder: &Path,
        dest: &Path,
    ) -> io::Result<()> {
        let mut ledger = self.load(data)?;
        let mut changed = false;
        for (claim, path) in self.files.iter().zip(self.paths(folder, dest)) {
            if !verified.contains(&claim.index)
                || !path
                    .symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_file())
            {
                continue;
            }
            let Ok(id) = identity_at(&path) else {
                continue;
            };
            for receipt in ledger
                .files
                .iter_mut()
                .chain(ledger.consented.iter_mut())
                .filter(|r| r.index == claim.index)
            {
                if receipt.identity != id {
                    receipt.identity = id;
                    changed = true;
                }
            }
        }
        if changed {
            self.save(data, &ledger)?;
        }
        Ok(())
    }

    /// Delete what this torrent made: the files whose identity still matches their receipt
    /// (all of the torrent's files were made here, ticked or not), then the folders it made,
    /// when empty. Anything else, and anything another download claims, stays.
    pub fn delete(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        keep_root: bool,
        protected: &[PathBuf],
    ) -> io::Result<()> {
        let ledger = self.load(data)?;
        let reserved: BTreeSet<_> = protected.iter().map(|p| key(p)).collect();
        let identities: std::collections::HashSet<_> = protected
            .iter()
            .filter_map(|p| identity_at(p).ok())
            .collect();
        let mut failure = None;
        let protected_files: std::collections::HashSet<usize> =
            ledger.protected.iter().copied().collect();
        for receipt in &ledger.files {
            if protected_files.contains(&receipt.index) {
                continue;
            }
            mdm_torrent::check_relative_path(&receipt.path).map_err(|_| {
                io::Error::other(crate::i18n::t(
                    // i18n: error when the saved record of a torrent's files holds a path that leaves its folder
                    "The torrent ownership record contains an unsafe path",
                ))
            })?;
            let path = if self.files.len() == 1 {
                dest.to_owned()
            } else {
                folder.join(&receipt.path)
            };
            if path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            if claimed(&reserved, &key(&path)) || identities.contains(&receipt.identity) {
                continue;
            }
            let Some(parent) = path.parent() else {
                continue;
            };
            if self.files.len() != 1 && !key(parent).starts_with(key(folder)) {
                continue;
            }
            match identity_at(&path) {
                Ok(id) if id == receipt.identity => {
                    if let Err(e) = remove_owned_torrent_file(&path, receipt.identity) {
                        failure.get_or_insert(e);
                    }
                }
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    failure.get_or_insert(e);
                }
                _ => {}
            }
        }
        let mut dirs: Vec<_> = ledger.directories.iter().collect();
        dirs.sort_by_key(|r| std::cmp::Reverse(r.path.components().count()));
        for receipt in dirs {
            if receipt.path.as_os_str().is_empty() && (keep_root || self.files.len() == 1) {
                continue;
            }
            if !receipt.path.as_os_str().is_empty()
                && mdm_torrent::check_relative_path(&receipt.path).is_err()
            {
                continue;
            }
            let path = folder.join(&receipt.path);
            if path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            if claimed(&reserved, &key(&path)) {
                continue;
            }
            if identity_at(&path).ok() == Some(receipt.identity) {
                match std::fs::remove_dir(path) {
                    Err(e)
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                        ) =>
                    {
                        failure.get_or_insert(e);
                    }
                    _ => {}
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[derive(Debug)]
struct ConsentRequired {
    files: Vec<mdm_torrent::authorized_storage::PreparedFile>,
}
impl std::fmt::Display for ConsentRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self
            .files
            .first()
            .map(|file| file.path.display().to_string())
            .unwrap_or_default();
        f.write_str(&crate::i18n::fmt(
            crate::i18n::t(
                // i18n: torrent start needs explicit write permission; {file} is the first existing file without a matching grant
                "This torrent needs permission to use {file} before it can start.",
            ),
            &[("file", &crate::i18n::isolate(&path))],
        ))
    }
}
impl std::error::Error for ConsentRequired {}
fn consent_error(files: Vec<mdm_torrent::authorized_storage::PreparedFile>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, ConsentRequired { files })
}
pub fn take_consent(
    error: io::Error,
) -> Result<Vec<mdm_torrent::authorized_storage::PreparedFile>, io::Error> {
    if error.get_ref().is_some_and(|e| e.is::<ConsentRequired>()) {
        Ok(error
            .into_inner()
            .unwrap()
            .downcast::<ConsentRequired>()
            .unwrap()
            .files)
    } else {
        Err(error)
    }
}

/// Delete a one-file torrent added before ownership records, as deleting a torrent always
/// did: its file, by name, when it is a plain file (not a link) inside the folder it was saved
/// to and no other download claims it. Nothing else is touched.
pub fn delete_single_file(folder: &Path, dest: &Path, protected: &[PathBuf]) -> io::Result<()> {
    let regular = dest
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_file());
    let inside = dest
        .parent()
        .is_some_and(|p| key(p).starts_with(key(folder)));
    let reserved: BTreeSet<_> = protected.iter().map(|p| key(p)).collect();
    if !regular || !inside || claimed(&reserved, &key(dest)) {
        return Ok(());
    }
    match std::fs::remove_file(dest) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Delete a torrent added before ownership records, which has its own outer folder (the one
/// MDM made for it): its files that are regular files in that folder, and the folders
/// that empty, as deleting a torrent always did. Links, other downloads' files and anything
/// that is not one of the torrent's stay.
pub fn delete_outer_folder(bytes: &[u8], folder: &Path, protected: &[PathBuf]) -> io::Result<()> {
    let files = mdm_torrent::files_from_bytes(bytes).map_err(io::Error::other)?;
    let reserved: BTreeSet<_> = protected.iter().map(|p| key(p)).collect();
    let root = key(folder);
    let mut dirs = BTreeSet::new();
    let mut failure = None;
    for file in files.iter().filter(|f| !f.padding) {
        if mdm_torrent::check_relative_path(&file.path).is_err() {
            continue;
        }
        let path = folder.join(&file.path);
        let regular = path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_file());
        let inside = path.parent().is_some_and(|p| key(p).starts_with(&root));
        if !regular || !inside || claimed(&reserved, &key(&path)) {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            failure.get_or_insert(e);
        }
        for dir in path.ancestors().skip(1) {
            dirs.insert(dir.to_owned());
            if dir == folder {
                break;
            }
        }
    }
    let mut dirs: Vec<_> = dirs.into_iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for dir in dirs {
        let linked = dir
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink());
        if linked || claimed(&reserved, &key(&dir)) {
            continue;
        }
        match std::fs::remove_dir(&dir) {
            Err(e)
                if !matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                failure.get_or_insert(e);
            }
            _ => {}
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(paths: &[&str]) -> Ownership {
        Ownership {
            token: mdm_ipc::random_token(),
            files: paths
                .iter()
                .enumerate()
                .map(|(index, path)| Claim {
                    index,
                    path: PathBuf::from(path),
                })
                .collect(),
        }
    }

    #[test]
    fn direct_preexisting_files_replaced_files_and_preexisting_directories_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(root.join("existing")).unwrap();
        std::fs::write(
            root.join("README.txt"),
            b"already here; user consented to reuse",
        )
        .unwrap();
        let own = owner(&["README.txt", "existing/a.bin", "unticked.txt", "new/b.bin"]);
        own.initialize(
            &data,
            &root,
            &root,
            &consent_for(&[root.join("README.txt")]),
        )
        .unwrap();
        own.prepare(&data, &root, &root).unwrap();
        // The person saves their own file over one of the torrent's (a new object).
        std::fs::rename(root.join("unticked.txt"), tmp.path().join("moved-away")).unwrap();
        std::fs::write(root.join("unticked.txt"), b"user put this here after Add").unwrap();
        own.delete(&data, &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"already here; user consented to reuse"
        );
        assert_eq!(
            std::fs::read(root.join("unticked.txt")).unwrap(),
            b"user put this here after Add"
        );
        assert!(root.join("existing").is_dir());
        assert!(!root.join("existing/a.bin").exists());
        assert!(!root.join("new").exists());
    }

    #[test]
    fn direct_owned_objects_claimed_by_another_download_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "Sample/a.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let protected = vec![root.join("README.txt"), root.join("Sample")];
        own.delete(tmp.path(), &root, &root, true, &protected)
            .unwrap();
        assert!(root.join("README.txt").is_file());
        assert!(root.join("Sample/a.bin").is_file());
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(!root.join("README.txt").exists());
        assert!(!root.join("Sample").exists());
        assert!(root.is_dir());
    }

    #[test]
    fn direct_replacement_file_is_not_the_object_the_torrent_created() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        std::fs::rename(root.join("README.txt"), root.join("old-object.txt")).unwrap();
        std::fs::write(root.join("README.txt"), b"user replacement").unwrap();
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"user replacement"
        );
        assert!(!root.join("b.bin").exists());
    }

    #[test]
    fn direct_single_file_delete_uses_current_dest_after_move_and_rename() {
        for move_to_another_folder in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("output");
            std::fs::create_dir(&root).unwrap();
            let own = owner(&["original.bin"]);
            let original = root.join("original.bin");
            own.initialize(tmp.path(), &root, &original, &[]).unwrap();
            own.prepare(tmp.path(), &root, &original).unwrap();
            let parent = if move_to_another_folder {
                tmp.path().join("moved")
            } else {
                root.clone()
            };
            std::fs::create_dir_all(&parent).unwrap();
            let current = parent.join("completion-name.bin");
            std::fs::rename(&original, &current).unwrap();
            std::fs::write(&original, b"not the torrent's file").unwrap();
            let reloaded: Ownership =
                serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
            reloaded
                .delete(tmp.path(), &root, &current, false, &[])
                .unwrap();
            assert!(!current.exists());
            assert_eq!(std::fs::read(&original).unwrap(), b"not the torrent's file");
            assert!(root.is_dir());
            assert!(parent.is_dir());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn direct_a_mount_is_told_from_the_main_disk_without_opening_anything() {
        let on = |p: &str| root_of(Path::new(p));
        assert_eq!(on("/home/a/Downloads/x"), on("/home/b/y"));
        assert_ne!(on("/mnt/usb/x"), on("/home/a/x"));
        assert_ne!(on("/mnt/usb/x"), on("/mnt/nas/x"));
        assert_eq!(on("/mnt/usb/a/x"), on("/mnt/usb/b/y"));
        assert_ne!(on("/media/me/disk1/x"), on("/media/me/disk2/x"));
        assert_ne!(on("/run/media/me/disk1/x"), on("/home/me/x"));
        assert_ne!(on("/Volumes/Backup/x"), on("/Users/me/x"));
    }

    #[test]
    fn direct_a_move_to_another_drive_is_recorded_so_mdms_own_file_is_not_a_stranger() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin"]);
        let there = root.join("a.bin");
        own.initialize(tmp.path(), &root, &there, &[]).unwrap();
        own.prepare(tmp.path(), &root, &there).unwrap();
        std::fs::write(&there, b"the finished download").unwrap();
        let ours = own.verified(tmp.path(), &root, &there).unwrap();
        assert_eq!(ours, vec![0]);
        // Move to another drive: a copy, then the original deleted. A new object.
        let moved = tmp.path().join("elsewhere");
        std::fs::create_dir(&moved).unwrap();
        let here = moved.join("a.bin");
        std::fs::copy(&there, &here).unwrap();
        std::fs::remove_file(&there).unwrap();
        // Unrecorded, the next start would ask about its own file (and delete would keep it).
        let error = own.prepare(tmp.path(), &moved, &here).unwrap_err();
        assert!(
            take_consent(error).is_ok(),
            "an unrecorded file is asked about"
        );
        own.rebind(tmp.path(), &ours, &moved, &here).unwrap();
        own.prepare(tmp.path(), &moved, &here)
            .expect("MDM's own moved file needs no question");
        own.delete(tmp.path(), &moved, &here, true, &[]).unwrap();
        assert!(!here.exists(), "and it is still the torrent's to delete");
    }

    #[test]
    fn direct_a_file_the_person_replaced_is_not_recorded_by_a_move() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        // One of them is replaced by the person's own file before the move.
        std::fs::rename(root.join("a.bin"), tmp.path().join("original")).unwrap();
        std::fs::write(root.join("a.bin"), b"the person's").unwrap();
        let ours = own.verified(tmp.path(), &root, &root).unwrap();
        assert_eq!(ours, vec![1], "only the file that is still MDM's");
        own.rebind(tmp.path(), &ours, &root, &root).unwrap();
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(root.join("a.bin").exists(), "the person's file stays");
        assert!(!root.join("b.bin").exists());
    }

    #[test]
    fn direct_a_second_start_does_not_rewrite_an_unchanged_record() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin", "c.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let ledger = own.ledger_path(tmp.path());
        let first = std::fs::metadata(&ledger).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        own.prepare(tmp.path(), &root, &root).unwrap();
        assert_eq!(
            std::fs::metadata(&ledger).unwrap().modified().unwrap(),
            first
        );
    }

    #[test]
    fn direct_an_older_one_file_download_goes_by_name_inside_its_folder_only() {
        let tmp = tempfile::tempdir().unwrap();
        let folder = tmp.path().join("Downloads");
        std::fs::create_dir(&folder).unwrap();
        let file = folder.join("movie.mkv");
        // Inside its folder, a plain file, claimed by no one: gone.
        std::fs::write(&file, b"movie").unwrap();
        delete_single_file(&folder, &file, &[]).unwrap();
        assert!(!file.exists());
        // Claimed by another download: stays.
        std::fs::write(&file, b"movie").unwrap();
        delete_single_file(&folder, &file, std::slice::from_ref(&file)).unwrap();
        assert!(file.exists());
        // A path that leads out of the folder it was saved to: stays.
        let outside = tmp.path().join("elsewhere.mkv");
        std::fs::write(&outside, b"not in the folder").unwrap();
        delete_single_file(&folder, &outside, &[]).unwrap();
        assert!(outside.exists());
        // A folder with that name is no file: stays.
        let dir = folder.join("a-folder.mkv");
        std::fs::create_dir(&dir).unwrap();
        delete_single_file(&folder, &dir, &[]).unwrap();
        assert!(dir.is_dir());
        // Already gone is not a failure.
        std::fs::remove_file(&file).unwrap();
        delete_single_file(&folder, &file, &[]).unwrap();
    }

    #[test]
    fn direct_file_appearing_while_queued_is_never_written_to() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("README.txt"), b"arrived after Later").unwrap();
        // The engine would open it, cut it to the torrent's size and fill it: the start stops.
        let error = own.prepare(tmp.path(), &root, &root).unwrap_err();
        assert!(error.to_string().contains("README.txt"), "{error}");
        assert!(!root.join("b.bin").exists(), "nothing else is set up");
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"arrived after Later"
        );
    }

    #[test]
    fn direct_add_time_consent_does_not_follow_a_replacement_filename() {
        for before_initialization in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("output");
            std::fs::create_dir(&root).unwrap();
            let path = root.join("README.txt");
            std::fs::write(&path, b"the file shown in the consent question").unwrap();
            let consent = consent_for(std::slice::from_ref(&path));
            let own = owner(&["README.txt", "another.bin"]);
            if !before_initialization {
                own.initialize(tmp.path(), &root, &root, &consent).unwrap();
            }
            std::fs::rename(&path, root.join("original-object")).unwrap();
            let replacement = b"a different user file, never consented to";
            std::fs::write(&path, replacement).unwrap();
            if before_initialization {
                own.initialize(tmp.path(), &root, &root, &consent).unwrap();
            }
            assert!(own.prepare(tmp.path(), &root, &root).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), replacement);
            assert!(!root.join("another.bin").exists());
            own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
            assert_eq!(std::fs::read(path).unwrap(), replacement);
        }
    }

    #[test]
    fn direct_ownership_and_created_directory_receipts_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("owned-root");
        let own = owner(&["a.bin", "nested/b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, false, &[])
            .unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn direct_queued_claims_cover_internal_paths_and_file_directory_prefixes() {
        let tmp = tempfile::tempdir().unwrap();
        let claimed_paths = vec![
            tmp.path().join("README.txt"),
            tmp.path().join("Sample/a.bin"),
        ];
        let candidates = vec![
            tmp.path().join("README.txt"),
            tmp.path().join("Sample"),
            tmp.path().join("free.bin"),
        ];
        assert_eq!(
            conflicts(&candidates, &claimed_paths, true),
            candidates[..2]
        );
        #[cfg(windows)]
        assert_eq!(
            conflicts(&[tmp.path().join("readme.TXT")], &claimed_paths, false).len(),
            1
        );
    }

    #[test]
    fn direct_ownership_rejects_escaping_paths_and_invalid_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["../outside.bin", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert!(!tmp.path().join("outside.bin").exists());
        let mut invalid = owner(&["a.bin"]);
        invalid.token = "../../escape".into();
        assert!(invalid.initialize(tmp.path(), &root, &root, &[]).is_err());
    }

    #[tokio::test]
    async fn direct_ownership_is_checked_against_the_saved_torrent_file_list_and_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.bin"), b"ownership a").unwrap();
        std::fs::write(source.join("nested/b.bin"), b"ownership b").unwrap();
        let spawner = mdm_torrent::librqbit::spawn_utils::BlockingSpawner::new(1);
        let made = mdm_torrent::librqbit::create_torrent(
            &source,
            mdm_torrent::librqbit::CreateTorrentOptions {
                name: Some("ownership-validation"),
                trackers: Vec::new(),
                piece_length: Some(16384),
            },
            &spawner,
        )
        .await
        .unwrap();
        let bytes = made.as_bytes().unwrap().to_vec();
        let hash = mdm_torrent::librqbit::torrent_from_bytes(&bytes)
            .unwrap()
            .info_hash
            .as_string();
        let mut own = Ownership {
            token: mdm_ipc::random_token(),
            files: mdm_torrent::files_from_bytes(&bytes)
                .unwrap()
                .into_iter()
                .enumerate()
                .map(|(index, f)| Claim {
                    index,
                    path: f.path,
                })
                .collect(),
        };
        own.validate(&bytes, &hash).unwrap();
        assert!(own.validate(&bytes, &"0".repeat(40)).is_err());
        own.files[0].path = "not-the-torrent.txt".into();
        assert!(own.validate(&bytes, &hash).is_err());
    }

    #[test]
    fn direct_refused_preparation_allocates_nothing_before_write_permission() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "later.txt"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("later.txt"), b"user file").unwrap();
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert!(!root.join("a.bin").exists());
        own.delete(tmp.path(), &root, &root, false, &[]).unwrap();
        assert!(!root.join("a.bin").exists());
        assert_eq!(std::fs::read(root.join("later.txt")).unwrap(), b"user file");
        assert!(root.is_dir(), "the pre-existing empty root is not owned");
    }

    #[test]
    fn direct_unticked_files_are_made_here_first_so_ticking_one_later_needs_no_guess() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["selected.bin", "unticked.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        assert!(root.join("unticked.bin").is_file());
        // The engine writes into what is there, without replacing it.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(root.join("unticked.bin"))
                .unwrap();
            f.write_all(b"part of a shared piece").unwrap();
        }
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, true, &[])
            .unwrap();
        assert!(!root.join("selected.bin").exists());
        assert!(!root.join("unticked.bin").exists(), "no empty leftovers");
    }

    #[test]
    fn direct_a_replaced_file_stops_the_start_and_is_never_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["edited.bin", "other.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let path = root.join("edited.bin");
        std::fs::rename(&path, tmp.path().join("original-object")).unwrap();
        std::fs::write(&path, b"saved by an editor").unwrap();
        // A resume would let the engine check its pieces against this file and rewrite it.
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"saved by an editor");
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(path.exists());
        assert!(!root.join("other.bin").exists());
    }

    #[test]
    fn direct_an_empty_file_is_used_without_asking_and_is_never_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        // A placeholder the person made, and a file with content.
        std::fs::write(root.join("a.bin"), b"").unwrap();
        std::fs::write(root.join("b.bin"), b"theirs").unwrap();
        let error = own.prepare(tmp.path(), &root, &root).unwrap_err();
        let asked = take_consent(error).unwrap();
        // Only the one with content is asked about.
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].index, 1);
        // Without the other one, the empty one alone starts, and again on the next start.
        std::fs::remove_file(root.join("b.bin")).unwrap();
        assert_eq!(own.prepare(tmp.path(), &root, &root).unwrap().len(), 2);
        assert_eq!(own.prepare(tmp.path(), &root, &root).unwrap().len(), 2);
        // It was the person's: deleting the torrent leaves it.
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(root.join("a.bin").exists());
        assert!(!root.join("b.bin").exists());
    }

    #[test]
    fn direct_a_swapped_file_is_told_from_the_one_the_engine_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        let held = identities(&own.prepare(tmp.path(), &root, &root).unwrap());
        assert_eq!(held.len(), 2);
        // The same file again: not swapped.
        assert!(!swapped(
            &held,
            &identities(&own.prepare(tmp.path(), &root, &root).unwrap())
        ));
        // Replaced by another object that is empty (so it is used without asking).
        let path = root.join("a.bin");
        std::fs::rename(&path, tmp.path().join("old")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, b"").unwrap();
        let now = identities(&own.prepare(tmp.path(), &root, &root).unwrap());
        assert!(swapped(&held, &now));
    }

    #[test]
    fn direct_damaged_ledger_recovers_without_granting_implicit_write_permission() {
        for damage in ["missing", "garbage", "newer", "other token"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("output");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("a.bin"), b"torrent data so far").unwrap();
            let own = owner(&["a.bin", "b.bin"]);
            own.initialize(tmp.path(), &root, &root, &[]).unwrap();
            let ledger = own.ledger_path(tmp.path());
            match damage {
                "missing" => std::fs::remove_file(&ledger).unwrap(),
                "garbage" => std::fs::write(&ledger, b"{not json").unwrap(),
                "newer" => std::fs::write(
                    &ledger,
                    format!(r#"{{"version":99,"token":"{}"}}"#, own.token),
                )
                .unwrap(),
                _ => std::fs::write(
                    &ledger,
                    format!(r#"{{"version":1,"token":"{}"}}"#, "0".repeat(64)),
                )
                .unwrap(),
            }
            let error = own.prepare(tmp.path(), &root, &root).unwrap_err();
            assert_eq!(
                std::fs::read(root.join("a.bin")).unwrap(),
                b"torrent data so far"
            );
            assert!(
                !root.join("b.bin").exists(),
                "refusal allocates nothing: {damage}"
            );
            let fresh = take_consent(error).unwrap();
            drop(
                own.prepare_consented(tmp.path(), &root, &root, fresh)
                    .unwrap(),
            );
            own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
            assert!(root.join("a.bin").exists(), "{damage}");
        }
    }

    #[test]
    fn direct_weak_ledger_migrates_to_protection_without_write_consent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin"]);
        std::fs::write(root.join("b.bin"), b"user's data").unwrap();
        std::fs::create_dir_all(tmp.path().join("ownership")).unwrap();
        std::fs::write(
            own.ledger_path(tmp.path()),
            format!(r#"{{"token":"{}","protected":[1]}}"#, own.token),
        )
        .unwrap();
        let error = own.prepare(tmp.path(), &root, &root).unwrap_err();
        assert!(!root.join("a.bin").exists());
        assert_eq!(std::fs::read(root.join("b.bin")).unwrap(), b"user's data");
        drop(
            own.prepare_consented(tmp.path(), &root, &root, take_consent(error).unwrap())
                .unwrap(),
        );
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(root.join("a.bin").exists());
        assert_eq!(std::fs::read(root.join("b.bin")).unwrap(), b"user's data");
    }

    #[test]
    fn direct_identity_has_a_creation_time_so_a_file_that_took_the_name_later_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cover.jpg");
        std::fs::write(&path, b"one").unwrap();
        let first = identity_at(&path).expect("this filesystem gives an identity");
        assert_ne!(first[3], 0, "a creation time is part of it");
        assert_eq!(identity_at(&path).unwrap(), first);
    }

    #[tokio::test]
    async fn direct_an_older_download_with_its_own_folder_still_deletes_its_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.bin"), b"ownership a").unwrap();
        std::fs::write(source.join("nested/b.bin"), b"ownership b").unwrap();
        let spawner = mdm_torrent::librqbit::spawn_utils::BlockingSpawner::new(1);
        let made = mdm_torrent::librqbit::create_torrent(
            &source,
            mdm_torrent::librqbit::CreateTorrentOptions {
                name: Some("Set"),
                trackers: Vec::new(),
                piece_length: Some(16384),
            },
            &spawner,
        )
        .await
        .unwrap();
        let bytes = made.as_bytes().unwrap().to_vec();
        let folder = tmp.path().join("Downloads/Set");
        std::fs::create_dir_all(folder.join("nested")).unwrap();
        std::fs::write(folder.join("a.bin"), b"torrent").unwrap();
        std::fs::write(folder.join("nested/b.bin"), b"torrent").unwrap();
        std::fs::write(folder.join("notes.txt"), b"the person's own note").unwrap();
        delete_outer_folder(&bytes, &folder, &[]).unwrap();
        assert!(!folder.join("a.bin").exists());
        assert!(!folder.join("nested").exists());
        assert_eq!(
            std::fs::read(folder.join("notes.txt")).unwrap(),
            b"the person's own note"
        );
        assert!(folder.is_dir(), "a folder with something else in it stays");
        // Another download's file stays too.
        std::fs::write(folder.join("a.bin"), b"claimed").unwrap();
        delete_outer_folder(&bytes, &folder, &[folder.join("a.bin")]).unwrap();
        assert!(folder.join("a.bin").exists());
    }
}
