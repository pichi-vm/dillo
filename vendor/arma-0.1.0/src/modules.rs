// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ModuleError(String);

pub(crate) fn validate_name(name: &str) -> Result<String, ModuleError> {
    static NAME: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = NAME.get_or_init(|| {
        regex::Regex::new(r"\A[A-Za-z0-9_][A-Za-z0-9_-]*\z").expect("constant ASCII regex")
    });
    if !pattern.is_match(name) {
        return Err(ModuleError(format!("invalid module name {name:?}")));
    }
    Ok(name.replace('-', "_"))
}

#[derive(Debug)]
pub(crate) struct Selection {
    pub(crate) tree: PathBuf,
    pub(crate) builtins: Vec<String>,
    pub(crate) files: Vec<ModuleFile>,
}

#[derive(Debug)]
pub(crate) struct ModuleFile {
    pub(crate) relative: PathBuf,
    pub(crate) bytes: Vec<u8>,
    pub(crate) is_root: bool,
}

impl ModuleFile {
    /// Slash-joined relative path for diagnostics and other POSIX consumers.
    ///
    /// `PathBuf` keeps host separators for filesystem work; this method always
    /// emits `/` so stderr and operator-facing paths match the Linux modules
    /// tree layout on every host, including Windows.
    pub(crate) fn posix_relative(&self) -> String {
        self.relative
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(part) => part.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// Resolve against a trusted, read-only module tree. These std filesystem checks
/// reject symlinks and escapes, but cannot prevent concurrent replacement (TOCTOU).
/// Both modules.dep and modules.builtin are mandatory; softdep/firmware/indexes
/// are intentionally not included or interpreted.
pub(crate) fn resolve(
    release: &str,
    tree_override: Option<&Path>,
    roots: &[String],
) -> Result<Selection, ModuleError> {
    validate_release(release)?;
    let roots = roots
        .iter()
        .map(|name| validate_name(name))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let tree = if let Some(tree) = tree_override {
        canonical_tree(tree)?
    } else {
        discover(
            release,
            &[
                PathBuf::from("/usr/lib/modules"),
                PathBuf::from("/lib/modules"),
            ],
        )?
    };
    let mut definitions = BTreeMap::new();
    let mut names = BTreeMap::new();
    for line in metadata(&tree, "modules.dep")?.lines() {
        if line.is_empty() {
            continue;
        }
        let (path, dependencies) = line
            .split_once(':')
            .ok_or_else(|| ModuleError(format!("malformed modules.dep line {line:?}")))?;
        let name = module_path(path)?;
        let mut edges = BTreeSet::new();
        for dependency in dependencies.split_ascii_whitespace() {
            module_path(dependency)?;
            if !edges.insert(dependency.to_owned()) {
                return Err(ModuleError(format!("duplicate dependency {dependency:?}")));
            }
        }
        if definitions.insert(path.to_owned(), edges).is_some() {
            return Err(ModuleError(format!("duplicate definition {path:?}")));
        }
        insert_name(&mut names, name, Some(path.to_owned()))?;
    }
    for line in metadata(&tree, "modules.builtin")?.lines() {
        if line.is_empty() {
            continue;
        }
        insert_name(&mut names, module_path(line)?, None)?;
    }
    // Validate the whole index, not only the chosen branch.
    for (path, dependencies) in &definitions {
        checked_file(&tree, path)?;
        for dependency in dependencies {
            if !definitions.contains_key(dependency) {
                return Err(ModuleError(format!(
                    "missing dependency definition {dependency:?} from {path:?}"
                )));
            }
        }
    }
    closure(&definitions, definitions.keys().cloned())?;
    let mut builtins = Vec::new();
    let mut selected = BTreeSet::new();
    for root in roots {
        match names.get(&root) {
            Some(Some(path)) => {
                selected.insert(path.clone());
            }
            Some(None) => builtins.push(root),
            None => return Err(ModuleError(format!("unknown module {root:?}"))),
        }
    }
    let files = closure(&definitions, selected.iter().cloned())?
        .into_iter()
        .map(|relative| {
            let bytes = read_file(&tree, &relative)?;
            Ok(ModuleFile {
                is_root: selected.contains(&relative),
                relative: posix_path(&relative),
                bytes,
            })
        })
        .collect::<Result<Vec<_>, ModuleError>>()?;
    Ok(Selection {
        tree,
        builtins,
        files,
    })
}

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
};

type Definitions = BTreeMap<String, BTreeSet<String>>;

fn validate_release(release: &str) -> Result<(), ModuleError> {
    crate::kernel_release::validate_component(release)
        .map_err(|error| ModuleError(format!("unsafe kernel release {release:?}: {error}")))
}

fn canonical_tree(tree: &Path) -> Result<PathBuf, ModuleError> {
    let canonical = tree.canonicalize().map_err(|error| io_error(tree, error))?;
    if !canonical.is_dir() {
        return Err(ModuleError(format!(
            "module tree is not a directory: {}",
            tree.display()
        )));
    }
    Ok(canonical)
}

fn discover(release: &str, roots: &[PathBuf]) -> Result<PathBuf, ModuleError> {
    validate_release(release)?;
    let mut candidates = BTreeSet::new();
    for root in roots {
        let path = root.join(release);
        match fs::metadata(&path) {
            Ok(_) => {
                candidates.insert(canonical_tree(&path)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&path, error)),
        }
    }
    if candidates.len() != 1 {
        return Err(ModuleError(format!(
            "expected one module tree for {release:?}, found {}: {candidates:?}",
            candidates.len()
        )));
    }
    Ok(candidates.pop_first().expect("one candidate"))
}

fn insert_name(
    names: &mut BTreeMap<String, Option<String>>,
    name: String,
    path: Option<String>,
) -> Result<(), ModuleError> {
    if names.insert(name.clone(), path).is_some() {
        return Err(ModuleError(format!("ambiguous module name {name:?}")));
    }
    Ok(())
}

fn module_path(path: &str) -> Result<String, ModuleError> {
    validate_path(path)?;
    let filename = path.rsplit('/').next().expect("nonempty path");
    let stem = [".ko", ".ko.xz", ".ko.gz", ".ko.zst"]
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))
        .ok_or_else(|| ModuleError(format!("unsupported module suffix {path:?}")))?;
    validate_name(stem)
}

fn validate_path(path: &str) -> Result<(), ModuleError> {
    if path.is_empty()
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part
                    .bytes()
                    .any(|byte| !byte.is_ascii_alphanumeric() && !b"._+-".contains(&byte))
        })
    {
        return Err(ModuleError(format!("unsafe POSIX module path {path:?}")));
    }
    Ok(())
}

fn posix_path(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn io_error(path: &Path, error: std::io::Error) -> ModuleError {
    ModuleError(format!("{}: {error}", path.display()))
}

fn checked_file(tree: &Path, relative: &str) -> Result<PathBuf, ModuleError> {
    validate_path(relative)?;
    let mut path = tree.to_owned();
    let components = relative.split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
        let expected = if index + 1 == components.len() {
            metadata.is_file()
        } else {
            metadata.is_dir()
        };
        if metadata.file_type().is_symlink() || !expected {
            return Err(ModuleError(format!(
                "symlink or nonregular module tree entry: {}",
                path.display()
            )));
        }
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| io_error(&path, error))?;
    if !canonical.starts_with(tree) {
        return Err(ModuleError(format!(
            "module path escapes tree: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn read_file(tree: &Path, relative: &str) -> Result<Vec<u8>, ModuleError> {
    let path = checked_file(tree, relative)?;
    let file = fs::File::open(&path).map_err(|error| io_error(&path, error))?;
    let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
    if !metadata.is_file() || metadata.len() > u64::from(u32::MAX) {
        return Err(ModuleError(format!(
            "not a regular newc-sized file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(u64::from(u32::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(&path, error))?;
    if u32::try_from(bytes.len()).is_err() {
        return Err(ModuleError(format!(
            "file exceeds newc size limit: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn metadata(tree: &Path, name: &str) -> Result<String, ModuleError> {
    String::from_utf8(read_file(tree, name)?)
        .map_err(|error| ModuleError(format!("invalid UTF-8 in {name}: {error}")))
}

fn closure(
    definitions: &Definitions,
    roots: impl Iterator<Item = String>,
) -> Result<BTreeSet<String>, ModuleError> {
    let mut done = BTreeSet::new();
    let mut active = BTreeSet::new();
    for root in roots {
        let mut stack = vec![(root, false)];
        while let Some((path, leaving)) = stack.pop() {
            if leaving {
                active.remove(&path);
                done.insert(path);
                continue;
            }
            if done.contains(&path) {
                continue;
            }
            if !active.insert(path.clone()) {
                return Err(ModuleError(format!("module dependency cycle at {path:?}")));
            }
            stack.push((path.clone(), true));
            for dependency in definitions[&path].iter().rev() {
                stack.push((dependency.clone(), false));
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dep: &str, builtin: &str, files: &[&str]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("modules.dep"), dep).unwrap();
        std::fs::write(temp.path().join("modules.builtin"), builtin).unwrap();
        for file in files {
            let path = temp.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"\0module\xff").unwrap();
        }
        temp
    }

    fn select(tree: &Path, names: &[&str]) -> Result<Selection, ModuleError> {
        resolve(
            "6.12-test+local",
            Some(tree),
            &names.iter().map(ToString::to_string).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn selects_sorted_transitive_closure_and_builtins_without_indexes() {
        let tree = fixture(
            "kernel/root-mod.ko.xz: kernel/z.ko.gz kernel/a.ko.zst\nkernel/z.ko.gz: kernel/a.ko.zst\nkernel/a.ko.zst:\n",
            "kernel/built-in.ko\n",
            &["kernel/root-mod.ko.xz", "kernel/z.ko.gz", "kernel/a.ko.zst"],
        );
        let result = select(tree.path(), &["root_mod", "built-in", "root-mod"]).unwrap();
        assert_eq!(result.tree, tree.path().canonicalize().unwrap());
        assert_eq!(result.builtins, ["built_in"]);
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| file.relative.clone())
                .collect::<Vec<_>>(),
            ["kernel/a.ko.zst", "kernel/root-mod.ko.xz", "kernel/z.ko.gz"].map(PathBuf::from)
        );
        assert!(
            result
                .files
                .iter()
                .all(|file| file.bytes == b"\0module\xff")
        );
    }

    #[test]
    fn preserves_root_identity_through_dependency_closure() {
        let tree = fixture(
            "kernel/root-mod.ko.xz: kernel/helper.ko.gz\nkernel/helper.ko.gz:\n",
            "kernel/built-in.ko\n",
            &["kernel/root-mod.ko.xz", "kernel/helper.ko.gz"],
        );
        let result = select(tree.path(), &["root_mod", "built-in"]).unwrap();
        assert_eq!(result.builtins, ["built_in"]);
        assert_eq!(
            result
                .files
                .iter()
                .map(|file| (file.relative.as_path(), file.is_root))
                .collect::<Vec<_>>(),
            [
                (Path::new("kernel/helper.ko.gz"), false),
                (Path::new("kernel/root-mod.ko.xz"), true),
            ]
        );
        // A dependency explicitly requested as a root retains that role.
        let result = select(tree.path(), &["root-mod", "helper", "root_mod"]).unwrap();
        assert!(result.files.iter().all(|file| file.is_root));
    }

    #[test]
    fn rejects_broken_or_ambiguous_indexes() {
        for (dep, builtin, files) in [
            ("a.ko: b.ko\n", "", vec!["a.ko", "b.ko"]),
            ("a.ko:\n", "", vec![]),
            ("a.ko: b.ko\nb.ko: a.ko\n", "", vec!["a.ko", "b.ko"]),
            ("a.ko: a.ko\n", "", vec!["a.ko"]),
            ("a.ko: b.ko b.ko\nb.ko:\n", "", vec!["a.ko", "b.ko"]),
            ("a.ko:\na.ko:\n", "", vec!["a.ko"]),
            ("a.ko:\na.ko: b.ko\nb.ko:\n", "", vec!["a.ko", "b.ko"]),
            ("x/a-b.ko:\ny/a_b.ko:\n", "", vec!["x/a-b.ko", "y/a_b.ko"]),
            ("a.ko:\n", "kernel/a.ko\n", vec!["a.ko"]),
            ("", "x/a.ko\ny/a.ko\n", vec![]),
            ("a.ko\n", "", vec!["a.ko"]),
            ("a.ko::\n", "", vec!["a.ko"]),
            (" \n", "", vec![]),
            ("a.ko:\n", "a.ko parameter\n", vec!["a.ko"]),
        ] {
            let tree = fixture(dep, builtin, &files);
            assert!(select(tree.path(), &["a"]).is_err(), "{dep:?}, {builtin:?}");
        }
        let tree = fixture("a.ko:\n", "", &["a.ko"]);
        assert!(select(tree.path(), &["missing"]).is_err());
        for name in ["a.ko", "a\n", "-a"] {
            assert!(select(tree.path(), &[name]).is_err());
        }
    }

    #[test]
    fn rejects_unsafe_paths_on_every_platform() {
        for path in [
            "/a.ko",
            "../a.ko",
            "x/../a.ko",
            "./a.ko",
            "x//a.ko",
            "x/./a.ko",
            "C:/a.ko",
            "C:a.ko",
            "x\\a.ko",
            "\\\\host\\a.ko",
            "a.ko/",
            "a.ko.bz2",
            "a.ko.xz.gz",
            "a\0.ko",
            "é.ko",
            "a b.ko",
        ] {
            let tree = fixture(&format!("{path}:\n"), "", &[]);
            assert!(select(tree.path(), &["a"]).is_err(), "{path:?}");
            let tree = fixture(&format!("a.ko: {path}\n"), "", &["a.ko"]);
            assert!(select(tree.path(), &["a"]).is_err(), "dependency {path:?}");
            let tree = fixture("", &format!("{path}\n"), &[]);
            assert!(select(tree.path(), &["a"]).is_err(), "builtin {path:?}");
        }
    }

    #[test]
    fn requires_regular_utf8_metadata_and_module_files() {
        for name in ["modules.dep", "modules.builtin"] {
            let tree = fixture("a.ko:\n", "", &["a.ko"]);
            fs::remove_file(tree.path().join(name)).unwrap();
            assert!(
                select(tree.path(), &["a"])
                    .unwrap_err()
                    .to_string()
                    .contains(name)
            );
            fs::create_dir(tree.path().join(name)).unwrap();
            assert!(select(tree.path(), &["a"]).is_err());
            fs::remove_dir(tree.path().join(name)).unwrap();
            fs::write(tree.path().join(name), [0xff]).unwrap();
            assert!(select(tree.path(), &["a"]).is_err());
        }
        let tree = fixture("a.ko:\n", "", &[]);
        fs::create_dir(tree.path().join("a.ko")).unwrap();
        assert!(select(tree.path(), &["a"]).is_err());
        assert!(select(&tree.path().join("modules.dep"), &["a"]).is_err());
    }

    #[test]
    fn rejects_newc_oversize_before_allocating() {
        let tree = fixture("a.ko:\n", "", &["a.ko"]);
        fs::File::options()
            .write(true)
            .open(tree.path().join("a.ko"))
            .unwrap()
            .set_len(u64::from(u32::MAX) + 1)
            .unwrap();
        assert!(
            select(tree.path(), &["a"])
                .unwrap_err()
                .to_string()
                .contains("newc")
        );
    }

    #[test]
    fn preserves_safe_local_release_suffix_in_override_resolution() {
        let tree = fixture("a.ko:\n", "", &["a.ko"]);
        let result = resolve("6.18-local~test@build", Some(tree.path()), &["a".into()]).unwrap();
        assert_eq!(result.files.len(), 1);
    }

    #[test]
    fn discovery_is_exact_and_rejects_ambiguity_and_unsafe_release() {
        let temp = tempfile::tempdir().unwrap();
        let roots = [temp.path().join("one"), temp.path().join("two")];
        assert!(discover("6-test", &roots).is_err());
        fs::create_dir_all(roots[0].join("6-test")).unwrap();
        assert_eq!(
            discover("6-test", &roots).unwrap(),
            roots[0].join("6-test").canonicalize().unwrap()
        );
        assert!(discover("other", &roots).is_err());
        fs::create_dir_all(roots[1].join("6-test")).unwrap();
        assert!(discover("6-test", &roots).is_err());
        for release in [
            "",
            ".",
            "..",
            "../6-test",
            "/6-test",
            "C:evil",
            "a\\b",
            "a\n",
            "é",
        ] {
            assert!(discover(release, &roots).is_err());
            assert!(resolve(release, Some(temp.path()), &["a".into()]).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn permits_top_alias_but_rejects_all_interior_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let tree = fixture("kernel/a.ko:\n", "", &["kernel/a.ko"]);
        let alias = temp.path().join("alias");
        symlink(tree.path(), &alias).unwrap();
        assert!(select(&alias, &["a"]).is_ok());
        let release = "6-test";
        fs::create_dir(temp.path().join(release)).unwrap();
        symlink(temp.path(), temp.path().join("root-alias")).unwrap();
        assert_eq!(
            discover(
                release,
                &[temp.path().to_owned(), temp.path().join("root-alias")]
            )
            .unwrap(),
            temp.path().join(release).canonicalize().unwrap()
        );
        for name in ["modules.dep", "modules.builtin", "kernel/a.ko"] {
            let path = tree.path().join(name);
            let target = temp.path().join("target");
            fs::rename(&path, &target).unwrap();
            symlink(&target, &path).unwrap();
            assert!(select(tree.path(), &["a"]).is_err(), "{name}");
            fs::remove_file(&path).unwrap();
            fs::rename(target, path).unwrap();
        }
        fs::rename(tree.path().join("kernel"), temp.path().join("outside")).unwrap();
        symlink(temp.path().join("outside"), tree.path().join("kernel")).unwrap();
        assert!(select(tree.path(), &["a"]).is_err());
    }

    #[test]
    fn deep_dependency_chain_is_iterative() {
        let count = 20_000;
        let mut definitions = Definitions::new();
        for index in 0..count {
            definitions.insert(
                format!("m{index}.ko"),
                if index + 1 == count {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([format!("m{}.ko", index + 1)])
                },
            );
        }
        assert_eq!(
            closure(&definitions, ["m0.ko".into()].into_iter())
                .unwrap()
                .len(),
            count
        );
        definitions
            .get_mut(&format!("m{}.ko", count - 1))
            .unwrap()
            .insert("m0.ko".into());
        assert!(closure(&definitions, ["m0.ko".into()].into_iter()).is_err());
    }

    #[test]
    fn builtins_need_no_payload_and_selection_is_order_independent() {
        let tree = fixture(
            "a.ko:\nb.ko: a.ko\n",
            "kernel/z-in.ko\nkernel/c-in.ko\n",
            &["a.ko", "b.ko"],
        );
        let builtin = select(tree.path(), &["z_in", "c-in", "z-in"]).unwrap();
        assert!(builtin.files.is_empty());
        assert_eq!(builtin.builtins, ["c_in", "z_in"]);
        let one = select(tree.path(), &["b", "a", "b"]).unwrap();
        let two = select(tree.path(), &["a", "b"]).unwrap();
        assert_eq!(
            one.files
                .iter()
                .map(|file| (&file.relative, &file.bytes))
                .collect::<Vec<_>>(),
            two.files
                .iter()
                .map(|file| (&file.relative, &file.bytes))
                .collect::<Vec<_>>()
        );
        fs::write(
            tree.path().join("modules.softdep"),
            b"not even valid metadata\0\xff",
        )
        .unwrap();
        assert_eq!(select(tree.path(), &["b"]).unwrap().files.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unix_special_files_and_in_tree_symlinks() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let tree = fixture("a.ko:\n", "", &[]);
        let path = tree.path().join("a.ko");
        let socket = UnixListener::bind(&path).unwrap();
        assert!(select(tree.path(), &["a"]).is_err());
        drop(socket);
        fs::remove_file(&path).unwrap();
        fs::write(tree.path().join("real.ko"), b"payload").unwrap();
        symlink("real.ko", &path).unwrap();
        assert!(select(tree.path(), &["a"]).is_err());
    }

    #[test]
    fn validates_original_ascii_names() {
        assert_eq!(validate_name("virtio-pci").unwrap(), "virtio_pci");
        assert_eq!(validate_name("_X9").unwrap(), "_X9");
        for name in [
            "", "-foo", "a\n", "a.ko", "../a", "a/b", "a\\b", "é", "a b", "a*", "a=x", "a\0",
        ] {
            assert!(validate_name(name).is_err(), "{name:?}");
        }
    }
}
