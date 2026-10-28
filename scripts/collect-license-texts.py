#!/usr/bin/env python3
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "Cargo.toml"
LOCKFILE = ROOT / "rust" / "Cargo.lock"
LICENSES = ROOT / "licenses"
STAGING = LICENSES / ".staging"
NOTICES = ROOT / "docs" / "THIRD_PARTY_NOTICES.md"
WORK = ROOT / "build" / "license-text-collection"
ARCHIVE_CACHE = WORK / "archives"
TAR_CACHE = WORK / "tars"
EXTRACTION = WORK / "extracted"
COLLECTION_MANIFEST = LICENSES / "manifest.json"
USER_AGENT = "Addressee-license-text-collector/1.0 (+https://github.com/Addressee)"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_LEGAL_FILE_BYTES = 4 * 1024 * 1024
MAX_LEGAL_TOTAL_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 50000
MAX_JSON_BYTES = 4 * 1024 * 1024
LEGAL_PREFIXES = ("license", "licence", "copying", "notice", "copyright", "patent")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

RECOVERED_REVISIONS = {
    ("crc24", "0.1.6"): {
        "commit": "521ddbbe1909c06fe322a06b00de1260c5d3acd6",
        "method": "fixed-revision-exact-non-legal-tree-match",
        "description": (
            "Cargo recorded no commit. This fixed upstream revision adds the license texts; "
            "it is used only if every non-legal file exactly matches the locked crate."
        ),
    },
    ("hex-slice", "0.1.4"): {
        "commit": "f320de67e978c0cde8993e8e62f4eaaaf4cbf06d",
        "method": "archived-exact-version-tag-and-non-legal-tree-match",
        "description": (
            "Cargo recorded no commit. The archived v0.1.4 tag must resolve to this fixed "
            "commit, and every non-legal file must exactly match the locked crate."
        ),
        "softwareHeritage": {
            "snapshot": "ea2791e7510bbd24157743e69464a8efd5cc9e40",
            "tag": "refs/tags/v0.1.4",
            "release": "97ffd2c45909fea98cdf4b2a22d848cfbe7646c3",
        },
    },
}
REPOSITORY_MIRRORS = {
    "https://gitlab.com/openpgp-card/openpgp-card": [
        "https://codeberg.org/openpgp-card/openpgp-card",
    ],
    "https://codeberg.org/openpgp-card/openpgp-card": [
        "https://gitlab.com/openpgp-card/openpgp-card",
    ],
}


class CollectionError(Exception):
    pass


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if urllib.parse.urlsplit(new_url).scheme != "https":
            raise CollectionError(f"Refusing non-HTTPS redirect to {new_url}")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


OPENER = urllib.request.build_opener(HTTPSRedirectHandler())


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def require_https(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CollectionError(f"Only credential-free HTTPS sources are allowed: {url}")


def open_url(url, method="GET"):
    require_https(url)
    request = urllib.request.Request(
        url,
        data=b"" if method == "POST" else None,
        method=method,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response = OPENER.open(request, timeout=60)
    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
        response.close()
        raise CollectionError(f"Refusing non-HTTPS response for {url}")
    return response


def api_json(url, method="GET"):
    try:
        with open_url(url, method) as response:
            data = response.read(MAX_JSON_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise CollectionError(f"HTTP {error.code} from {url}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise CollectionError(f"Request failed for {url}: {error}") from error
    if len(data) > MAX_JSON_BYTES:
        raise CollectionError(f"JSON response exceeds {MAX_JSON_BYTES} bytes: {url}")
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CollectionError(f"Invalid JSON from {url}: {error}") from error


def sha256_file(path, maximum=MAX_ARCHIVE_BYTES):
    size = path.stat().st_size
    if size > maximum:
        raise CollectionError(f"File exceeds {maximum} bytes: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest(), size


def safe_relative(value):
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise CollectionError(f"Unsafe relative path: {value!r}")
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise CollectionError(f"Unsafe relative path: {value!r}")
    return path


def output_path(root, relative):
    path = safe_relative(relative)
    destination = root.joinpath(*path.parts)
    root.mkdir(parents=True, exist_ok=True)
    resolved_root = root.resolve()
    resolved_destination = destination.resolve(strict=False)
    if resolved_destination != resolved_root and resolved_root not in resolved_destination.parents:
        raise CollectionError(f"Output path escapes {root}: {relative}")
    current = root
    for part in path.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise CollectionError(f"Refusing symlink in output path: {current}")
    if destination.is_symlink():
        raise CollectionError(f"Refusing symlink output: {destination}")
    return destination


def legal_basename(path):
    return PurePosixPath(path).name.lower().startswith(LEGAL_PREFIXES)


def embedded_notice_content(path, content):
    if PurePosixPath(path).name.upper() not in {"AUTHOR", "AUTHORS"}:
        return False
    return bool(
        re.search(br"(?m)^LICENSE:\s*$", content)
        and re.search(br"(?m)^COPYRIGHT:", content)
    )


def embedded_notice_file(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_LEGAL_FILE_BYTES:
        return False
    with path.open("rb") as source:
        return embedded_notice_content(path.name, source.read(256 * 1024))


def legal_repository_path(path, package_path=""):
    path = PurePosixPath(path)

    def selected(relative):
        if len(relative.parts) == 1:
            return legal_basename(relative.name)
        return len(relative.parts) > 1 and relative.parts[0].upper() == "LICENSES"

    if selected(path):
        return True
    package = PurePosixPath(package_path) if package_path else PurePosixPath()
    if not package.parts or path.parts[: len(package.parts)] != package.parts:
        return False
    return selected(PurePosixPath(*path.parts[len(package.parts) :]))


def normalize_repository(url):
    require_https(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.query or parsed.fragment:
        raise CollectionError(f"Repository URL must not contain a query or fragment: {url}")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise CollectionError(f"Invalid repository path: {url}")
    return f"https://{parsed.hostname.lower()}/{path}"


def archive_url(repository, commit):
    parsed = urllib.parse.urlsplit(repository)
    path = parsed.path.strip("/")
    host = parsed.hostname.lower()
    if host == "github.com":
        return f"{repository}/archive/{commit}.tar.gz"
    if host == "codeberg.org":
        return f"{repository}/archive/{commit}.tar.gz"
    if host == "gitlab.com" or host.startswith("gitlab."):
        name = path.rsplit("/", 1)[-1]
        return f"{repository}/-/archive/{commit}/{name}-{commit}.tar.gz"
    raise CollectionError(f"Unsupported repository host: {host}")


def mirror_commit_verification(repository, commit):
    parsed = urllib.parse.urlsplit(repository)
    host = parsed.hostname.lower()
    path = parsed.path.strip("/")
    if host == "github.com":
        url = f"https://api.github.com/repos/{path}/commits/{commit}"
        response = api_json(url)
        actual = response.get("sha")
    elif host == "codeberg.org":
        url = f"https://codeberg.org/api/v1/repos/{path}/git/commits/{commit}"
        response = api_json(url)
        actual = response.get("sha")
    elif host == "gitlab.com" or host.startswith("gitlab."):
        project = urllib.parse.quote(path, safe="")
        url = f"https://{host}/api/v4/projects/{project}/repository/commits/{commit}"
        response = api_json(url)
        actual = response.get("id")
    else:
        raise CollectionError(f"Unsupported mirror host: {host}")
    if actual != commit:
        raise CollectionError(f"Mirror commit mismatch at {url}: expected {commit}, got {actual}")
    return {"type": "host-commit-api", "url": url, "commit": actual}


def lock_checksums():
    packages = {}
    current = None
    for line in LOCKFILE.read_text().splitlines():
        if line == "[[package]]":
            if current and all(key in current for key in ("name", "version", "checksum")):
                packages[(current["name"], current["version"])] = current["checksum"]
            current = {}
        elif line.startswith("[") and line != "[[package]]":
            if current and all(key in current for key in ("name", "version", "checksum")):
                packages[(current["name"], current["version"])] = current["checksum"]
            current = None
        elif current is not None:
            match = re.match(r'^(name|version|checksum) = "(.*)"$', line)
            if match:
                current[match.group(1)] = match.group(2)
    if current and all(key in current for key in ("name", "version", "checksum")):
        packages[(current["name"], current["version"])] = current["checksum"]
    return packages


def decompress_tar(archive, destination):
    temporary = destination.with_suffix(destination.suffix + ".part")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary.unlink(missing_ok=True)
    total = 0
    try:
        with gzip.open(archive, "rb") as source, temporary.open("xb") as target:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_TAR_BYTES:
                    raise CollectionError(f"Uncompressed tar exceeds {MAX_TAR_BYTES} bytes: {archive}")
                target.write(block)
        os.replace(temporary, destination)
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        temporary.unlink(missing_ok=True)
        raise CollectionError(f"Cannot decompress {archive}: {error}") from error
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


class SafeArchive:
    def __init__(self, archive_path, tar_path):
        self.archive_path = archive_path
        self.tar_path = tar_path
        self.members = {}
        self.files = {}
        self.embedded_notices = set()
        self.extracted = set()
        self._read_index()

    def _read_index(self):
        roots = set()
        members = []
        total_size = 0
        try:
            with tarfile.open(self.tar_path, "r:") as archive:
                for member in archive:
                    if len(members) >= MAX_MEMBERS:
                        raise CollectionError(f"Archive has more than {MAX_MEMBERS} members")
                    if not (member.isfile() or member.isdir()):
                        raise CollectionError(f"Archive contains a link or non-regular member: {member.name}")
                    path = safe_relative(member.name.rstrip("/"))
                    roots.add(path.parts[0])
                    members.append((member, path))
                    if member.isfile():
                        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                            raise CollectionError(f"Archive member has an unsafe size: {member.name}")
                        total_size += member.size
                        if total_size > MAX_TAR_BYTES:
                            raise CollectionError("Archive members exceed the expanded-size limit")
                if len(roots) != 1:
                    raise CollectionError(f"Archive must have one top-level directory, found {sorted(roots)}")
                for member, path in members:
                    if len(path.parts) == 1:
                        if member.isfile():
                            raise CollectionError("Archive root is a regular file")
                        continue
                    relative = PurePosixPath(*path.parts[1:])
                    key = relative.as_posix()
                    if member.isdir():
                        continue
                    if key in self.members:
                        raise CollectionError(f"Duplicate archive member: {key}")
                    self.members[key] = member
                    source = archive.extractfile(member)
                    if source is None:
                        raise CollectionError(f"Cannot read archive member: {key}")
                    digest = hashlib.sha256()
                    remaining = member.size
                    sample = bytearray()
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise CollectionError(f"Truncated archive member: {key}")
                        remaining -= len(block)
                        digest.update(block)
                        if len(sample) < 256 * 1024:
                            sample.extend(block[: 256 * 1024 - len(sample)])
                    if source.read(1):
                        raise CollectionError(f"Archive member exceeds its declared size: {key}")
                    if member.size <= MAX_LEGAL_FILE_BYTES and embedded_notice_content(key, bytes(sample)):
                        self.embedded_notices.add(key)
                    self.files[key] = {"sha256": digest.hexdigest(), "size": member.size}
        except (tarfile.TarError, OSError) as error:
            raise CollectionError(f"Unsafe or invalid tar archive {self.archive_path}: {error}") from error

    def verify_package(self, reference, package_path, exact_non_legal_tree):
        prefix = f"{package_path}/" if package_path else ""
        actual = {}
        for path, details in self.files.items():
            if prefix and not path.startswith(prefix):
                continue
            relative = path[len(prefix) :]
            if not relative or legal_basename(relative) or "LICENSES" in PurePosixPath(relative).parts[:-1]:
                continue
            actual[relative] = details
        expected = reference["files"]
        generated = []
        if not exact_non_legal_tree:
            generated = sorted(
                path
                for path in expected
                if path in {"Cargo.lock", "README.md"} and path not in actual
            )
            expected = {path: details for path, details in expected.items() if path not in generated}
        missing = sorted(path for path in expected if path not in actual)
        mismatched = sorted(
            path for path in expected if path in actual and expected[path]["sha256"] != actual[path]["sha256"]
        )
        extra = sorted(path for path in actual if path not in expected) if exact_non_legal_tree else []
        if missing or mismatched or extra:
            details = []
            if missing:
                details.append("missing=" + ",".join(missing[:10]))
            if mismatched:
                details.append("mismatched=" + ",".join(mismatched[:10]))
            if extra:
                details.append("extra=" + ",".join(extra[:10]))
            raise CollectionError("Registry source verification failed: " + "; ".join(details))
        return {
            "status": "matched",
            "method": (
                "locked-crate-exact-non-legal-tree"
                if exact_non_legal_tree
                else "locked-crate-file-subset"
            ),
            "crateSha256": reference["crateSha256"],
            "matchedFileCount": len(expected),
            "matchedFiles": [
                {"path": path, "sha256": expected[path]["sha256"]} for path in sorted(expected)
            ],
            "generatedPackageFilesNotRequired": generated,
        }

    def legal_files(self, package_path):
        embedded_paths = {"AUTHORS", "AUTHOR"}
        if package_path:
            embedded_paths.update(
                {f"{package_path}/AUTHORS", f"{package_path}/AUTHOR"}
            )
        return sorted(
            path
            for path in self.files
            if legal_repository_path(path, package_path)
            or (path in self.embedded_notices and path in embedded_paths)
        )

    def extract(self, relative, archive_id):
        if relative not in self.members:
            raise CollectionError(f"Missing archive member: {relative}")
        destination = output_path(EXTRACTION / archive_id, relative)
        if relative in self.extracted:
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".part")
        temporary.unlink(missing_ok=True)
        try:
            with tarfile.open(self.tar_path, "r:") as archive:
                source = archive.extractfile(self.members[relative])
                if source is None:
                    raise CollectionError(f"Cannot extract {relative}")
                with temporary.open("xb") as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
            actual, size = sha256_file(temporary, MAX_LEGAL_FILE_BYTES)
            expected = self.files[relative]
            if actual != expected["sha256"] or size != expected["size"]:
                raise CollectionError(f"Extracted file hash mismatch: {relative}")
            os.replace(temporary, destination)
            self.extracted.add(relative)
            return destination
        except (tarfile.TarError, OSError) as error:
            temporary.unlink(missing_ok=True)
            raise CollectionError(f"Cannot extract {relative}: {error}") from error
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


def load_reference(package, checksum, cache):
    identity = (package["name"], package["version"])
    if identity in cache:
        return cache[identity]
    if not checksum or not SHA256_RE.fullmatch(checksum):
        raise CollectionError(f"No locked crate checksum for {identity[0]} {identity[1]}")
    pattern = f".cargo/registry/cache/*/{identity[0]}-{identity[1]}.crate"
    candidates = sorted(Path.home().glob(pattern))
    selected = None
    selected_digest = None
    for candidate in candidates:
        digest, _ = sha256_file(candidate)
        if digest == checksum:
            selected = candidate
            selected_digest = digest
            break
    if selected is None:
        raise CollectionError(f"No checksum-matching locked crate archive for {identity[0]} {identity[1]}")
    tar_path = TAR_CACHE / f"crate-{identity[0]}-{identity[1]}-{checksum[:16]}.tar"
    decompress_tar(selected, tar_path)
    archive = SafeArchive(selected, tar_path)
    files = {}
    has_original_manifest = "Cargo.toml.orig" in archive.files
    for path, details in archive.files.items():
        if path == ".cargo_vcs_info.json":
            continue
        if path == "Cargo.toml" and has_original_manifest:
            continue
        canonical = "Cargo.toml" if path == "Cargo.toml.orig" else path
        if legal_basename(canonical) or "LICENSES" in PurePosixPath(canonical).parts[:-1]:
            continue
        if canonical in files:
            raise CollectionError(f"Duplicate canonical crate path: {canonical}")
        files[canonical] = details
    result = {"crateSha256": selected_digest, "files": files}
    cache[identity] = result
    return result


def download(url, destination, previous=None):
    require_https(url)
    if destination.is_file() and previous:
        try:
            digest, size = sha256_file(destination)
            if digest == previous.get("sha256") and size == previous.get("size"):
                return {
                    "url": url,
                    "sha256": digest,
                    "size": size,
                    "retrievedAt": previous.get("retrievedAt"),
                    "reusedDownload": True,
                }
        except (OSError, CollectionError):
            pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    temporary.unlink(missing_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with open_url(url) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_ARCHIVE_BYTES:
                raise CollectionError(f"Archive exceeds {MAX_ARCHIVE_BYTES} bytes: {url}")
            with temporary.open("xb") as target:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_ARCHIVE_BYTES:
                        raise CollectionError(f"Archive exceeds {MAX_ARCHIVE_BYTES} bytes: {url}")
                    digest.update(block)
                    target.write(block)
        if size == 0:
            raise CollectionError(f"Empty archive: {url}")
        os.replace(temporary, destination)
    except urllib.error.HTTPError as error:
        temporary.unlink(missing_ok=True)
        raise CollectionError(f"HTTP {error.code} from {url}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        temporary.unlink(missing_ok=True)
        raise CollectionError(f"Download failed for {url}: {error}") from error
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {
        "url": url,
        "sha256": digest.hexdigest(),
        "size": size,
        "retrievedAt": now(),
        "reusedDownload": False,
    }


def software_heritage_archive(repository, recovery):
    settings = recovery["softwareHeritage"]
    commit = recovery["commit"]
    origin = repository.rstrip("/")
    visits_url = f"https://archive.softwareheritage.org/api/1/origin/{origin}/visits/"
    visits = api_json(visits_url)
    if not any(
        visit.get("status") == "full" and visit.get("snapshot") == settings["snapshot"]
        for visit in visits
    ):
        raise CollectionError("Software Heritage does not bind the required snapshot to the declared origin")
    snapshot_url = f"https://archive.softwareheritage.org/api/1/snapshot/{settings['snapshot']}/"
    snapshot = api_json(snapshot_url)
    branch = snapshot.get("branches", {}).get(settings["tag"], {})
    if branch.get("target") != settings["release"] or branch.get("target_type") != "release":
        raise CollectionError("Software Heritage snapshot does not contain the required version tag")
    release_url = f"https://archive.softwareheritage.org/api/1/release/{settings['release']}/"
    release = api_json(release_url)
    if (
        release.get("name") != settings["tag"].rsplit("/", 1)[-1]
        or release.get("target") != commit
        or release.get("target_type") != "revision"
        or release.get("synthetic") is not False
    ):
        raise CollectionError("Software Heritage version tag does not resolve to the required commit")
    revision_url = f"https://archive.softwareheritage.org/api/1/revision/{commit}/"
    revision = api_json(revision_url)
    directory = revision.get("directory")
    if (
        revision.get("id") != commit
        or revision.get("type") != "git"
        or revision.get("synthetic") is not False
        or not COMMIT_RE.fullmatch(directory or "")
    ):
        raise CollectionError("Software Heritage revision verification failed")
    swhid = f"swh:1:dir:{directory}"
    vault_url = f"https://archive.softwareheritage.org/api/1/vault/flat/{swhid}/"
    api_json(vault_url, "POST")
    for _ in range(60):
        status = api_json(vault_url)
        state = status.get("status")
        if state == "done":
            fetch_url = status.get("fetch_url")
            if fetch_url != vault_url + "raw/":
                raise CollectionError("Unexpected Software Heritage vault download URL")
            verification = {
                "type": "software-heritage-origin-tag-and-revision",
                "originVisitsUrl": visits_url,
                "snapshotUrl": snapshot_url,
                "releaseUrl": release_url,
                "revisionUrl": revision_url,
                "commit": commit,
                "directory": directory,
            }
            return fetch_url, vault_url + "raw/", verification
        if state in {"failed", "expired"}:
            raise CollectionError(f"Software Heritage vault preparation {state}")
        time.sleep(2)
    raise CollectionError("Software Heritage vault preparation timed out")


def copy_notice(source, destination, expected=None):
    if source.is_symlink() or not source.is_file():
        raise CollectionError(f"Notice is not a regular file: {source}")
    size = source.stat().st_size
    if size <= 0 or size > MAX_LEGAL_FILE_BYTES:
        raise CollectionError(f"Notice has an unsafe or empty size: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".part")
    temporary.unlink(missing_ok=True)
    digest = hashlib.sha256()
    try:
        with source.open("rb") as src, temporary.open("xb") as target:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                target.write(block)
        actual = digest.hexdigest()
        if expected and (actual != expected["sha256"] or size != expected["size"]):
            raise CollectionError(f"Notice hash mismatch: {source}")
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {"path": PurePosixPath(destination.name).name, "sha256": actual, "size": size}


def local_notices(directory):
    if not directory.is_dir():
        raise CollectionError(f"Package directory is unavailable: {directory}")
    resolved_root = directory.resolve()
    files = []
    for child in sorted(directory.iterdir(), key=lambda item: item.name):
        if child.is_file() and (legal_basename(child.name) or embedded_notice_file(child)):
            files.append(child)
    licenses_directory = directory / "LICENSES"
    if licenses_directory.is_symlink():
        raise CollectionError(f"LICENSES must not be a symlink: {licenses_directory}")
    if licenses_directory.is_dir():
        for child in sorted(licenses_directory.rglob("*"), key=lambda item: item.as_posix()):
            if child.is_file():
                files.append(child)
    result = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise CollectionError(f"Notice is not a regular file: {path}")
        resolved = path.resolve()
        if resolved_root not in resolved.parents:
            raise CollectionError(f"Notice escapes package directory: {path}")
        relative = path.relative_to(directory).as_posix()
        safe_relative(relative)
        result.append((relative, path))
    return result


def vcs_information(package):
    path = Path(package["manifest_path"]).parent / ".cargo_vcs_info.json"
    if not path.is_file():
        return None, ""
    if path.stat().st_size > 1024 * 1024:
        raise CollectionError(f"Oversized VCS information: {path}")
    information = json.loads(path.read_text())
    commit = information.get("git", {}).get("sha1", "").lower()
    if not COMMIT_RE.fullmatch(commit):
        raise CollectionError(f"Invalid Cargo VCS commit in {path}")
    package_path = information.get("path_in_vcs", "")
    if package_path:
        package_path = safe_relative(package_path).as_posix()
    return commit, package_path


def package_directory(package):
    return f"{package['name']}-{package['version']}"


def is_vendored(package):
    directory = Path(package["manifest_path"]).parent.resolve()
    vendor = (ROOT / "vendor").resolve()
    return package.get("source") is None and vendor in directory.parents


def previous_archive_records():
    if not COLLECTION_MANIFEST.is_file():
        return {}
    try:
        manifest = json.loads(COLLECTION_MANIFEST.read_text())
        return {item.get("id"): item for item in manifest.get("archives", [])}
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}


def markdown_text(value):
    if value is None:
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_readme():
    return f"""# Third-party legal texts

This directory is generated by `python3 scripts/collect-license-texts.py` from locked Cargo metadata. The collector copies legal files from the authoritative registry package or vendored source. When a registry package omits those files, it retrieves a repository archive at the Cargo-recorded commit and verifies the archived package files against the checksum-verified locked crate.

Archives are shared by normalized repository and commit, cached under `build/license-text-collection/`, downloaded only over HTTPS with a descriptive User-Agent, and limited to {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB compressed and {MAX_TAR_BYTES // (1024 * 1024)} MiB uncompressed. Tar links, special files, absolute paths, traversal, duplicate files, and unsafe output paths are rejected. Only legal notice files are copied here; source code and tests are not collected.

`manifest.json` records the actual collection time, package metadata, archive URLs, commits, archive SHA-256 digests, source-verification results, and every collected file's SHA-256 and size. A recovered revision without Cargo VCS metadata requires an exact non-legal tree match to the locked crate; a branch or license-expression inference is not accepted. Mirrors must independently resolve the same fixed commit before their archives are used.

A Cargo `license` expression is metadata, not license-text evidence. A package without a packaged notice must have a verified collected directory with hashed notice files to pass `python3 scripts/audit-dependencies.py`. Failed collections are recorded in the manifest and make both commands fail; partial output must not be treated as complete third-party notices.

To reproduce the collection, run the collector again with the lockfile and registry crates available. It replaces this generated directory and `docs/THIRD_PARTY_NOTICES.md`. Previously cached downloads are reused only when their URL and SHA-256 match the preceding manifest. Network changes, removed upstream history, or a changed lockfile can therefore produce new failures rather than silently substituting different evidence.
"""


def generate_notices(manifest):
    lines = [
        "# Third-party notices",
        "",
        f"Generated from locked Cargo metadata at {manifest['generatedAt']}.",
        "",
        "This is an index of collected legal texts, not a claim that license metadata alone proves notice compliance. File provenance, exact commits, archive digests, source verification, and failures are recorded in [`licenses/manifest.json`](../licenses/manifest.json).",
        "",
        f"Third-party packages: {manifest['summary']['thirdPartyPackages']}; collected: {manifest['summary']['collected']}; failed: {manifest['summary']['failed']}. Local Addressee crates are omitted.",
        "",
        "| Package | Version | SPDX expression | Repository | Evidence | Collected paths |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for package in manifest["packages"]:
        evidence = package["evidence"]["type"] if package.get("evidence") else "failed"
        if package["status"] == "collected":
            paths = "<br>".join(
                f"[`{markdown_text(item['path'])}`](../licenses/{package['directory']}/{item['path']})"
                for item in package["files"]
            )
        else:
            paths = "Not collected — " + markdown_text(package.get("error", "unknown failure"))
        repository = package.get("repository")
        repository_cell = f"<{repository}>" if repository else "—"
        lines.append(
            f"| `{markdown_text(package['name'])}` | `{markdown_text(package['version'])}` "
            f"| `{markdown_text(package.get('normalizedLicense'))}` | {repository_cell} "
            f"| {markdown_text(evidence)} | {paths} |"
        )
    return "\n".join(lines) + "\n"


def publish(staging_manifest, staging_notices):
    for child in LICENSES.iterdir():
        if child == STAGING:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in STAGING.iterdir():
        shutil.move(os.fspath(child), os.fspath(LICENSES / child.name))
    STAGING.rmdir()
    shutil.copyfile(staging_notices, NOTICES)


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    ARCHIVE_CACHE.mkdir(parents=True, exist_ok=True)
    TAR_CACHE.mkdir(parents=True, exist_ok=True)
    EXTRACTION.mkdir(parents=True, exist_ok=True)
    LICENSES.mkdir(parents=True, exist_ok=True)
    if STAGING.exists():
        shutil.rmtree(STAGING)
    STAGING.mkdir()
    previous_archives = previous_archive_records()
    metadata_command = [
        "cargo",
        "metadata",
        "--manifest-path",
        os.fspath(MANIFEST),
        "--locked",
        "--format-version",
        "1",
    ]
    metadata = json.loads(
        subprocess.run(metadata_command, cwd=ROOT, check=True, text=True, capture_output=True).stdout
    )
    checksums = lock_checksums()
    packages = sorted(metadata["packages"], key=lambda item: (item["name"], item["version"]))
    manifest = {
        "schemaVersion": 1,
        "generatedAt": now(),
        "metadataCommand": [
            "cargo",
            "metadata",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "--format-version",
            "1",
        ],
        "packages": [],
        "skippedLocalPackages": [],
        "archives": [],
        "failures": [],
    }
    archive_cache = {}
    reference_cache = {}
    notices_staging = WORK / "THIRD_PARTY_NOTICES.md"

    for package in packages:
        identity = (package["name"], package["version"])
        if package.get("source") is None and not is_vendored(package):
            manifest["skippedLocalPackages"].append(
                {"name": package["name"], "version": package["version"]}
            )
            continue
        record = {
            "name": package["name"],
            "version": package["version"],
            "license": package.get("license"),
            "normalizedLicense": (
                package["license"].replace("/", " OR ").strip() if package.get("license") else None
            ),
            "repository": package.get("repository"),
            "source": package.get("source"),
            "directory": package_directory(package),
            "status": "failed",
            "files": [],
        }
        destination_directory = STAGING / record["directory"]
        try:
            directory = Path(package["manifest_path"]).parent
            local_files = local_notices(directory)
            if local_files:
                for relative, source in local_files:
                    destination = output_path(destination_directory, relative)
                    details = copy_notice(source, destination)
                    details["path"] = relative
                    record["files"].append(details)
                record["evidence"] = {
                    "type": "vendored-package" if package.get("source") is None else "registry-package",
                }
            else:
                commit, package_path = vcs_information(package)
                recovery = None
                if not commit:
                    recovery = RECOVERED_REVISIONS.get(identity)
                    if recovery is None:
                        raise CollectionError(
                            "Cargo recorded no commit and no verified fixed-revision recovery is configured"
                        )
                    commit = recovery["commit"]
                if not package.get("repository"):
                    raise CollectionError("Package has no authoritative repository")
                repository = normalize_repository(package["repository"])
                archive_identity = hashlib.sha256(
                    (repository + "\0" + commit).encode("utf-8")
                ).hexdigest()[:24]
                if archive_identity not in archive_cache:
                    candidates = [(repository, archive_url(repository, commit), False)]
                    candidates.extend(
                        (mirror, archive_url(mirror, commit), True)
                        for mirror in REPOSITORY_MIRRORS.get(repository, [])
                    )
                    errors = []
                    selected_archive = None
                    for candidate_repository, url, mirror in candidates:
                        try:
                            verification = (
                                mirror_commit_verification(candidate_repository, commit)
                                if mirror
                                else {"type": "authoritative-repository-commit-archive"}
                            )
                            previous = previous_archives.get(archive_identity)
                            if previous and previous.get("url") != url:
                                previous = None
                            downloaded = download(
                                url, ARCHIVE_CACHE / f"{archive_identity}.tar.gz", previous
                            )
                            tar_path = TAR_CACHE / f"{archive_identity}-{downloaded['sha256'][:16]}.tar"
                            decompress_tar(ARCHIVE_CACHE / f"{archive_identity}.tar.gz", tar_path)
                            archive = SafeArchive(ARCHIVE_CACHE / f"{archive_identity}.tar.gz", tar_path)
                            selected_archive = {
                                "id": archive_identity,
                                "repository": repository,
                                "sourceRepository": candidate_repository,
                                "commit": commit,
                                "mirror": mirror,
                                "verification": verification,
                                "archive": archive,
                                **downloaded,
                            }
                            break
                        except (CollectionError, ValueError) as error:
                            errors.append(str(error))
                    if selected_archive is None and recovery and "softwareHeritage" in recovery:
                        try:
                            fetch_url, stable_url, verification = software_heritage_archive(
                                repository, recovery
                            )
                            previous = previous_archives.get(archive_identity)
                            if previous and previous.get("url") != stable_url:
                                previous = None
                            downloaded = download(
                                fetch_url, ARCHIVE_CACHE / f"{archive_identity}.tar.gz", previous
                            )
                            downloaded["url"] = stable_url
                            tar_path = TAR_CACHE / f"{archive_identity}-{downloaded['sha256'][:16]}.tar"
                            decompress_tar(ARCHIVE_CACHE / f"{archive_identity}.tar.gz", tar_path)
                            archive = SafeArchive(ARCHIVE_CACHE / f"{archive_identity}.tar.gz", tar_path)
                            selected_archive = {
                                "id": archive_identity,
                                "repository": repository,
                                "sourceRepository": "https://archive.softwareheritage.org",
                                "commit": commit,
                                "mirror": True,
                                "verification": verification,
                                "archive": archive,
                                **downloaded,
                            }
                        except (CollectionError, ValueError) as error:
                            errors.append(str(error))
                    if selected_archive is None:
                        raise CollectionError("No verified repository archive: " + " | ".join(errors))
                    selected_archive["recovery"] = recovery
                    archive_cache[archive_identity] = selected_archive
                    print(
                        f"Archived {repository} at {commit} from {selected_archive['url']} "
                        f"(SHA-256 {selected_archive['sha256']})"
                    )
                selected_archive = archive_cache[archive_identity]
                archive = selected_archive["archive"]
                reference = load_reference(package, checksums.get(identity), reference_cache)
                verification = archive.verify_package(
                    reference, package_path, exact_non_legal_tree=recovery is not None
                )
                legal_files = archive.legal_files(package_path)
                if not legal_files:
                    raise CollectionError(
                        f"Verified repository archive at {commit} contains no license or notice files"
                    )
                if sum(archive.files[path]["size"] for path in legal_files) > MAX_LEGAL_TOTAL_BYTES:
                    raise CollectionError("Selected legal texts exceed the per-package size limit")
                for relative in legal_files:
                    extracted = archive.extract(relative, archive_identity)
                    destination = output_path(destination_directory, relative)
                    details = copy_notice(extracted, destination, archive.files[relative])
                    details["path"] = relative
                    record["files"].append(details)
                record["evidence"] = {
                    "type": "repository-archive",
                    "archiveId": archive_identity,
                    "repository": repository,
                    "commit": commit,
                    "packagePath": package_path,
                    "cargoVcsCommit": recovery is None,
                    "recovery": recovery,
                    "registryVerification": verification,
                }
            if not record["files"]:
                raise CollectionError("No legal notice files collected")
            record["files"].sort(key=lambda item: item["path"])
            record["status"] = "collected"
            record.pop("error", None)
        except (CollectionError, OSError, json.JSONDecodeError) as error:
            if destination_directory.exists():
                shutil.rmtree(destination_directory)
            record["error"] = str(error)
            manifest["failures"].append(
                {"name": package["name"], "version": package["version"], "error": str(error)}
            )
            print(f"Collection failed for {identity[0]} {identity[1]}: {error}", file=sys.stderr)
        manifest["packages"].append(record)

    for archive_id, archive in sorted(archive_cache.items()):
        public = {key: value for key, value in archive.items() if key not in {"archive", "reusedDownload"}}
        manifest["archives"].append(public)
    manifest["summary"] = {
        "thirdPartyPackages": len(manifest["packages"]),
        "collected": sum(item["status"] == "collected" for item in manifest["packages"]),
        "failed": len(manifest["failures"]),
    }
    (STAGING / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (STAGING / "README.md").write_text(generate_readme())
    notices_staging.write_text(generate_notices(manifest))
    publish(STAGING / "manifest.json", notices_staging)
    print(
        f"Collected {manifest['summary']['collected']} of {manifest['summary']['thirdPartyPackages']} "
        f"third-party packages using {len(manifest['archives'])} repository archives; "
        f"failures: {manifest['summary']['failed']}."
    )
    return 1 if manifest["failures"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", file=sys.stderr)
        print(error.stderr or "", file=sys.stderr)
        raise
