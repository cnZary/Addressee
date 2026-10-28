#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "Cargo.toml"
LOCKFILE = ROOT / "rust" / "Cargo.lock"
REPORT = ROOT / "build" / "audit" / "dependency-licenses.json"
LICENSES = ROOT / "licenses"
COLLECTION_MANIFEST = LICENSES / "manifest.json"
MAX_NOTICE_BYTES = 4 * 1024 * 1024

ALLOWED_LICENSES = {
    "Apache-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "Zlib",
}
ALLOWED_EXPRESSIONS = {"MIT OR Apache-2.0 OR LGPL-2.1-or-later"}
ALLOWED_EXCEPTIONS = {"LLVM-exception"}
LEGAL_PREFIXES = ("license", "licence", "copying", "notice", "copyright", "patent")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def run(command):
    return subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)


def normalize_license(expression):
    return expression.replace("/", " OR ").strip()


def license_tokens(expression):
    for character in "()+":
        expression = expression.replace(character, " ")
    return expression.split()


def legal_basename(path):
    return PurePosixPath(path).name.lower().startswith(LEGAL_PREFIXES)


def embedded_notice_file(path):
    if path.name.upper() not in {"AUTHOR", "AUTHORS"}:
        return False
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_NOTICE_BYTES:
        return False
    with path.open("rb") as source:
        content = source.read(256 * 1024)
    return bool(
        re.search(br"(?m)^LICENSE:\s*$", content)
        and re.search(br"(?m)^COPYRIGHT:", content)
    )


def safe_relative(value):
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise ValueError("unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in value.split("/")
    ):
        raise ValueError("unsafe path")
    return path


def packaged_notices(directory):
    if not directory.is_dir():
        return []
    result = []
    for child in directory.iterdir():
        if (
            child.is_file()
            and not child.is_symlink()
            and child.stat().st_size > 0
            and (legal_basename(child.name) or embedded_notice_file(child))
        ):
            result.append(child)
    licenses_directory = directory / "LICENSES"
    if licenses_directory.is_dir() and not licenses_directory.is_symlink():
        for child in licenses_directory.rglob("*"):
            if child.is_file() and not child.is_symlink() and child.stat().st_size > 0:
                result.append(child)
    return result


def read_collection_manifest():
    result = {"packages": {}, "failures": {}, "archives": {}, "errors": []}
    if not COLLECTION_MANIFEST.is_file():
        return result
    try:
        if COLLECTION_MANIFEST.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("manifest exceeds 64 MiB")
        data = json.loads(COLLECTION_MANIFEST.read_text())
        if data.get("schemaVersion") != 1:
            raise ValueError("unsupported schema version")
        for record in data.get("packages", []):
            identity = (record["name"], record["version"])
            if identity in result["packages"]:
                raise ValueError(f"duplicate package {identity[0]} {identity[1]}")
            result["packages"][identity] = record
        for record in data.get("failures", []):
            result["failures"][(record["name"], record["version"])] = record.get("error")
        for record in data.get("archives", []):
            archive_id = record["id"]
            if archive_id in result["archives"]:
                raise ValueError(f"duplicate archive {archive_id}")
            result["archives"][archive_id] = record
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        result["errors"].append(f"invalid collection manifest: {error}")
    return result


def locked_checksums():
    checksums = {}
    current = None
    for line in LOCKFILE.read_text().splitlines():
        if line == "[[package]]":
            current = {}
        elif line.startswith("["):
            current = None
        elif current is not None:
            match = re.match(r'^(name|version|checksum) = "(.*)"$', line)
            if match:
                current[match.group(1)] = match.group(2)
        if current and all(key in current for key in ("name", "version", "checksum")):
            identity = (current["name"], current["version"])
            checksums[identity] = current["checksum"]
    return checksums


def validate_archive_evidence(package, record, manifest, checksums):
    evidence = record.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("type") != "repository-archive":
        raise ValueError("missing repository archive evidence")
    archive = manifest["archives"].get(evidence.get("archiveId"))
    if not archive:
        raise ValueError("archive record is missing")
    commit = evidence.get("commit")
    if not COMMIT_RE.fullmatch(commit or ""):
        raise ValueError("invalid evidence commit")
    if archive.get("commit") != commit or archive.get("repository") != evidence.get("repository"):
        raise ValueError("archive provenance does not match package evidence")
    if not str(archive.get("url", "")).startswith("https://"):
        raise ValueError("archive URL is not HTTPS")
    if not SHA256_RE.fullmatch(archive.get("sha256", "")):
        raise ValueError("archive SHA-256 is missing")
    if type(archive.get("size")) is not int or archive["size"] <= 0:
        raise ValueError("archive size is invalid")
    verification = archive.get("verification")
    if not isinstance(verification, dict):
        raise ValueError("archive commit verification is missing")
    if archive.get("mirror") and verification.get("commit") != commit:
        raise ValueError("mirror did not verify the exact commit")
    registry = evidence.get("registryVerification")
    if not isinstance(registry, dict) or registry.get("status") != "matched":
        raise ValueError("locked crate source verification is missing")
    identity = (package["name"], package["version"])
    if registry.get("crateSha256") != checksums.get(identity):
        raise ValueError("locked crate checksum does not match the collection manifest")
    matched_files = registry.get("matchedFiles")
    if not isinstance(matched_files, list) or not matched_files:
        raise ValueError("locked crate matched-file list is missing")
    if registry.get("matchedFileCount") != len(matched_files):
        raise ValueError("locked crate matched-file count is inconsistent")
    for item in matched_files:
        safe_relative(item.get("path"))
        if not SHA256_RE.fullmatch(item.get("sha256", "")):
            raise ValueError("locked crate matched-file hash is invalid")
    vcs_path = Path(package["manifest_path"]).parent / ".cargo_vcs_info.json"
    cargo_commit = None
    if vcs_path.is_file():
        cargo_commit = json.loads(vcs_path.read_text()).get("git", {}).get("sha1", "").lower()
    if cargo_commit:
        if commit != cargo_commit or evidence.get("cargoVcsCommit") is not True:
            raise ValueError("collected archive does not use the Cargo-recorded commit")
        if registry.get("method") != "locked-crate-file-subset":
            raise ValueError("Cargo-commit archive lacks subset source verification")
    else:
        if evidence.get("cargoVcsCommit") is not False or not evidence.get("recovery"):
            raise ValueError("recovered archive lacks fixed-revision evidence")
        if registry.get("method") != "locked-crate-exact-non-legal-tree":
            raise ValueError("recovered archive lacks exact non-legal tree verification")


def collected_directory_files(directory):
    result = {}

    def visit(current):
        for child in current.iterdir():
            if child.is_symlink():
                raise ValueError("collected directory contains a symlink")
            if child.is_dir():
                visit(child)
            elif child.is_file():
                relative = child.relative_to(directory).as_posix()
                safe_relative(relative)
                result[relative] = child
            else:
                raise ValueError("collected directory contains a non-regular file")

    visit(directory)
    return result


def verified_collected(package, manifest, checksums):
    identity = (package["name"], package["version"])
    record = manifest["packages"].get(identity)
    if record is None:
        failure = manifest["failures"].get(identity)
        return [], f"collection failed: {failure}" if failure else "no collection manifest entry"
    if record.get("status") != "collected":
        return [], f"collection failed: {record.get('error', 'not collected')}"
    for field in ("license", "repository", "source"):
        if record.get(field) != package.get(field):
            return [], f"collection metadata mismatch: {field}"
    expected_directory = f"{package['name']}-{package['version']}"
    if record.get("directory") != expected_directory:
        return [], "collected directory name does not match the package"
    try:
        validate_archive_evidence(package, record, manifest, checksums)
        directory = LICENSES / expected_directory
        if directory.is_symlink() or not directory.is_dir():
            return [], "collected directory is missing or not regular"
        actual_files = collected_directory_files(directory)
        declared_files = {}
        for item in record.get("files", []):
            relative = safe_relative(item.get("path")).as_posix()
            path = PurePosixPath(relative)
            if (
                not legal_basename(relative)
                and not any(part.upper() == "LICENSES" for part in path.parts[:-1])
                and not (
                    relative in actual_files and embedded_notice_file(actual_files[relative])
                )
            ):
                return [], f"collected file is not a legal notice: {relative}"
            if relative in declared_files:
                return [], f"duplicate collected file: {relative}"
            if not SHA256_RE.fullmatch(item.get("sha256", "")):
                return [], f"invalid collected SHA-256: {relative}"
            if type(item.get("size")) is not int or not 0 < item["size"] <= MAX_NOTICE_BYTES:
                return [], f"invalid collected size: {relative}"
            declared_files[relative] = item
        if not declared_files:
            return [], "collected directory has no declared notice files"
        if set(actual_files) != set(declared_files):
            return [], "collected directory contents do not match the manifest"
        for relative, item in declared_files.items():
            path = actual_files[relative]
            if path.stat().st_size != item["size"]:
                return [], f"collected file size mismatch: {relative}"
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != item["sha256"]:
                return [], f"collected file hash mismatch: {relative}"
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        return [], f"invalid collected evidence: {error}"
    return [
        f"licenses/{expected_directory}/{relative}" for relative in sorted(declared_files)
    ], None


def main():
    metadata = json.loads(run([
        "cargo", "metadata", "--manifest-path", os.fspath(MANIFEST),
        "--locked", "--format-version", "1",
    ]).stdout)
    packages = []
    rejected = []
    missing_files = []
    collection = read_collection_manifest()
    checksums = locked_checksums()
    missing_files.extend(collection["errors"])

    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        source = package.get("source")
        expression = package.get("license")
        if expression:
            expression = normalize_license(expression)
        license_file = package.get("license_file")
        record = {
            "name": package["name"],
            "version": package["version"],
            "license": expression,
            "licenseFile": license_file,
            "source": source,
            "local": source is None,
        }
        packages.append(record)

        manifest_directory = Path(package["manifest_path"]).parent
        declared_license_file = None
        if license_file:
            path = manifest_directory / license_file
            if path.is_file() and not path.is_symlink() and path.stat().st_size > 0:
                declared_license_file = path
            else:
                missing_files.append(f"{package['name']} {package['version']}: {license_file}")
        elif not expression:
            if source:
                rejected.append(f"{package['name']} {package['version']}: no SPDX expression")
        elif expression not in ALLOWED_EXPRESSIONS:
            tokens = license_tokens(expression)
            index = 0
            while index < len(tokens):
                token = tokens[index]
                if token in {"AND", "OR"}:
                    index += 1
                    continue
                if token == "WITH":
                    index += 1
                    if index >= len(tokens) or tokens[index] not in ALLOWED_EXCEPTIONS:
                        rejected.append(f"{package['name']} {package['version']}: {expression}")
                    index += 1
                    continue
                if token not in ALLOWED_LICENSES:
                    rejected.append(f"{package['name']} {package['version']}: {expression}")
                index += 1

        package_notices = packaged_notices(manifest_directory)
        if declared_license_file and declared_license_file not in package_notices:
            package_notices.append(declared_license_file)
        is_vendored = source is None and (ROOT / "vendor").resolve() in manifest_directory.resolve().parents
        record["licenseTextAvailable"] = bool(package_notices)
        record["licenseTextEvidence"] = "package" if package_notices else "missing"
        record["packageNotices"] = [
            path.relative_to(manifest_directory).as_posix() for path in package_notices
        ]
        if not package_notices and (source or is_vendored):
            collected, error = verified_collected(package, collection, checksums)
            if collected:
                record["licenseTextAvailable"] = True
                record["licenseTextEvidence"] = "collected"
                record["collectedNotices"] = collected
            elif declared_license_file is None:
                missing_files.append(
                    f"{package['name']} {package['version']}: license text not packaged; {error}"
                )

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps({
        "packages": packages,
        "licensePolicyFailures": rejected,
        "licenseTextReview": missing_files,
    }, indent=2) + "\n")
    (REPORT.parent / "license-text-review.json").write_text(
        json.dumps(missing_files, indent=2) + "\n"
    )

    for issue in rejected:
        print(f"License policy failure: {issue}", file=sys.stderr)
    for issue in missing_files:
        print(f"License text collection required before distribution: {issue}", file=sys.stderr)

    print(
        f"Checked {len(packages)} packages: {len(rejected)} license policy failures; "
        f"{len(missing_files)} license-text collection items."
    )

    resolved = {(package["name"], package["version"]) for package in packages}
    exceptions = json.loads((ROOT / "scripts" / "audit-exceptions.json").read_text())
    audit_command = [
        "cargo", "audit", "--file", os.fspath(LOCKFILE), "--deny", "warnings",
    ]
    if database := os.environ.get("ADDRESSEE_RUSTSEC_DB"):
        revision = run(["git", "-C", database, "rev-parse", "HEAD"]).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("The RustSec database revision is invalid")
        print(f"RustSec database snapshot: {revision}")
        audit_command.extend(["--db", database, "--no-fetch"])
    stale_exceptions = []
    for exception in exceptions:
        identity = (exception["package"], exception["version"])
        if identity not in resolved:
            stale_exceptions.append(exception)
            continue
        print(
            f"Scoped audit exception: {exception['advisory']} "
            f"({exception['package']} {exception['version']}): {exception['scope']}"
        )
        audit_command.extend(["--ignore", exception["advisory"]])
    for exception in stale_exceptions:
        print(
            f"Stale audit exception requires review: {exception['advisory']} "
            f"({exception['package']} {exception['version']})",
            file=sys.stderr,
        )

    result = subprocess.run(audit_command, cwd=ROOT)
    if rejected or missing_files or stale_exceptions:
        return 1
    return result.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", file=sys.stderr)
        print(error.stderr or "", file=sys.stderr)
        raise
