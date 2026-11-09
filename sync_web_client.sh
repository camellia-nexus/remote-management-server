#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SRC_INPUT=""
CLIENT_REPO_INPUT=""
EXPECTED_ROOT_DIGEST=""
LOCKED_REVISION="$("${SCRIPT_DIR}/scripts/web_client_revision.sh")"

usage() {
  cat <<'EOF'
Usage:
  sync_web_client.sh --build-from CLIENT_REPOSITORY [--expected-root-digest DIGEST]
  sync_web_client.sh --source COMPILED_WEB_DIRECTORY [--expected-root-digest DIGEST]

Exactly one input mode is required. --build-from runs the client's canonical
release build first; --source only synchronizes an already compiled, clean and
revision-stamped build. Both modes require the source revision pinned by
web-client.lock and generate a verified web_client_manifest.json with root digest.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-from)
      if [[ $# -lt 2 ]]; then
        echo "--build-from requires a client repository" >&2
        exit 2
      fi
      CLIENT_REPO_INPUT="$2"
      shift 2
      ;;
    --source)
      if [[ $# -lt 2 ]]; then
        echo "--source requires a compiled web directory" >&2
        exit 2
      fi
      SRC_INPUT="$2"
      shift 2
      ;;
    --expected-root-digest)
      if [[ $# -lt 2 ]]; then
        echo "--expected-root-digest requires a sha256 digest" >&2
        exit 2
      fi
      EXPECTED_ROOT_DIGEST="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$SRC_INPUT" && -n "$CLIENT_REPO_INPUT" ]]; then
  echo "--source and --build-from are mutually exclusive" >&2
  exit 2
fi
if [[ -z "$SRC_INPUT" && -z "$CLIENT_REPO_INPUT" ]]; then
  usage >&2
  exit 2
fi

EXPECTED_REVISION=""
if [[ -n "$CLIENT_REPO_INPUT" ]]; then
  if [[ ! -d "$CLIENT_REPO_INPUT" ]]; then
    echo "Client repository not found: $CLIENT_REPO_INPUT" >&2
    exit 1
  fi
  CLIENT_REPO="$(cd "$CLIENT_REPO_INPUT" && pwd -P)"
  BUILD_SCRIPT="${CLIENT_REPO}/flutter/web/tools/build_web.sh"
  if [[ ! -f "$BUILD_SCRIPT" ]] || ! git -C "$CLIENT_REPO" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "Invalid client repository: $CLIENT_REPO" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$CLIENT_REPO" status --porcelain --untracked-files=no)" ]]; then
    echo "Client repository has tracked changes; commit them before producing a synchronized runtime." >&2
    exit 1
  fi
  EXPECTED_REVISION="$(git -C "$CLIENT_REPO" rev-parse HEAD)"
  if [[ "$EXPECTED_REVISION" != "$LOCKED_REVISION" ]]; then
    echo "Client repository revision does not match web-client.lock: expected $LOCKED_REVISION, got $EXPECTED_REVISION" >&2
    exit 1
  fi

  (cd "$CLIENT_REPO" && bash "$BUILD_SCRIPT" --mode release --base-href /static/web_client/)

  if [[ -n "$(git -C "$CLIENT_REPO" status --porcelain --untracked-files=no)" ]]; then
    echo "Client build modified tracked source files; refusing to synchronize ambiguous output." >&2
    exit 1
  fi
  SRC_INPUT="${CLIENT_REPO}/flutter/build/web"
fi

if [[ ! -d "$SRC_INPUT" ]]; then
  echo "Source web build not found: $SRC_INPUT" >&2
  exit 1
fi

SRC="$(cd "$SRC_INPUT" && pwd -P)"
DST="${SCRIPT_DIR}/static/web_client"
STATIC_DIR="${SCRIPT_DIR}/static"

if [[ "$SRC" == "/" || "$SRC" == "$DST" ]]; then
  echo "Refusing unsafe web client source: $SRC" >&2
  exit 1
fi
if [[ -n "$(find "$SRC" -type l -print -quit)" ]]; then
  echo "Web client build must not contain symbolic links" >&2
  exit 1
fi

SOURCE_REVISION_FILE="${SRC}/.source_revision"
if [[ ! -f "$SOURCE_REVISION_FILE" ]]; then
  echo "Web client build is missing source provenance: $SOURCE_REVISION_FILE" >&2
  exit 1
fi
SOURCE_REVISION_RECORD="$(tr -d '\r\n' < "$SOURCE_REVISION_FILE")"
if [[ ! "$SOURCE_REVISION_RECORD" =~ ^([0-9a-f]{40,64})[[:space:]]clean$ ]]; then
  echo "Web client build does not come from a clean, revision-stamped source tree" >&2
  exit 1
fi
SOURCE_REVISION="${BASH_REMATCH[1]}"
if [[ "$SOURCE_REVISION" != "$LOCKED_REVISION" ]]; then
  echo "Web client revision does not match web-client.lock: expected $LOCKED_REVISION, got $SOURCE_REVISION" >&2
  exit 1
fi
if [[ -n "$EXPECTED_REVISION" && "$SOURCE_REVISION" != "$EXPECTED_REVISION" ]]; then
  echo "Web client provenance mismatch: expected $EXPECTED_REVISION, got $SOURCE_REVISION" >&2
  exit 1
fi

# Require build_manifest.json and verify its full integrity before staging
BUILD_MANIFEST_FILE="${SRC}/build_manifest.json"
if [[ ! -f "$BUILD_MANIFEST_FILE" ]]; then
  echo "Web client build is missing build_manifest.json: $BUILD_MANIFEST_FILE" >&2
  exit 1
fi

python3 -c '
import hashlib, json, os, sys
from pathlib import Path

src = Path(sys.argv[1])
expected_rev = sys.argv[2]
manifest_path = src / "build_manifest.json"

with manifest_path.open("r", encoding="utf-8") as f:
    manifest = json.load(f)

if manifest.get("schema_version") != 1:
    sys.exit("Invalid build_manifest schema_version")

actual_rev = manifest.get("source_revision")
if actual_rev != expected_rev:
    sys.exit(f"build_manifest source_revision mismatch: expected {expected_rev}, got {actual_rev}")

actual_state = manifest.get("source_state")
if actual_state != "clean":
    sys.exit(f"build_manifest source_state is not clean: {actual_state}")

files = manifest.get("files", {})
if not files:
    sys.exit("build_manifest contains no files")

lines = []
for rel, spec in sorted(files.items()):
    fp = src / rel
    if not fp.is_file() or fp.is_symlink():
        sys.exit(f"Missing or invalid file declared in build_manifest: {rel}")
    data = fp.read_bytes()
    expected_size = spec["size"]
    if len(data) != expected_size:
        sys.exit(f"Size mismatch for {rel}: expected {expected_size}, got {len(data)}")
    sha = hashlib.sha256(data).hexdigest()
    expected_sha = spec["sha256"]
    if sha.lower() != expected_sha.lower():
        sys.exit(f"Hash mismatch for {rel}: expected {expected_sha}, got {sha}")
    lines.append(f"{rel}:{expected_size}:{expected_sha}")

expected_root = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
manifest_root = manifest.get("root_digest", "")
if expected_root.lower() != manifest_root.lower():
    sys.exit(f"build_manifest root_digest mismatch: expected {expected_root}, got {manifest_root}")

for root_dir, _, filenames in os.walk(src):
    for fn in filenames:
        p = Path(root_dir) / fn
        rel_posix = p.relative_to(src).as_posix()
        if rel_posix in (".source_revision", "build_manifest.json"):
            continue
        if rel_posix not in files:
            sys.exit(f"Unmanifested file found in web client source: {rel_posix}")
' "$SRC" "$LOCKED_REVISION"

STAGING="$(mktemp -d "${STATIC_DIR}/.web-client-stage.XXXXXX")"
BACKUP=""

cleanup() {
  if [[ -n "$STAGING" && -d "$STAGING" ]]; then
    rm -rf -- "$STAGING"
  fi
  if [[ -n "$BACKUP" && -d "$BACKUP" ]]; then
    if [[ ! -e "$DST" ]]; then
      mv -- "$BACKUP" "$DST"
    else
      rm -rf -- "$BACKUP"
    fi
  fi
}
trap cleanup EXIT

cp -a -- "$SRC"/. "$STAGING"/

# Flutter copies everything under flutter/web into build/web. Only the compiled
# bridge belongs in a deployable artifact; source, package managers and build
# scripts needlessly expose internals and inflate the production image.
rm -rf -- \
  "$STAGING/README.md" \
  "$STAGING/tools" \
  "$STAGING/js/README.md" \
  "$STAGING/js/node_modules" \
  "$STAGING/js/src" \
  "$STAGING/js/tools" \
  "$STAGING/js/package.json" \
  "$STAGING/js/package-lock.json" \
  "$STAGING/js/tsconfig.json" \
  "$STAGING/js/vite.config.ts" \
  "$STAGING/build_manifest.json"

if [[ -f "$STAGING/assets/NOTICES" ]]; then
  sed -i 's/[[:blank:]]\+$//' "$STAGING/assets/NOTICES"
fi

# Ensure canonical base in index.html for Management deployment
if [[ -f "$STAGING/index.html" ]]; then
  sed -i 's|<base href="[^"]*">|<base href="/static/web_client/">|' "$STAGING/index.html"
fi

# Flutter embeds flutter.js into the bootstrap but leaves a source-map comment
# even when release builds do not publish the map. WhiteNoise treats the
# dangling comment as a required static dependency, so remove it from both
# emitted copies.
for generated_js in flutter.js flutter_bootstrap.js; do
  if [[ -f "$STAGING/$generated_js" ]]; then
    sed -i '/^[[:blank:]]*\/\/[#@][[:blank:]]*sourceMappingURL=.*$/d' \
      "$STAGING/$generated_js"
  fi
done

required_files=(
  ".source_revision"
  "flutter_bootstrap.js"
  "main.dart.js"
  "manifest.json"
  "canvaskit/canvaskit.wasm"
  "js/dist/web_bridge.js"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$STAGING/$required_file" ]]; then
    echo "Incomplete web client build; missing $required_file" >&2
    exit 1
  fi
done

# Verify video worker chunk exists
shopt -s nullglob
worker_matches=("$STAGING"/js/dist/assets/video_worker-*.js)
shopt -u nullglob
if [[ ${#worker_matches[@]} -eq 0 ]]; then
  echo "Incomplete web client build; missing video worker in js/dist/assets/" >&2
  exit 1
fi

# Verify no absolute /js/dist/ paths or undefined requests in bundle
if grep -Eq '["'\'']/js/dist/assets/video_worker' "$STAGING/js/dist/web_bridge.js"; then
  echo "Web bridge contains root-absolute video worker path /js/dist/assets/video_worker; expected relative import.meta.url resolution" >&2
  exit 1
fi
if grep -Eq 'Object\.assign\(\{\}\)\[' "$STAGING/js/dist/web_bridge.js"; then
  echo "Web bridge contains empty Object.assign glob lookup for software decoders" >&2
  exit 1
fi

# Generate canonical deployment manifest for the sanitized deployment tree
python3 -c '
import hashlib, json, os, sys
from pathlib import Path

staging = Path(sys.argv[1])
revision = sys.argv[2]
expected_digest = sys.argv[3]

files = {}
for root, _, filenames in os.walk(staging):
    for fn in filenames:
        fp = Path(root) / fn
        rel = fp.relative_to(staging).as_posix()
        if rel in (".source_revision", "web_client_manifest.json"):
            continue
        data = fp.read_bytes()
        files[rel] = {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()
        }

sorted_files = sorted(files.keys())
lines = [k + ":" + str(files[k]["size"]) + ":" + files[k]["sha256"] for k in sorted_files]
root_digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()

if expected_digest and root_digest.lower() != expected_digest.lower():
    sys.exit(f"Web client root digest mismatch: expected {expected_digest}, got {root_digest}")

manifest = {
    "schema_version": 1,
    "source_revision": revision,
    "root_digest": root_digest,
    "files": files
}

manifest_file = staging / "web_client_manifest.json"
with manifest_file.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")

print(f"Generated web_client_manifest.json (root_digest={root_digest})")
' "$STAGING" "$SOURCE_REVISION" "$EXPECTED_ROOT_DIGEST"

if [[ ! -f "$STAGING/web_client_manifest.json" ]]; then
  echo "Failed to generate web_client_manifest.json" >&2
  exit 1
fi

if [[ -d "$DST" ]]; then
  BACKUP="$(mktemp -d "${STATIC_DIR}/.web-client-backup.XXXXXX")"
  rmdir -- "$BACKUP"
  mv -- "$DST" "$BACKUP"
fi
mv -- "$STAGING" "$DST"
STAGING=""
if [[ -n "$BACKUP" ]]; then
  rm -rf -- "$BACKUP"
  BACKUP=""
fi

echo "Synced web client revision $SOURCE_REVISION to: $DST"
