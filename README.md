# Lagrange

Lagrange is an offline trajectory, workspace, and project reconciler and CLI manager for Antigravity across the **Hub** (non-IDE), **IDE** (v1 and v2), and **CLI** surfaces.

---

## Why Antigravity Loses Conversations and Mis-tags Workspaces

Antigravity splits conversation storage across three independent application-data directories, two trajectory formats, a separate project registry, and three mutually unaware index stores:

| Surface | Trajectory & Brain Store | Index Store |
| :--- | :--- | :--- |
| **Hub (non-IDE)** | `~/.gemini/antigravity/{conversations,brain,annotations}/` | `~/.gemini/antigravity/agyhub_summaries_proto.pb` + `conversation_summaries.db` (SQLite + FTS5) |
| **IDE (v1 / v2)** | `~/.gemini/antigravity-ide/{conversations,brain,annotations}/` (v2) or `~/.gemini/antigravity/` (v1) | `state.vscdb` (`antigravityUnifiedStateSync.trajectorySummaries`, `sidebarWorkspaces`, and legacy `agentManagerInitState`) |
| **CLI** | `~/.gemini/antigravity-cli/{conversations,brain,annotations}/` | `~/.gemini/antigravity-cli/cache/{projects,last_conversations,conversation_metadata}.json` |
| **Project Registry** | `~/.gemini/config/projects/<uuid>.json` | Referenced by `TrajectoryMetadata.project_id` (field 18) inside each trajectory |

Forensic analysis of the on-disk protobuf and SQLite stores exposes seven structural flaws that cause conversations to vanish or show up untagged:

1. **Siloed Surface Directories**: Conversations created in IDE v2 (`~/.gemini/antigravity-ide/conversations/<id>.db`) are never copied or linked into `~/.gemini/antigravity/conversations/`. The Hub never sees them, and the startup summary reconciler only scans its own `conversations/` directory (plus the CLI directory) on an add-only basis (`AddSummaryIfAbsent`), never refreshing stale entries already in `agyhub_summaries_proto.pb`.
2. **The `source = CLI` Visibility Filter**: While the Hub watches `~/.gemini/antigravity-cli/conversations/`, it stamps every CLI trajectory with `source = 17` (`CLI`). The Hub UI filters the main conversation list by `isLocalSource` (allowing only `0`, `18`, and `20`) and routes `source = 17` into `externalSummaries`—hiding CLI conversations from the list entirely.
3. **Divergent Workspace & Project Binding Fields**:
   - The **IDE** groups conversations using `TrajectorySummary.workspaces` (field 9, copied from deprecated `TrajectoryMetadata.workspaces` field 1).
   - The **Hub** and **CLI** group conversations using `TrajectoryMetadata.workspace_uris` (field 7) and `TrajectoryMetadata.project_id` (field 18).
   - Any tool or migration that updates only summary field 9 leaves `workspace_uris` empty and `project_id` set to `"outside-of-project"`, stranding conversations in *"Outside of Project"*.
4. **Encrypted Legacy `.pb` vs. SQLite `.db` Trajectories**: Older conversations are stored as `<id>.pb` files encrypted with AES-256-GCM (`12-byte nonce || ciphertext || 16-byte tag`), while newer conversations use SQLite WAL databases (`<id>.db`, with serialized `TrajectoryMetadata` in `trajectory_metadata_blob` where `id = 'main'`). If a `.pb` file's internal `Trajectory.metadata` (field 7) and `source` (field 8) are not decrypted, updated, and re-encrypted, its project and workspace bindings cannot be repaired.
5. **Blank Titles in `conversation_summaries.db`**: The Hub SQLite table `conversation_summaries` populates its `title` column strictly from `TrajectorySummary.annotations.title` (`field 15 -> field 1`) and `annotations/<id>.pbtxt`, whereas auto-generated conversation titles live in `TrajectorySummary.summary` (field 1). Without backfilling `annotations.title`, legacy `.pb` and un-annotated `.db` chats show blank titles in SQLite.
6. **Subagent Flattening**: Child subagent trajectories live alongside top-level conversations in `conversations/<id>.db` and link to their parent via `TrajectoryMetadata.parent_conversation_id` (field 5), `root_conversation_id` (field 6), and `nesting_depth` (field 17), carried on `TrajectorySummary.trajectory_metadata` (field 17). Rebuilding a summary without field 17 flattens every subagent into a noisy top-level chat.
7. **Double-Encoded `UssTopic` Rows & `SidebarWorkspace` Field 4**: In `state.vscdb`, `antigravityUnifiedStateSync.trajectorySummaries` and `sidebarWorkspaces` store a base64-encoded `UssTopic` whose map entries contain a `UssRow` where `value` (field 1) is an **inner base64 string** (`base64(TrajectorySummary)` or `base64(SidebarWorkspace)` with the folder URI in **field 4**, fields 1–3 reserved). Naive scripts that only decode outer base64—or scrape `file://` strings from raw wire bytes without checking protobuf tags—corrupt workspace URIs with raw wire tags and mislabel every directory as a Git repository (`git_root_absolute_uri`, sub-field 2).

---

## How Lagrange Works

Lagrange treats the trajectory files (`<id>.db` and encrypted `<id>.pb`) as the single source of truth and reconciles every surface and index in one deterministic pass:

1. **Process Gate**: Refuses to mutate disk state while any Antigravity UI, `language_server`, or CLI process is running (since the language server flushes its in-memory summary map to `agyhub_summaries_proto.pb` every ~1 second and would clobber offline edits). Override with `--force`.
2. **Non-Destructive Backup & Manifest**: Backs up every modified or retired file into `~/.gemini/lagrange_backups/<timestamp>/` with a complete `manifest.json` before writing a single byte.
3. **Single Physical Home + Surface Linking**: Moves IDE-only and CLI-only trajectories (`<id>.db` with `-wal`/`-shm`, `<id>.pb`), `brain/<id>/`, and `annotations/<id>.pbtxt` into `~/.gemini/antigravity/`, keeping the copy with the highest step count when duplicates exist, and symlinks `~/.gemini/antigravity-ide/{conversations,brain,annotations}` to the Hub directories so IDE v2 and Hub can never drift apart again (`--no-link-surfaces` to copy instead).
4. **Project Registry Curation**: Deduplicates `~/.gemini/config/projects/<uuid>.json` files that point to the same folder, merges stale subfolder projects (`--merge-stale-subprojects`), creates missing project JSONs for active workspaces, and cleans path-like project names (e.g. `/Users/<you>` $\to$ `Home`).
5. **Tag-Verified Trajectory Metadata Rewrite**: Updates `workspaces` (field 1, setting `git_root_absolute_uri` sub-field 2 **only** when a real `.git` exists), `workspace_uris` (field 7), `project_id` (field 18), and `source = 0` inside every `.db` (`trajectory_metadata_blob` and `trajectory_meta`) and every encrypted `.pb` while preserving file modification times.
6. **Hub & IDE Index Reconstruction**:
   - Rebuilds `~/.gemini/antigravity/agyhub_summaries_proto.pb` with all conversations, preserving `trajectory_metadata` (field 17) so subagents stay nested under their parent conversations, and retires `conversation_summaries.db` so the language server cleanly re-seeds SQLite and FTS5 on next startup.
   - Rebuilds `antigravityUnifiedStateSync.trajectorySummaries`, `sidebarWorkspaces`, and legacy `agentManagerInitState` in both `Antigravity` and `Antigravity IDE` `state.vscdb` databases.
   - Updates `~/.gemini/antigravity-cli/cache/` and (when paths are remapped) IDE `storage.json` and `workspaceStorage/*/workspace.json`.

### Title Resolution Priority

1. Explicit title set via `rename-conversation`.
2. User title in `annotations/<id>.pbtxt` or `TrajectorySummary.annotations.title` (`field 15 -> 1`).
3. Existing summary preview in `TrajectorySummary.summary` (`field 1`, tag-verified UTF-8).
4. First `CHECKPOINT` step (`step_type = 23`) `user_intent` (`field 30 -> 4`).
5. First markdown heading (`# ...`) in `brain/<id>/{task,implementation_plan,walkthrough}.md`.
6. First multi-word `USER_INPUT` step (`step_type = 14`, `field 19 -> 2`), truncated to 80 characters.

### Workspace Resolution Priority

1. Explicit assignment (`move-conversation`, `--assign`, or `--remap OLD=NEW`).
2. `TrajectoryMetadata.workspace_uris` (field 7) and `workspaces` (field 1), after scrubbing corrupted wire bytes and applying remap rules.
3. Workspace URI in an existing summary (`agyhub_summaries_proto.pb` or `state.vscdb`).
4. Dominant project path referenced across `brain/<id>/*.md` and trajectory steps.

---

## Requirements

- **Python 3.9+** (standard library only; zero third-party packages required).
- For legacy AES-256-GCM `.pb` trajectories, Lagrange automatically uses `cryptography` if installed, falls back to the system OpenSSL `libcrypto` via `ctypes`, and includes a pure-Python AES-256-GCM implementation as a universal fallback.

---

## Usage

Close all Antigravity windows, language servers, and CLI sessions before running mutating commands.

```sh
python3 lagrange.py                      # interactive menu
python3 lagrange.py status               # cross-surface diagnostic report
python3 lagrange.py status --json --include-subagents
python3 lagrange.py sync --dry-run       # preview full reconciliation
python3 lagrange.py sync                 # execute reconciliation
```

### `sync` Options

| Option | Description |
| :--- | :--- |
| `--remap OLD=NEW` | Remap a moved workspace folder path across trajectories, projects, and indexes (repeatable). |
| `--assign ID=PATH_OR_PROJECT` | Assign a conversation (and its child subagents) to a workspace path or project name. |
| `--merge-project SRC=DST` | Merge duplicate project `SRC` into `DST` and repoint all conversations. |
| `--rename-project ID_OR_NAME=NAME` | Rename a project in `~/.gemini/config/projects/<uuid>.json`. |
| `--auto-create-projects` | Create a project JSON for every workspace that does not yet have one. |
| `--merge-stale-subprojects` | Merge projects whose folder no longer exists into their parent project. |
| `--prune-empty` | Stash empty 0-step stub sessions into the backup directory. |
| `--no-link-surfaces` | Copy trajectories into the Hub instead of symlinking IDE v2 folders. |
| `--link-cli` | Also symlink `~/.gemini/antigravity-cli/{conversations,brain,annotations}` to the Hub. |
| `--rewrite-deep-paths` | Rewrite remapped folder paths inside `.db`/`.pb` step payloads and `brain/<id>/` files. |
| `--write-annotations` | Write resolved titles back to `annotations/<id>.pbtxt` even when an annotation title already exists. |

### Targeted Management Commands

```sh
python3 lagrange.py rename-conversation 9f3a7c12 "TARS Telemetry & Flight Control"
python3 lagrange.py move-conversation 9f3a7c12 ~/Documents/Dev/Endurance
python3 lagrange.py move-conversation 9f3a7c12 Endurance
python3 lagrange.py rename-project /Users/me Home
python3 lagrange.py merge-project 4b8e21a0 c3d910f4
python3 lagrange.py create-project Gargantua ~/Documents/Dev/Gargantua
python3 lagrange.py remap-path "/Users/me/Cooper Station" /Users/me/Documents/Dev/Endurance --deep
```

Every mutating command supports `--dry-run`, `--force`, `--home <dir>`, and `--config-root <dir>`.

---

## Testing

```sh
python3 -m unittest discover -s tests -v
```

---

## Acknowledgments & License

The initial spark to tackle broken Antigravity conversation histories came from [FutureisinPast/antigravity-conversation-fix](https://github.com/FutureisinPast/antigravity-conversation-fix); Lagrange was architected and written from the ground up around the complete multi-surface trajectory, summary, and project schemas.

MIT License. See [LICENSE](LICENSE).
