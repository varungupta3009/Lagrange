#!/usr/bin/env python3
"""Unit and end-to-end tests for lagrange.py (standard library only)."""

import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lagrange as lg  # noqa: E402
from lagrange import ProtoFields  # noqa: E402

T0 = 1760000000.0  # fixed reference time


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def step(stype, text=None, intent=None, created=None, extra=None):
    s = ProtoFields().append(lg.StepF.TYPE, stype)
    if created is not None:
        s.append(lg.StepF.METADATA, ProtoFields().append(1, lg.ts_from_float(created)))
    if text is not None:
        s.append(lg.StepF.USER_INPUT, ProtoFields().append(2, text))
    if intent is not None:
        s.append(lg.StepF.CHECKPOINT, ProtoFields().append(4, intent))
    if extra is not None:
        s.append(98, extra)
    return s


def metadata(ws=(), project=None, parent=None, root=None, depth=0, created=T0,
             legacy_only=False, raw_ws=None):
    md = ProtoFields()
    for u in (raw_ws if raw_ws is not None else ws):
        md.append(lg.MetaF.WORKSPACES, ProtoFields().append(1, u).append(3, b""))
    md.append(lg.MetaF.CREATED_AT, lg.ts_from_float(created))
    md.append(3, "init-state-id")  # unknown-to-us field that must survive
    if parent:
        md.append(lg.MetaF.PARENT_CONVERSATION_ID, parent)
    if root:
        md.append(lg.MetaF.ROOT_CONVERSATION_ID, root)
    if not legacy_only:
        for u in ws:
            md.append(lg.MetaF.WORKSPACE_URIS, u)
    if depth:
        md.append(lg.MetaF.NESTING_DEPTH, depth)
    if project is not None:
        md.append(lg.MetaF.PROJECT_ID, project)
    return md


SCHEMA = [
    "CREATE TABLE trajectory_meta (trajectory_id TEXT PRIMARY KEY, cascade_id TEXT, "
    "trajectory_type INTEGER, source INTEGER)",
    "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER NOT NULL DEFAULT 0, "
    "status INTEGER NOT NULL DEFAULT 0, has_subtrajectory NUMERIC, metadata BLOB, "
    "error_details BLOB, permissions BLOB, task_details BLOB, render_info BLOB, "
    "step_payload BLOB, step_format INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)",
    "CREATE TABLE executor_metadata (idx INTEGER PRIMARY KEY, data BLOB)",
    "CREATE TABLE parent_references (idx INTEGER PRIMARY KEY, data BLOB)",
    "CREATE TABLE trajectory_metadata_blob (id TEXT PRIMARY KEY DEFAULT 'main', data BLOB)",
    "CREATE TABLE battle_mode_infos (idx INTEGER PRIMARY KEY, data BLOB)",
]


def make_db(path, cid, md, steps, source=0, ttype=1, mtime=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    for stmt in SCHEMA:
        conn.execute(stmt)
    conn.execute("INSERT INTO trajectory_meta VALUES (?, ?, ?, ?)", ("traj-" + cid, cid, ttype, source))
    conn.execute("INSERT INTO trajectory_metadata_blob VALUES ('main', ?)", (md.serialize(),))
    for i, s in enumerate(steps):
        meta = s.get(lg.StepF.METADATA, b"")
        conn.execute("INSERT INTO steps (idx, step_type, metadata, step_payload) VALUES (?, ?, ?, ?)",
                     (i, s.get_int(lg.StepF.TYPE), meta, s.serialize()))
    conn.commit()
    conn.close()
    if mtime:
        os.utime(str(path), (mtime, mtime))
    return path


def make_pb(path, cid, md, steps, source=0, ttype=1, encrypted=True, mtime=None):
    traj = ProtoFields().append(lg.TrajectoryF.TRAJECTORY_ID, "traj-" + cid)
    for s in steps:
        traj.append(lg.TrajectoryF.STEPS, s)
    traj.append(lg.TrajectoryF.TRAJECTORY_TYPE, ttype)
    traj.append(lg.TrajectoryF.CASCADE_ID, cid)
    traj.append(lg.TrajectoryF.METADATA, md)
    if source:
        traj.append(lg.TrajectoryF.SOURCE, source)
    traj.append(9, b"\x0a\x03abc")  # executor metadata: must survive untouched
    data = traj.serialize()
    if encrypted:
        data = lg.encrypt_pb(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mtime:
        os.utime(str(path), (mtime, mtime))
    return path


def make_state_db(path, items):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    for k, v in items.items():
        conn.execute("INSERT INTO ItemTable VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


def read_state(path, key):
    conn = sqlite3.connect(str(path))
    row = conn.execute("SELECT value FROM ItemTable WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else None


def read_db_meta(path):
    conn = sqlite3.connect(str(path))
    md = conn.execute("SELECT data FROM trajectory_metadata_blob WHERE id='main'").fetchone()[0]
    src = conn.execute("SELECT source FROM trajectory_meta").fetchone()[0]
    conn.close()
    return ProtoFields.parse(md), src


def summary(title, cid, ws=None, step_count=3):
    s = ProtoFields()
    s.append(lg.SummaryF.STEP_COUNT, step_count)  # deliberately first: never a title
    if title:
        s.append(lg.SummaryF.SUMMARY, title)
    s.append(lg.SummaryF.TRAJECTORY_ID, cid)
    if ws:
        s.append(lg.SummaryF.WORKSPACES, ProtoFields().append(1, ws).append(2, ws))
    s.append(99, b"unknown-field")
    return s


def tree_digest(root):
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            p = os.path.join(dirpath, name)
            h.update(p.encode())
            if os.path.islink(p):
                h.update(os.readlink(p).encode())
            elif os.path.isfile(p):
                with open(p, "rb") as fh:
                    h.update(fh.read())
                h.update(str(int(os.stat(p).st_mtime)).encode())
    return h.hexdigest()


def quiet():
    lines = []
    return lines, lines.append


CORRUPT = "file:///\n#file:///HOME/Cooper Station\x12\x08file:///\x1a\x00"


# ---------------------------------------------------------------------------
# Protobuf codec
# ---------------------------------------------------------------------------


class ProtoCodecTests(unittest.TestCase):
    def test_round_trip_is_byte_exact_with_unknown_fields(self):
        msg = (lg.encode_tag(1, 2) + b"\x03abc" + lg.encode_tag(2, 0) + lg.encode_varint(300)
               + lg.encode_tag(3, 5) + b"\x01\x02\x03\x04" + lg.encode_tag(4, 1) + b"\x00" * 8
               + lg.encode_tag(5, 3) + lg.encode_tag(1, 0) + b"\x07" + lg.encode_tag(5, 4)
               + lg.encode_tag(1000, 0) + b"\x80\x01")
        pf = ProtoFields.parse(msg)
        self.assertEqual(pf.serialize(), msg)
        self.assertEqual(pf.get_str(1), "abc")
        self.assertEqual(pf.get_int(2), 300)
        self.assertEqual(pf.get_int(1000), 128)

    def test_set_preserves_other_fields_and_position(self):
        pf = ProtoFields().append(1, "a").append(7, "x").append(2, 5).append(7, "y").append(9, b"\xff\x00")
        before_tail = pf.fields[-1].raw
        pf.set_all(7, ["z"])
        self.assertEqual([f.num for f in pf.fields], [1, 7, 2, 9])
        self.assertEqual(pf.get_strs(7), ["z"])
        self.assertEqual(pf.fields[-1].raw, before_tail)
        pf.set(2, None)
        self.assertFalse(pf.has(2))

    def test_negative_varint_uses_ten_bytes(self):
        self.assertEqual(lg.encode_varint(-1), b"\xff" * 9 + b"\x01")
        pf = ProtoFields().append(3, -2)
        self.assertEqual(lg.to_signed64(ProtoFields.parse(pf.serialize()).get_int(3)), -2)

    def test_strict_parser_rejects_garbage(self):
        self.assertIsNone(ProtoFields.try_parse(b"\x0a\x05ab"))
        self.assertIsNone(ProtoFields.try_parse(b"\x07"))
        self.assertIsNone(ProtoFields.try_parse(b"\x00\x01"))
        self.assertIsNone(ProtoFields.try_parse(b"\xff" * 11))

    def test_title_is_tag_verified(self):
        s = summary(None, "c1")
        parsed = ProtoFields.parse(s.serialize())
        self.assertEqual(parsed.get_str(lg.SummaryF.SUMMARY), "")
        bad = ProtoFields().append(1, b"\xff\xfe\x00")
        self.assertEqual(ProtoFields.parse(bad.serialize()).get_str(1), "")

    def test_trajectory_metadata_and_summary_round_trip(self):
        md = metadata(["file:///w"], project="p1", parent="par", depth=2)
        parsed = ProtoFields.parse(md.serialize())
        self.assertEqual(parsed.get_strs(lg.MetaF.WORKSPACE_URIS), ["file:///w"])
        self.assertEqual(parsed.get_str(lg.MetaF.PROJECT_ID), "p1")
        self.assertEqual(parsed.get_str(lg.MetaF.PARENT_CONVERSATION_ID), "par")
        self.assertEqual(parsed.get_int(lg.MetaF.NESTING_DEPTH), 2)
        self.assertAlmostEqual(lg.ts_to_float(parsed.get_msg(lg.MetaF.CREATED_AT)), T0)
        ws = parsed.get_msgs(lg.MetaF.WORKSPACES)[0]
        self.assertEqual(ws.get_str(lg.WsF.FOLDER_URI), "file:///w")

    def test_summaries_state_and_uss_topic(self):
        s = summary("Hello", "c1", ws="file:///w")
        state = ProtoFields()
        state.append(lg.StateF.SUMMARIES, lg.make_map_entry("c1", s))
        state.append(lg.StateF.FILE_MOD_TIMES, lg.make_map_entry("c1", 1700000000))
        parsed = ProtoFields.parse(state.serialize())
        entries = lg.map_entries(parsed, lg.StateF.SUMMARIES)
        self.assertEqual(entries[0][0], "c1")
        self.assertEqual(ProtoFields.parse(entries[0][1]).get_str(1), "Hello")
        self.assertEqual(lg.map_entries(parsed, lg.StateF.FILE_MOD_TIMES)[0][1], 1700000000)
        topic = lg.build_topic([("c1", lg.row_with_inner(None, s))])
        base64.b64decode(topic, validate=True)
        rows = lg.parse_topic(topic)
        self.assertEqual(rows[0][0], "c1")
        inner_b64 = rows[0][1].get_str(1)
        self.assertEqual(base64.b64decode(inner_b64), s.serialize())
        self.assertEqual(lg.row_inner(rows[0][1]).get_str(1), "Hello")

    def test_rewrite_proto_strings_keeps_lengths_consistent(self):
        inner = ProtoFields().append(1, "see /old/dir/file.txt").append(2, 7)
        outer = ProtoFields().append(1, 14).append(19, inner).append(5, b"\x0a\x00")
        remap = lg.Remapper([("/old/dir", "/brand/new/location")])
        out = lg.rewrite_proto_strings(outer.serialize(), remap.text)
        parsed = ProtoFields.parse(out)
        self.assertEqual(parsed.get_msg(19).get_str(1), "see /brand/new/location/file.txt")
        self.assertEqual(parsed.get_msg(19).get_int(2), 7)
        self.assertEqual(parsed.get_int(1), 14)


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


class CryptoTests(unittest.TestCase):
    KEY0 = b"\x00" * 32
    IV0 = b"\x00" * 12

    def backends(self):
        out = []
        for name in lg.available_crypto_backends():
            out.append(lg.get_crypto_backend(name))
        return out

    def test_pure_python_is_always_available(self):
        self.assertIn("pure-python", lg.available_crypto_backends())

    def test_known_answer_vectors(self):
        for b in self.backends():
            with self.subTest(backend=b.name):
                self.assertEqual(b.encrypt(self.KEY0, self.IV0, b"").hex(),
                                 "530f8afbc74536b9a963b4f1c4cb738b")
                self.assertEqual(b.encrypt(self.KEY0, self.IV0, b"\x00" * 16).hex(),
                                 "cea7403d4d606b6e074ec5d3baf39d18"
                                 "d0d1c8a799996bf0265b98b5d48ab919")

    def test_backends_agree_and_round_trip(self):
        data = os.urandom(1000) + b"tail"
        nonce = os.urandom(12)
        results = {}
        for b in self.backends():
            ct = b.encrypt(lg.DEFAULT_PB_KEY, nonce, data)
            results[b.name] = ct
            for other in self.backends():
                self.assertEqual(other.decrypt(lg.DEFAULT_PB_KEY, nonce, ct), data)
        self.assertEqual(len(set(results.values())), 1, results.keys())

    def test_tamper_is_detected(self):
        for b in self.backends():
            ct = bytearray(b.encrypt(lg.DEFAULT_PB_KEY, self.IV0, b"hello world"))
            ct[0] ^= 1
            with self.assertRaises(lg.InvalidTag):
                b.decrypt(lg.DEFAULT_PB_KEY, self.IV0, bytes(ct))

    def test_key_bytes(self):
        self.assertEqual(len(lg.DEFAULT_PB_KEY), 32)

    def test_pb_round_trip_and_unencrypted_fallback(self):
        md = metadata(["file:///w"])
        plain = ProtoFields().append(1, "t").append(7, md).serialize()
        enc = lg.encrypt_pb(plain)
        self.assertNotEqual(enc[12:], plain)
        self.assertEqual(lg.decrypt_pb(enc), (plain, True))
        self.assertEqual(lg.decrypt_pb(plain), (plain, False))
        with self.assertRaises(lg.LagrangeError):
            lg.decrypt_pb(b"\xff" * 40)

    def test_pb_metadata_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = make_pb(Path(tmp) / "c.pb", "c", metadata(["file:///old"]),
                        [step(14, text="hello there", created=T0)], source=17)
            info = lg.load_pb_info(p, keep_trajectory=True)
            self.assertTrue(info.pb_encrypted)
            self.assertEqual(info.source, 17)
            self.assertEqual(info.first_prompt, "hello there")
            traj = info.pb_trajectory
            traj.set(lg.TrajectoryF.METADATA, metadata(["file:///new"], project="p"))
            traj.remove(lg.TrajectoryF.SOURCE)
            p.write_bytes(lg.encrypt_pb(traj.serialize()))
            info2 = lg.load_pb_info(p, keep_trajectory=True)
            self.assertEqual(info2.metadata.get_strs(7), ["file:///new"])
            self.assertEqual(info2.source, 0)
            self.assertEqual(info2.pb_trajectory.get(9), b"\x0a\x03abc")


# ---------------------------------------------------------------------------
# URIs, titles, annotations, remapping
# ---------------------------------------------------------------------------


class UriTests(unittest.TestCase):
    def test_scrub_corrupted_wire_bytes(self):
        self.assertEqual(lg.scrub_uri(CORRUPT), "file:///HOME/Cooper%20Station")
        self.assertEqual(lg.scrub_uri("file:///\n\x1efile:///HOME/Lazarus Archive\x12\x08file:///\x1a\x00"),
                         "file:///HOME/Lazarus%20Archive")
        self.assertEqual(lg.scrub_uri('file:///\n#file:///HOME/Pod\x12#file:///HOME/Pod\x1a\x00"\x04main'),
                         "file:///HOME/Pod")
        self.assertEqual(lg.scrub_uri("file:///"), "")
        self.assertEqual(lg.scrub_uri("\x12\x08"), "")

    def test_double_encoding_is_fixed(self):
        self.assertEqual(lg.normalize_uri("file:///a/My%2520Folder/"), "file:///a/My%20Folder")
        self.assertEqual(lg.normalize_uri("file:///a/My Folder"), "file:///a/My%20Folder")
        self.assertEqual(lg.path_to_file_uri("/a/My%20Folder"), "file:///a/My%20Folder")
        self.assertEqual(lg.file_uri_to_path("file:///a/My%2520Folder"), "/a/My Folder")

    def test_windows_and_remote(self):
        self.assertEqual(lg.normalize_uri("file:///C:/Users/x"), "file:///c%3A/Users/x")
        self.assertEqual(lg.file_uri_to_path("file:///c%3A/Users/x"), "C:/Users/x")
        self.assertEqual(lg.normalize_uri("vscode-remote://ssh-remote+h/home/u/My%2520x"),
                         "vscode-remote://ssh-remote+h/home/u/My%20x")
        self.assertTrue(lg.is_valid_workspace_uri("vscode-remote://wsl+Ubuntu/home/u"))

    def test_git_root_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".git").mkdir(parents=True)
            (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
            (repo / "sub").mkdir()
            self.assertEqual(lg.find_git_root(str(repo / "sub")), str(repo))
            self.assertEqual(lg.read_git_branch(str(repo)), "main")
            self.assertIsNone(lg.find_git_root(str(Path(tmp) / "missing")))


class TitleTests(unittest.TestCase):
    def test_clean_title(self):
        long = "word " * 40
        out = lg.clean_title(long)
        self.assertLessEqual(len(out), 80)
        self.assertTrue(out.endswith("\u2026"))
        self.assertEqual(lg.clean_title("  a \n b  "), "a b")

    def test_long_prompt_becomes_short_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = lg.Env(home=Path(tmp), platform="darwin")
            cid = "12345678-0000-4000-8000-000000000000"
            make_db(env.conv_dir("hub") / (cid + ".db"), cid, metadata([]),
                    [step(14, text="ok"), step(14, text="Please audit the whole queue " * 40)])
            app = lg.Lagrange(env, out=lambda s: None)
            app.scan()
            title, source = app.resolve_title(app.convs[cid])
            self.assertEqual(source, "prompt")
            self.assertTrue(title.startswith("Please audit the whole queue"))
            self.assertLessEqual(len(title), 80)

    def test_pbtxt(self):
        text = 'archived:false  last_user_view_time:{seconds:1  nanos:2}'
        self.assertEqual(lg.pbtxt_get_title(text), "")
        new = lg.pbtxt_set_title(text, 'Say "hi"\\now\n\u00e9')
        self.assertEqual(lg.pbtxt_get_title(new), 'Say "hi"\\now\n\u00e9')
        self.assertIn("archived:false", new)
        again = lg.pbtxt_set_title(new, "Second")
        self.assertEqual(lg.pbtxt_get_title(again), "Second")
        self.assertEqual(again.count("title:"), 1)
        self.assertEqual(lg.pbtxt_get_title(r'title:"caf\303\251"'), "caf\u00e9")
        self.assertIs(lg.pbtxt_get_bool("pinned:true", "pinned"), True)


class RemapTests(unittest.TestCase):
    def test_paths_uris_and_boundaries(self):
        r = lg.Remapper([("/u/Gargantua/ring", "/u/Gargantua"), ("/u/Cooper Station", "/u/Dev/Endurance")])
        self.assertEqual(r.path("/u/Gargantua/ring/x"), "/u/Gargantua/x")
        self.assertEqual(r.path("/u/Gargantua/ringy"), "/u/Gargantua/ringy")
        self.assertEqual(r.uri("file:///u/Cooper%20Station/a"), "file:///u/Dev/Endurance/a")
        text = "open /u/Cooper Station/x and file:///u/Cooper%20Station and /u/Cooper Stations"
        self.assertEqual(r.text(text), "open /u/Dev/Endurance/x and file:///u/Dev/Endurance "
                                       "and /u/Cooper Stations")

    def test_idempotent_when_new_is_inside_old(self):
        r = lg.Remapper([("/a/proj", "/a/proj/src")])
        once = r.text("see /a/proj/file")
        self.assertEqual(once, "see /a/proj/src/file")
        self.assertEqual(r.text(once), once)
        self.assertEqual(r.path(r.path("/a/proj/x")), "/a/proj/src/x")

    def test_json_value(self):
        r = lg.Remapper([("/u/old", "/u/new")])
        data = {"folder": "file:///u/old", "map": {"file:///u/old/w.code-workspace": "p"}, "n": 1}
        self.assertEqual(r.json_value(data), {"folder": "file:///u/new",
                                              "map": {"file:///u/new/w.code-workspace": "p"}, "n": 1})


# ---------------------------------------------------------------------------
# End-to-end fixture
# ---------------------------------------------------------------------------

A = "aaaaaaaa-0000-4000-8000-000000000001"   # hub .db, old workspace path
S1 = "a1a1a1a1-0000-4000-8000-000000000002"  # subagent of A
P1 = "bbbbbbbb-0000-4000-8000-000000000003"  # .pb in hub and IDE, legacy workspace only
B = "cccccccc-0000-4000-8000-000000000004"   # IDE-only .db, TARS
C = "dddddddd-0000-4000-8000-000000000005"   # CLI-only .db, source=CLI
E = "eeeeeeee-0000-4000-8000-000000000006"   # CLI-only empty 0-step db
F = "ffffffff-0000-4000-8000-000000000007"   # CLI-only .pb, untagged (inferred workspace)
PROJ_ENDURANCE = "11111111-1111-4111-8111-111111111111"
PROJ_ENDURANCE_DUP = "22222222-2222-4222-8222-222222222222"
PROJ_HOME = "33333333-3333-4333-8333-333333333333"
PROJ_ARRAKIS = "44444444-4444-4444-8444-444444444444"


class Fixture(object):
    def __init__(self, tmp):
        self.home = Path(tmp) / "home"
        self.env = lg.Env(home=self.home, platform="darwin")
        h = str(self.home)
        self.dev = self.home / "Documents" / "Dev"
        self.endurance = self.dev / "Endurance"
        self.tars = self.dev / "TARS"
        self.arrakis = self.dev / "Arrakis"
        for repo in (self.endurance, self.tars):
            (repo / ".git").mkdir(parents=True)
            (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        self.arrakis.mkdir(parents=True)
        self.old_endurance = h + "/Cooper Station"
        self.endurance_uri = lg.path_to_file_uri(str(self.endurance))
        self.tars_uri = lg.path_to_file_uri(str(self.tars))
        self.arrakis_uri = lg.path_to_file_uri(str(self.arrakis))
        self.old_uri = lg.path_to_file_uri(self.old_endurance)
        hub, ide, cli = (self.env.surface_dirs[s] for s in ("hub", "ide", "cli"))
        self.hub, self.ide, self.cli = hub, ide, cli

        make_db(hub / "conversations" / (A + ".db"), A,
                metadata([self.old_uri], project=lg.OUTSIDE_PROJECT),
                [step(14, text="Build the docking module please", created=T0),
                 step(15, created=T0 + 10, extra=ProtoFields().append(1, self.old_endurance + "/src/a.ts")),
                 step(14, text="next", created=T0 + 20)], mtime=T0 + 100)
        make_db(hub / "conversations" / (S1 + ".db"), S1,
                metadata([self.old_uri], parent=A, root=A, depth=1),
                [step(14, text="sub task here", created=T0 + 5)], ttype=16, mtime=T0 + 50)
        (hub / "brain" / A).mkdir(parents=True)
        (hub / "brain" / A / "task.md").write_text("# Endurance Tasks\nPath " + self.old_endurance + "/x\n")

        p1_md = metadata([self.arrakis_uri], project=lg.OUTSIDE_PROJECT, legacy_only=True)
        p1_steps = [step(14, text="Fix the telemetry bugs now", created=T0 - 1000),
                    step(23, intent="Fix rendering bugs in deep arrakis. More detail.",
                         created=T0 - 900)]
        make_pb(hub / "conversations" / (P1 + ".pb"), P1, p1_md, p1_steps, mtime=T0 - 500)
        make_pb(ide / "conversations" / (P1 + ".pb"), P1, p1_md, p1_steps, mtime=T0 - 500)

        make_db(ide / "conversations" / (B + ".db"), B, metadata([self.tars_uri], project=""),
                [step(14, text="This is my tars navigation project", created=T0 + 200)], mtime=T0 + 300)
        (ide / "brain" / B).mkdir(parents=True)
        (ide / "brain" / B / "implementation_plan.md").write_text("# TARS Navigation Plan\n")
        (ide / "annotations").mkdir(parents=True)
        (ide / "annotations" / (B + ".pbtxt")).write_text("last_user_view_time:{seconds:5}")

        make_db(cli / "conversations" / (C + ".db"), C,
                metadata([self.old_uri], project=PROJ_ENDURANCE_DUP),
                [step(14, text="cli chat about endurance", created=T0 + 400)], source=17, mtime=T0 + 450)
        (cli / "annotations").mkdir(parents=True)
        (cli / "annotations" / (C + ".pbtxt")).write_text('title:"CLI Endurance Chat"')
        make_db(cli / "conversations" / (E + ".db"), E, metadata([self.old_uri]), [], mtime=T0)
        make_pb(cli / "conversations" / (F + ".pb"), F, metadata([], created=T0 + 600),
                [step(14, text="look at %s/src/main.go please" % self.arrakis, created=T0 + 600)],
                source=17, mtime=T0 + 650)
        (cli / "cache").mkdir(parents=True)
        (cli / "cache" / "last_conversations.json").write_text(json.dumps({self.old_endurance: C}))
        (cli / "cache" / "conversation_metadata.json").write_text(json.dumps({"conversations": {}}))
        (cli / SUMMARIES_DB).write_bytes(b"x")

        # Hub summaries: A has an LLM title; P1 has a title; B unknown.
        state = ProtoFields()
        for cid, s in ((A, summary("Endurance Ring Architecture", A, ws=CORRUPT)),
                       (P1, summary("Deep Arrakis Bug Fixes", P1)),
                       ("99999999-dead-4000-8000-000000000000", summary("Orphan", "x"))):
            state.append(1, lg.make_map_entry(cid, s))
        hub.mkdir(parents=True, exist_ok=True)
        (hub / lg.HUB_SUMMARIES_FILE).write_bytes(state.serialize())
        (hub / SUMMARIES_DB).write_bytes(b"sqlite placeholder")

        # Projects
        pdir = self.env.projects_dir
        pdir.mkdir(parents=True)
        self.write_project(PROJ_ENDURANCE, "Endurance", {"gitFolder": {"folderUri": self.endurance_uri,
                                                                        "allowWrite": True}},
                           settings={"x": 1})
        self.write_project(PROJ_ENDURANCE_DUP, "Endurance", {"gitFolder": {"folderUri":
                                                                            "file://" + str(self.endurance)}})
        self.write_project(PROJ_HOME, str(self.home), {"folderUri": lg.path_to_file_uri(h)})
        self.write_project(PROJ_ARRAKIS, "Arrakis", {"folderUri": self.arrakis_uri})

        # IDE state databases with corrupted rows and stale sidebar entries.
        bad_row = summary("Old Title", A, ws=CORRUPT)
        topic = lg.build_topic([(A, lg.row_with_inner(None, bad_row))])
        side_inner = ProtoFields().append(4, self.old_uri).append(5, ProtoFields().append(2, 1)
                                                                   .append(3, -1))
        side = lg.build_topic([(self.endurance_uri, lg.row_with_inner(None, side_inner))])
        init = ProtoFields()
        init.append(1, ProtoFields().append(1, lg.make_map_entry(A, bad_row)).append(
            1, lg.make_map_entry("99999999-dead-4000-8000-000000000000", bad_row)))
        init.append(14, ProtoFields().append(4, self.old_uri))
        for app in ("Antigravity", "Antigravity IDE"):
            make_state_db(self.env.state_db(app), {
                lg.USS_TRAJECTORY_KEY: topic, lg.USS_SIDEBAR_KEY: side,
                lg.LEGACY_INIT_STATE_KEY: base64.b64encode(init.serialize()).decode(),
                "other.key": "keep me"})
        user = self.env.app_user_dir("Antigravity IDE")
        (user / "globalStorage" / "storage.json").write_text(json.dumps(
            {"profileAssociations": {"workspaces": {self.old_uri: "__default__profile__"}},
             "windowsState": {"lastActiveWindow": {"folder": self.old_uri}}}))
        (user / "workspaceStorage" / "abc").mkdir(parents=True)
        (user / "workspaceStorage" / "abc" / "workspace.json").write_text(
            json.dumps({"folder": self.old_uri}))

    def write_project(self, pid, name, resource, settings=None):
        data = {"id": pid, "name": name, "projectResources": {"resources": [resource]}}
        if settings is not None:
            data["settings"] = settings
        (self.env.projects_dir / (pid + ".json")).write_text(json.dumps(data, indent=2))

    def app(self, **kw):
        lines, out = quiet()
        app = lg.Lagrange(self.env, out=out, **kw)
        app.lines = lines
        return app

    def hub_summaries(self):
        state = ProtoFields.parse((self.hub / lg.HUB_SUMMARIES_FILE).read_bytes())
        sums = {k: ProtoFields.parse(v) for k, v, _ in lg.map_entries(state, 1)}
        mods = {k: v for k, v, _ in lg.map_entries(state, 2)}
        return sums, mods


SUMMARIES_DB = lg.SUMMARIES_DB_FILE


def sync_opts(fx, **kw):
    base = dict(remaps=[(fx.old_endurance, str(fx.endurance))])
    base.update(kw)
    return lg.SyncOptions(**base)


@unittest.skipIf(os.name == "nt", "end-to-end fixture uses POSIX paths")
class SyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(self.tmp.name)
        patcher = mock.patch.object(lg, "find_running_processes", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_dry_run_changes_nothing(self):
        before = tree_digest(self.fx.home)
        app = self.fx.app(dry_run=True)
        app.sync(sync_opts(self.fx))
        self.assertTrue(app.actions)
        self.assertEqual(tree_digest(self.fx.home), before)

    def test_refuses_when_running(self):
        with mock.patch.object(lg, "find_running_processes", return_value=[(42, "Antigravity")]):
            with self.assertRaises(lg.LagrangeError):
                self.fx.app().sync(sync_opts(self.fx))
            self.fx.app(force=True).sync(sync_opts(self.fx))

    def test_full_sync(self):
        fx = self.fx
        a_mtime = os.stat(str(fx.hub / "conversations" / (A + ".db"))).st_mtime
        app = fx.app()
        app.sync(sync_opts(fx))
        hubc = fx.hub / "conversations"

        # Consolidation: IDE-only and CLI-only conversations now live in the Hub.
        for name in (A + ".db", S1 + ".db", P1 + ".pb", B + ".db", C + ".db", F + ".pb"):
            self.assertTrue((hubc / name).exists(), name)
        self.assertTrue((fx.hub / "brain" / B / "implementation_plan.md").exists())
        self.assertFalse((fx.cli / "conversations" / (C + ".db")).exists())
        self.assertFalse((fx.cli / "conversations" / (F + ".pb")).exists())
        # Empty 0-step stub is kept unless --prune-empty.
        self.assertTrue((hubc / (E + ".db")).exists())

        # IDE folders are linked to the Hub store; leftovers went to the backup.
        if hasattr(os, "symlink"):
            for sub in ("conversations", "brain", "annotations"):
                link = fx.ide / sub
                if link.is_symlink():
                    self.assertEqual(os.path.realpath(str(link)), os.path.realpath(str(fx.hub / sub)))

        # Projects: duplicate merged, TARS created, path-like name cleaned.
        pdir = fx.env.projects_dir
        self.assertFalse((pdir / (PROJ_ENDURANCE_DUP + ".json")).exists())
        self.assertTrue((app.backup_dir / ".gemini" / "config" / "projects" /
                         (PROJ_ENDURANCE_DUP + ".json")).exists())
        projects = {json.loads(p.read_text())["id"]: json.loads(p.read_text()) for p in pdir.glob("*.json")}
        self.assertEqual(projects[PROJ_HOME]["name"], "Home")
        tars = [p for p in projects.values() if p["name"] == "TARS"]
        self.assertEqual(len(tars), 1)
        self.assertEqual(tars[0]["projectResources"]["resources"][0]["gitFolder"]["folderUri"], fx.tars_uri)
        self.assertEqual(tars[0]["settings"], {})
        self.assertIs(tars[0]["isWorkspaceOnly"], False)
        tars_id = tars[0]["id"]

        # Trajectory metadata (A): remapped workspace, canonical project, git root, source=0.
        md, src = read_db_meta(hubc / (A + ".db"))
        self.assertEqual(md.get_strs(lg.MetaF.WORKSPACE_URIS), [fx.endurance_uri])
        self.assertEqual(md.get_str(lg.MetaF.PROJECT_ID), PROJ_ENDURANCE)
        ws = md.get_msgs(lg.MetaF.WORKSPACES)
        self.assertEqual(len(ws), 1)
        self.assertEqual(ws[0].get_str(lg.WsF.FOLDER_URI), fx.endurance_uri)
        self.assertEqual(ws[0].get_str(lg.WsF.GIT_ROOT_URI), fx.endurance_uri)
        self.assertEqual(ws[0].get_str(lg.WsF.BRANCH_NAME), "main")
        self.assertEqual(md.get_str(3), "init-state-id")
        self.assertEqual(src, 0)
        # mtime preserved so sort order is not disturbed.
        self.assertAlmostEqual(os.stat(str(hubc / (A + ".db"))).st_mtime, a_mtime, places=3)

        # Subagent keeps its parent link and inherits the project.
        smd, _ = read_db_meta(hubc / (S1 + ".db"))
        self.assertEqual(smd.get_str(lg.MetaF.PARENT_CONVERSATION_ID), A)
        self.assertEqual(smd.get_str(lg.MetaF.PROJECT_ID), PROJ_ENDURANCE)

        # IDE-only TARS conversation: new project id.
        bmd, _ = read_db_meta(hubc / (B + ".db"))
        self.assertEqual(bmd.get_str(lg.MetaF.PROJECT_ID), tars_id)

        # CLI conversation: duplicate project repointed and source cleared.
        cmd_, csrc = read_db_meta(hubc / (C + ".db"))
        self.assertEqual(cmd_.get_str(lg.MetaF.PROJECT_ID), PROJ_ENDURANCE)
        self.assertEqual(cmd_.get_strs(lg.MetaF.WORKSPACE_URIS), [fx.endurance_uri])
        self.assertEqual(csrc, 0)

        # Legacy .pb: re-encrypted with workspace_uris and project set; arrakis has no .git.
        info = lg.load_pb_info(hubc / (P1 + ".pb"), keep_trajectory=True)
        self.assertTrue(info.pb_encrypted)
        self.assertEqual(info.metadata.get_strs(lg.MetaF.WORKSPACE_URIS), [fx.arrakis_uri])
        self.assertEqual(info.metadata.get_str(lg.MetaF.PROJECT_ID), PROJ_ARRAKIS)
        self.assertFalse(info.metadata.get_msgs(1)[0].has(lg.WsF.GIT_ROOT_URI))
        self.assertEqual(info.pb_trajectory.get(9), b"\x0a\x03abc")
        self.assertEqual(info.step_count, 2)

        # Untagged CLI .pb: workspace inferred from its prompt, source cleared.
        finfo = lg.load_pb_info(hubc / (F + ".pb"))
        self.assertEqual(finfo.metadata.get_strs(lg.MetaF.WORKSPACE_URIS), [fx.arrakis_uri])
        self.assertEqual(finfo.metadata.get_str(lg.MetaF.PROJECT_ID), PROJ_ARRAKIS)
        self.assertEqual(finfo.source, 0)

        # Hub summaries.
        sums, mods = fx.hub_summaries()
        self.assertNotIn("99999999-dead-4000-8000-000000000000", sums)
        for cid in (A, S1, P1, B, C, F):
            self.assertIn(cid, sums)
            self.assertFalse(sums[cid].has(lg.SummaryF.SOURCE))
            self.assertEqual(sums[cid].get_int(lg.SummaryF.STATUS), 1)
        self.assertEqual(sums[A].get_str(1), "Endurance Ring Architecture")
        self.assertEqual(sums[A].get_msg(15).get_str(1), "Endurance Ring Architecture")
        self.assertEqual(sums[A].get(99), b"unknown-field")
        self.assertEqual(sums[A].get_int(2), 3)
        self.assertEqual(sums[A].get_int(16), 2)
        self.assertEqual(sums[A].get_msgs(9)[0].get_str(1), fx.endurance_uri)
        self.assertEqual(sums[P1].get_str(1), "Deep Arrakis Bug Fixes")
        self.assertEqual(sums[B].get_str(1), "TARS Navigation Plan")
        self.assertEqual(sums[C].get_str(1), "CLI Endurance Chat")
        self.assertEqual(sums[S1].get_msg(17).get_str(lg.MetaF.PARENT_CONVERSATION_ID), A)
        self.assertFalse(sums[S1].has(15))
        self.assertEqual(sums[A].get_msg(17).get_strs(7), [fx.endurance_uri])
        self.assertEqual(mods[A], int(a_mtime))
        self.assertEqual(sums[S1].get_int(22), 16)

        # Annotations backfilled for top-level conversations.
        ann = (fx.hub / "annotations" / (A + ".pbtxt")).read_text()
        self.assertEqual(lg.pbtxt_get_title(ann), "Endurance Ring Architecture")
        bann = (fx.hub / "annotations" / (B + ".pbtxt")).read_text()
        self.assertEqual(lg.pbtxt_get_title(bann), "TARS Navigation Plan")
        self.assertIn("last_user_view_time", bann)
        self.assertFalse((fx.hub / "annotations" / (S1 + ".pbtxt")).exists())

        # Summary databases are retired so the language server re-seeds them.
        self.assertFalse((fx.hub / SUMMARIES_DB).exists())
        self.assertFalse((fx.cli / SUMMARIES_DB).exists())

        # state.vscdb: clean rows with inner base64, sidebar URIs in field 4.
        for app_name in ("Antigravity", "Antigravity IDE"):
            path = fx.env.state_db(app_name)
            rows = dict(lg.parse_topic(read_state(path, lg.USS_TRAJECTORY_KEY)))
            self.assertIn(A, rows)
            self.assertIn(B, rows)
            inner = lg.row_inner(rows[A])
            self.assertEqual(inner.get_msgs(9)[0].get_str(1), fx.endurance_uri)
            self.assertEqual(inner.get_str(1), "Endurance Ring Architecture")
            side = lg.parse_topic(read_state(path, lg.USS_SIDEBAR_KEY))
            keys = [k for k, _ in side]
            self.assertEqual(keys.count(fx.endurance_uri), 1)
            self.assertIn(fx.tars_uri, keys)
            for k, row in side:
                self.assertEqual(lg.row_inner(row).get_str(4), k)
            self.assertEqual(read_state(path, "other.key"), "keep me")
            init = ProtoFields.parse(base64.b64decode(read_state(path, lg.LEGACY_INIT_STATE_KEY)))
            keys = [k for k, _, _ in lg.map_entries(init.get_msg(1), 1)]
            self.assertEqual(keys, [A])
            self.assertEqual(init.get_msgs(14)[0].get_str(4), fx.endurance_uri)

        # IDE storage remapped.
        user = fx.env.app_user_dir("Antigravity IDE")
        storage = json.loads((user / "globalStorage" / "storage.json").read_text())
        self.assertIn(fx.endurance_uri, storage["profileAssociations"]["workspaces"])
        self.assertEqual(json.loads((user / "workspaceStorage" / "abc" / "workspace.json")
                                    .read_text())["folder"], fx.endurance_uri)

        # CLI caches.
        self.assertFalse((fx.cli / "cache" / "conversation_metadata.json").exists())
        self.assertEqual(json.loads((fx.cli / "cache" / "last_conversations.json").read_text()), {})

        # Backup and manifest.
        self.assertTrue((app.backup_dir / "manifest.json").exists())
        self.assertTrue((app.backup_dir / ".gemini" / "antigravity" / lg.HUB_SUMMARIES_FILE).exists())

        # Second run is idempotent for trajectories.
        app2 = fx.app()
        app2.sync(sync_opts(fx))
        self.assertFalse([a for a in app2.actions if a.startswith("update ") and "metadata" in a],
                         app2.actions)
        self.assertFalse([a for a in app2.actions if a.startswith(("move ", "copy "))])

    def test_no_link_copies_ide_and_prune_empty(self):
        fx = self.fx
        fx.app().sync(sync_opts(fx, link_surfaces=False, prune_empty=True))
        self.assertTrue((fx.ide / "conversations" / (B + ".db")).exists())
        self.assertFalse((fx.ide / "conversations").is_symlink())
        self.assertTrue((fx.hub / "conversations" / (B + ".db")).exists())
        self.assertFalse((fx.hub / "conversations" / (E + ".db")).exists())
        self.assertFalse((fx.cli / "conversations" / (E + ".db")).exists())

    def test_status_reports_issues(self):
        lines, out = quiet()
        app = lg.Lagrange(self.fx.env, out=out)
        app.print_status(as_json=True, include_subagents=True)
        st = json.loads("\n".join(lines))
        self.assertEqual(st["top_level_conversations"], 6)
        self.assertEqual(st["subagents"], 1)
        joined = "\n".join(st["issues"])
        self.assertIn("duplicate projects", joined)
        self.assertIn("source=CLI", joined)
        self.assertIn("only in ide", joined)
        self.assertIn("corrupted workspace URI", joined)
        lines2, out2 = quiet()
        lg.Lagrange(self.fx.env, out=out2).print_status()
        self.assertTrue(any("Issues" in l for l in lines2))

    def test_rename_conversation(self):
        fx = self.fx
        fx.app().sync(sync_opts(fx))
        app = fx.app()
        app.rename_conversation(A[:8], "Renamed Chat")
        sums, _ = fx.hub_summaries()
        self.assertEqual(sums[A].get_str(1), "Renamed Chat")
        self.assertEqual(sums[A].get_msg(15).get_str(1), "Renamed Chat")
        self.assertEqual(sums[B].get_str(1), "TARS Navigation Plan")
        self.assertEqual(lg.pbtxt_get_title((fx.hub / "annotations" / (A + ".pbtxt")).read_text()),
                         "Renamed Chat")
        for app_name in ("Antigravity", "Antigravity IDE"):
            rows = dict(lg.parse_topic(read_state(fx.env.state_db(app_name), lg.USS_TRAJECTORY_KEY)))
            self.assertEqual(lg.row_inner(rows[A]).get_str(1), "Renamed Chat")
        with self.assertRaises(lg.LagrangeError):
            app.rename_conversation("zzzz", "x")

    def test_move_conversation_moves_children(self):
        fx = self.fx
        fx.app().sync(sync_opts(fx))
        fx.app().move_conversation(A, "Arrakis")
        hubc = fx.hub / "conversations"
        for cid in (A, S1):
            md, _ = read_db_meta(hubc / (cid + ".db"))
            self.assertEqual(md.get_strs(7), [fx.arrakis_uri])
            self.assertEqual(md.get_str(18), PROJ_ARRAKIS)
        sums, _ = fx.hub_summaries()
        self.assertEqual(sums[A].get_msg(17).get_str(18), PROJ_ARRAKIS)
        self.assertEqual(sums[A].get_str(1), "Endurance Ring Architecture")
        bmd, _ = read_db_meta(hubc / (B + ".db"))
        self.assertEqual(bmd.get_strs(7), [fx.tars_uri])
        other = fx.home / "elsewhere"
        other.mkdir()
        fx.app().move_conversation(B, str(other))
        bmd, _ = read_db_meta(hubc / (B + ".db"))
        self.assertEqual(bmd.get_strs(7), [lg.path_to_file_uri(str(other))])
        self.assertEqual(bmd.get_str(18), lg.OUTSIDE_PROJECT)

    def test_rename_and_merge_project(self):
        fx = self.fx
        cache = fx.cli / "cache" / "projects.json"
        cache.write_text(json.dumps({"projects": [{"id": PROJ_ARRAKIS, "name": "Arrakis"},
                                                  {"id": PROJ_ENDURANCE_DUP, "name": "Endurance"}]}))
        fx.app().rename_project("Arrakis", "Deep Arrakis")
        data = json.loads((fx.env.projects_dir / (PROJ_ARRAKIS + ".json")).read_text())
        self.assertEqual(data["name"], "Deep Arrakis")
        self.assertEqual(json.loads(cache.read_text())["projects"][0]["name"], "Deep Arrakis")

        fx.app().merge_projects_cmd(PROJ_ENDURANCE_DUP, PROJ_ENDURANCE)
        self.assertFalse((fx.env.projects_dir / (PROJ_ENDURANCE_DUP + ".json")).exists())
        md, src = read_db_meta(fx.cli / "conversations" / (C + ".db"))
        self.assertEqual(md.get_str(18), PROJ_ENDURANCE)
        self.assertEqual(json.loads(cache.read_text())["projects"][1]["id"], PROJ_ENDURANCE)
        with self.assertRaises(lg.LagrangeError):
            fx.app().rename_project("nope-nope", "x")

    def test_remap_path_deep(self):
        fx = self.fx
        fx.app().remap_path_cmd(fx.old_endurance, str(fx.endurance), deep=True)
        hubc = fx.hub / "conversations"
        md, _ = read_db_meta(hubc / (A + ".db"))
        self.assertEqual(md.get_strs(7), [fx.endurance_uri])
        conn = sqlite3.connect(str(hubc / (A + ".db")))
        payloads = [bytes(r[0]) for r in conn.execute("SELECT step_payload FROM steps ORDER BY idx")]
        conn.close()
        parsed = ProtoFields.parse(payloads[1])
        self.assertEqual(parsed.get_msg(98).get_str(1), str(fx.endurance) + "/src/a.ts")
        self.assertNotIn(fx.old_endurance.encode(), b"".join(payloads))
        brain = (fx.hub / "brain" / A / "task.md").read_text()
        self.assertIn(str(fx.endurance) + "/x", brain)
        user = fx.env.app_user_dir("Antigravity IDE")
        self.assertEqual(json.loads((user / "workspaceStorage" / "abc" / "workspace.json")
                                    .read_text())["folder"], fx.endurance_uri)
        # Duplicate projects (same folder after remap) are merged.
        self.assertFalse((fx.env.projects_dir / (PROJ_ENDURANCE_DUP + ".json")).exists())
        cmd_, _ = read_db_meta(fx.cli / "conversations" / (C + ".db"))
        self.assertEqual(cmd_.get_str(18), PROJ_ENDURANCE)
        side = lg.parse_topic(read_state(fx.env.state_db("Antigravity"), lg.USS_SIDEBAR_KEY))
        self.assertEqual(lg.row_inner(side[0][1]).get_str(4), fx.endurance_uri)

    def test_create_project_and_cli(self):
        fx = self.fx
        lines, out = quiet()
        code = lg.main(["create-project", "--home", str(fx.home), "--force", "Notes",
                        str(fx.home / "Documents")])
        self.assertEqual(code, 0)
        names = [json.loads(p.read_text())["name"] for p in fx.env.projects_dir.glob("*.json")]
        self.assertIn("Notes", names)
        with mock.patch("sys.stderr"):
            self.assertEqual(lg.main(["rename-project", "--home", str(fx.home), "--force",
                                      "missing-project", "x"]), 2)


# ---------------------------------------------------------------------------
# Open-source hygiene
# ---------------------------------------------------------------------------

# Hex-encoded so this test file does not trip its own scan.
FORBIDDEN_SUBSTRINGS = [bytes.fromhex(h).decode() for h in (
    "6a6574736b69", "676f6f676c6533", "63697463", "626c617a65", "7069706572",
    "6372697469717565", "6369646572", "6a6574626f78", "65786166756e6374696f6e",
    "636f646569756d5f636f6d6d6f6e", "76726740", "646173682e7672672e726f636b73",
    "62617269756d", "736e6f7762616c6c", "6d656e64656c", "636f646569756d",
    "73746f636b70696c65", "686f6d65626f78", "64617461207661756c74", "31316d61",
    "62766d73", "3165346433623239", "3863343666646535", "6135356166386561",
)]
FORBIDDEN_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9_])(?:b|cl|go)/[A-Za-z0-9]", re.I),
    re.compile(r"(?<![A-Za-z])exa\.", re.I),
]


class ConfidentialityTests(unittest.TestCase):
    def test_no_internal_identifiers_in_repository(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(str(ROOT)):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "build", "dist")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "rb") as fh:
                        text = fh.read().decode("utf-8", "ignore")
                except OSError:
                    continue
                low = text.lower()
                for token in FORBIDDEN_SUBSTRINGS:
                    joined = token
                    if joined in low:
                        offenders.append("%s: %s" % (os.path.relpath(path, str(ROOT)), joined))
                for pat in FORBIDDEN_PATTERNS:
                    for m in pat.finditer(text):
                        offenders.append("%s: %r" % (os.path.relpath(path, str(ROOT)), m.group(0)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
