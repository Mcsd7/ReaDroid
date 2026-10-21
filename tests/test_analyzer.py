from __future__ import annotations

import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from readroid.analyzer import (analyze_manifest, decompile_with_jadx, inspect_apk,
                               scan_strings, validate_apk)
from readroid import __version__, axml, builder


# ---------------------------------------------------------------- fixtures

def build_axml(events) -> bytes:
    """Monta um AndroidManifest.xml binário (AXML) mínimo a partir de eventos
    ('start', tag, {attrs}) / ('end', tag), pra testar o parser sem depender
    de um APK real."""
    strings: list[str] = []

    def idx(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    ns = idx("http://schemas.android.com/apk/res/android")
    body = b""
    for ev in events:
        if ev[0] == "start":
            _, tag, attrs = ev
            name_i = idx(tag)
            packed = b""
            for k, v in attrs.items():
                n_i = idx(k)
                a_ns = 0xFFFFFFFF if k == "package" else ns
                if isinstance(v, bool):
                    packed += struct.pack("<IIIHBBI", a_ns, n_i, 0xFFFFFFFF, 8, 0, 0x12, 0xFFFFFFFF if v else 0)
                elif isinstance(v, int):
                    packed += struct.pack("<IIIHBBI", a_ns, n_i, 0xFFFFFFFF, 8, 0, 0x10, v)
                else:
                    s_i = idx(v)
                    packed += struct.pack("<IIIHBBI", a_ns, n_i, s_i, 8, 0, 0x03, s_i)
            size = 36 + len(packed)
            body += struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
            body += struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_i, 20, 20, len(attrs), 0, 0, 0) + packed
        else:
            _, tag = ev
            body += struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, idx(tag))

    offsets, blob = [], b""
    for s in strings:
        offsets.append(len(blob))
        blob += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(blob) % 4:
        blob += b"\x00"
    pool_hdr = 28 + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, 28, pool_hdr + len(blob), len(strings), 0, 0, pool_hdr, 0)
    pool += struct.pack("<%dI" % len(strings), *offsets) + blob
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


MANIFEST_EVENTS = [
    ("start", "manifest", {"package": "com.exemplo.app", "versionName": "2.0", "versionCode": 5}),
    ("start", "uses-permission", {"name": "android.permission.RECEIVE_SMS"}), ("end", "uses-permission"),
    ("start", "uses-permission", {"name": "android.permission.INTERNET"}), ("end", "uses-permission"),
    ("start", "application", {"debuggable": True, "allowBackup": True}),
    ("start", "activity", {"name": ".Main", "exported": True}), ("end", "activity"),
    ("end", "application"), ("end", "manifest"),
]


def make_apk(root: Path, manifest: bytes | None = None, extra: dict | None = None) -> Path:
    apk = root / "sample.apk"
    with zipfile.ZipFile(apk, "w") as z:
        if manifest is not None:
            z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00 https://example.com/api test.example.org 192.168.1.2 "
                                  b"android.content.pm.PackageManager androidx.core.app.NotificationCompat")
        z.writestr("res/layout/main.xml", b"<view />")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return apk


# ---------------------------------------------------------------- testes

class AxmlTests(unittest.TestCase):
    def test_parses_binary_manifest(self):
        events = axml.parse_events(build_axml(MANIFEST_EVENTS))
        m = axml.to_manifest_dict(events)
        self.assertEqual(m["package"], "com.exemplo.app")
        self.assertEqual(m["version_name"], "2.0")
        names = {p["name"] for p in m["permissions"]}
        self.assertIn("android.permission.RECEIVE_SMS", names)
        self.assertEqual(m["application"]["debuggable"], "true")
        self.assertEqual(m["components"][0]["exported"], "true")

    def test_rejects_garbage(self):
        with self.assertRaises(axml.AxmlError):
            axml.parse_events(b"not an axml at all")


class AnalyzerTests(unittest.TestCase):
    def test_inspect_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp), b"<manifest package='org.example' />")
            result = inspect_apk(apk)
            self.assertEqual(result["file_name"], "sample.apk")
            self.assertEqual(result["dex_files"], ["classes.dex"])
            self.assertEqual(len(result["sha256"]), 64)
            self.assertEqual(result["version"], __version__)

    def test_scan_strings_filters_package_name_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp))
            result = scan_strings(apk)
            self.assertTrue(any("example.com" in v for v in result["urls"]))
            self.assertIn("192.168.1.2", result["ipv4_candidates"])
            # Nomes de classe Android/Kotlin não devem aparecer como "domínio"
            for noisy in ("android.content.pm.packagemanager", "androidx.core.app.notificationcompat"):
                self.assertNotIn(noisy, result["domains"])
            self.assertIn("test.example.org", result["domains"])

    def test_scan_strings_reports_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            many = b" ".join(f"host{i}.example.com".encode() for i in range(3200))
            apk = make_apk(Path(tmp), extra={"assets/data.txt": many})
            result = scan_strings(apk)
            self.assertIn("domains", result["truncated_categories"])
            self.assertLessEqual(len(result["domains"]), 3000)

    def test_manifest_text_path_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = (b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                       b'package="org.example"><uses-permission android:name="android.permission.INTERNET"/>'
                       b'<application android:debuggable="false"><activity android:name=".Main" '
                       b'android:exported="true"/></application></manifest>')
            apk = make_apk(Path(tmp), manifest)
            result = analyze_manifest(apk, Path(tmp) / "out")
            self.assertTrue(result["decoded"])
            self.assertEqual(result["permissions"][0]["name"], "android.permission.INTERNET")
            self.assertEqual(result["components"][0]["exported"], "true")

    def test_manifest_with_dtd_is_rejected_without_entity_expansion(self):
        # Manifesto Android válido nunca tem DTD. Sem o bloqueio, o ElementTree
        # expande estas entidades e um arquivo de poucos KB vira megabytes na RAM.
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz ['
                b'<!ENTITY lol "lol">'
                b'<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                b'<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
                b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
                b']><manifest package="&lol3;"/>')
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp), bomb)
            result = analyze_manifest(apk, Path(tmp) / "out")
        self.assertFalse(result["decoded"])
        self.assertIn("DTD", result["reason"])
        # Nem JADX/Apktool/aapt2 devem receber um manifesto recusado por DTD.
        self.assertEqual(result["optional_tool_runs"], {})

    def test_manifest_above_size_limit_is_reported_not_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = b"<manifest>" + b" " * 5000 + b"</manifest>"
            apk = make_apk(Path(tmp), big)
            with patch("readroid.analyzer.MAX_MANIFEST_BYTES", 1024):
                inspected = inspect_apk(apk)
                analyzed = analyze_manifest(apk, Path(tmp) / "out")
        self.assertEqual(inspected["manifest"]["format"], "não lido (acima do limite de tamanho)")
        self.assertTrue(any("limite" in warning for warning in inspected["warnings"]))
        self.assertFalse(analyzed["decoded"])
        self.assertIn("limite", analyzed["reason"])
        self.assertEqual(analyzed["permissions"], [])

    def test_manifest_binary_axml_decoded_natively(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp), build_axml(MANIFEST_EVENTS))
            result = analyze_manifest(apk, Path(tmp) / "out")
            self.assertTrue(result["decoded"])
            self.assertEqual(result["decoded_by"], "readroid (leitor AXML nativo)")
            self.assertEqual(result["package"], "com.exemplo.app")
            self.assertEqual(result["optional_tool_runs"], {})  # nenhuma ferramenta externa foi chamada

    def test_any_zip_extension_accepted_with_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = make_apk(Path(tmp), b"<manifest package='org.example' />")
            renamed = apk.with_suffix(".xapk")
            apk.rename(renamed)
            validate_apk(renamed)  # não deve levantar exceção
            result = inspect_apk(renamed)
            self.assertEqual(result["warnings"], [])  # .xapk é extensão conhecida

            renamed2 = Path(tmp) / "sample.bin"
            Path(renamed).rename(renamed2)
            result2 = inspect_apk(renamed2)
            self.assertTrue(result2["warnings"])  # extensão incomum gera aviso, não erro

    def test_jadx_partial_output_is_reported_as_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = make_apk(root, b"<manifest package='org.example'/>")
            output = root / "out"

            def fake_run(command, timeout=180):
                (output / "sources" / "org" / "example").mkdir(parents=True)
                (output / "sources" / "org" / "example" / "Main.java").write_text("class Main {}")
                return {"returncode": 1, "stdout": "", "stderr": "finished with errors"}

            with patch("readroid.analyzer.shutil.which", return_value="/usr/bin/jadx"), \
                 patch("readroid.analyzer._run", side_effect=fake_run):
                result = decompile_with_jadx(apk, output)

            self.assertFalse(result["ok"])
            self.assertTrue(result["partial"])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["java_files"], 1)
            self.assertEqual(result["files_generated"], 1)


class BuilderTests(unittest.TestCase):
    def test_apply_quick_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            decoded = Path(tmp) / "decoded"
            decoded.mkdir()
            (decoded / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">'
                '<application android:allowBackup="true"></application></manifest>')
            result = builder.apply_quick_edits(decoded, ["debuggable_on", "add_internet"])
            self.assertTrue(result["ok"])
            text = (decoded / "AndroidManifest.xml").read_text()
            self.assertIn('android:debuggable="true"', text)
            self.assertIn("android.permission.INTERNET", text)

    def test_full_pipeline_with_fake_tools(self):
        """Simula apktool/zipalign/apksigner (binários reais podem não existir no CI)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decoded = root / "decoded"
            decoded.mkdir()
            (decoded / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x">'
                '<application></application></manifest>')
            (decoded / "apktool.yml").write_text("version: 2.9.0")
            work = root / "work"
            keystore = root / "ks.jks"

            def fake_which(name):
                return f"/usr/bin/{name}" if name in ("apktool", "zipalign", "keytool", "apksigner") else None

            def fake_run(cmd, timeout=180):
                tool = Path(cmd[0]).name
                if tool == "apktool":
                    out = Path(cmd[cmd.index("-o") + 1])
                    out.write_bytes(b"PK\x03\x04fake-unsigned")
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if tool == "zipalign":
                    out = Path(cmd[-1])
                    out.write_bytes(b"PK\x03\x04fake-aligned")
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if tool == "keytool":
                    keystore.write_bytes(b"fake-keystore")
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if tool == "apksigner" and cmd[1] == "sign":
                    return {"returncode": 0, "stdout": "", "stderr": ""}
                if tool == "apksigner" and cmd[1] == "verify":
                    return {"returncode": 0, "stdout": "Verified", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            with patch("readroid.builder.shutil.which", side_effect=fake_which), \
                 patch("readroid.builder._run", side_effect=fake_run):
                result = builder.build_pipeline(decoded, work, keystore, quick_edits=["debuggable_on"])

            self.assertTrue(result["ok"], result["steps"])
            self.assertTrue(Path(result["final_apk"]).is_file())
            self.assertIn('android:debuggable="true"', (decoded / "AndroidManifest.xml").read_text())
            self.assertEqual(result["steps"]["sign"]["scheme"], "v1 + v2 + v3")

    def test_rename_package_moves_smali_and_updates_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            decoded = Path(tmp) / "decoded"
            decoded.mkdir()
            (decoded / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.velho.app">'
                '<application android:name="com.velho.app.App">'
                '<activity android:name="com.velho.app.MainActivity"/>'
                '</application></manifest>')
            main_dir = decoded / "smali" / "com" / "velho" / "app"
            main_dir.mkdir(parents=True)
            (main_dir / "MainActivity.smali").write_text(
                ".class public Lcom/velho/app/MainActivity;\n.super Landroid/app/Activity;\n"
                'const-string v1, "com.velho.app2.Outro"\n')  # pacote vizinho parecido, não pode mudar
            other_dir = decoded / "smali" / "com" / "outro" / "lib"
            other_dir.mkdir(parents=True)
            (other_dir / "Lib.smali").write_text(".class public Lcom/outro/lib/Lib;\n.super Ljava/lang/Object;\n")

            result = builder.rename_package(decoded, "com.novo.apprenomeado")

            self.assertTrue(result["ok"])
            self.assertEqual(result["old_package"], "com.velho.app")
            self.assertEqual(result["directories_moved"], 1)
            manifest_text = (decoded / "AndroidManifest.xml").read_text()
            self.assertIn('package="com.novo.apprenomeado"', manifest_text)
            self.assertIn('android:name="com.novo.apprenomeado.MainActivity"', manifest_text)
            moved = decoded / "smali" / "com" / "novo" / "apprenomeado" / "MainActivity.smali"
            self.assertTrue(moved.is_file())
            moved_text = moved.read_text()
            self.assertIn("Lcom/novo/apprenomeado/MainActivity;", moved_text)
            self.assertIn("com.velho.app2.Outro", moved_text)  # pacote vizinho intacto
            self.assertFalse((decoded / "smali" / "com" / "velho").exists())  # pasta antiga limpa
            self.assertEqual(other_dir.joinpath("Lib.smali").read_text(),
                             ".class public Lcom/outro/lib/Lib;\n.super Ljava/lang/Object;\n")  # outro pacote intacto

    def test_rename_package_rejects_invalid_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            decoded = Path(tmp) / "decoded"
            decoded.mkdir()
            (decoded / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x"/>')
            for bad in ("semponto", "1com.app", "com..app", ""):
                result = builder.rename_package(decoded, bad)
                self.assertFalse(result["ok"], bad)

    def test_pipeline_reports_missing_apktool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decoded = root / "decoded"
            decoded.mkdir()
            with patch("readroid.builder.shutil.which", return_value=None):
                result = builder.build_pipeline(decoded, root / "work", root / "ks.jks")
            self.assertFalse(result["ok"])
            self.assertIn("Apktool", result["steps"]["rebuild"]["message"])


if __name__ == "__main__":
    unittest.main()
