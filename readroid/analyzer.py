"""Rotinas de análise estática. Não instala, executa nem altera o APK analisado."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from . import __version__, axml

MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 256 * 1024 * 1024
MAX_REPORT_ITEMS = 3000
# Manifestos reais têm alguns KB. O limite existe para um APK craftado não
# conseguir carregar centenas de MB na RAM do celular com um único arquivo.
MAX_MANIFEST_BYTES = 16 * 1024 * 1024

URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,500}", re.I)
# Lista de TLDs reais (não "qualquer coisa.palavra"), senão nomes de classe Java/Kotlin
# e nomes de arquivo viram "domínio" por acidente (ex.: classes.dex, gate.php).
_TLDS = (rb"com|net|org|io|dev|app|gov|edu|mil|info|biz|name|pro|xyz|top|online|site|club|vip|link|click|"
        rb"shop|store|live|icu|buzz|cyou|work|space|tech|cc|ws|pw|su|me|co|ai|br|ru|cn|tk|ml|ga|cf|gq|"
        rb"onion|duckdns|ngrok")
DOMAIN_RE = re.compile(rb"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + rb")\b")
IPV4_RE = re.compile(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
# Prefixos de pacotes Android/Java/Kotlin que combinam com a forma de um domínio
# ("android.content.pm") mas nunca são um - filtrados antes de entrar no relatório.
_NOT_DOMAIN_PREFIXES = (b"android.", b"androidx.", b"java.", b"javax.", b"kotlin.", b"kotlinx.", b"dalvik.",
                        b"com.android.", b"com.google.android.", b"org.apache.", b"org.json.", b"org.w3c.",
                        b"org.xml.", b"sun.", b"libcore.")

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = "{" + ANDROID_NS + "}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    # Lemos em blocos para não carregar um APK inteiro na memória.
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], timeout: int = 180) -> dict[str, Any]:
    """Executa uma ferramenta opcional sem passar argumentos por um shell."""
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return {"returncode": result.returncode,
                "stdout": result.stdout[-20000:],
                "stderr": result.stderr[-20000:]}
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "Ferramenta não encontrada."}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": f"Tempo limite ({timeout}s) excedido."}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)}


class ManifestTooLarge(ValueError):
    """O AndroidManifest.xml excede o limite que o ReaDroid aceita ler."""


def _read_manifest_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Lê o AndroidManifest.xml com teto de tamanho.

    O APK é entrada não confiável: um ZIP pode declarar um manifesto de centenas
    de MB comprimido em poucos KB. Lemos no máximo MAX_MANIFEST_BYTES (+1 byte só
    para detectar estouro), em vez de confiar no tamanho declarado ou carregar
    tudo na memória. Acima do limite levantamos ManifestTooLarge.
    """
    if info.file_size > MAX_MANIFEST_BYTES:
        raise ManifestTooLarge(
            f"AndroidManifest.xml declara {info.file_size} bytes, acima do limite de {MAX_MANIFEST_BYTES} bytes.")
    with archive.open(info) as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        # Tamanho declarado no índice do ZIP não bate com o conteúdo entregue.
        raise ManifestTooLarge(
            f"AndroidManifest.xml entrega mais de {MAX_MANIFEST_BYTES} bytes de conteúdo.")
    return data


# Extensões que normalmente guardam um ZIP/APK válido. Não é mais um bloqueio rígido:
# o que importa é o conteúdo (zipfile.is_zipfile), a extensão só gera um aviso.
KNOWN_APK_EXTENSIONS = (".apk", ".apks", ".xapk", ".apk.1")


def validate_apk(path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise ValueError("O caminho não aponta para um arquivo existente.")
    if path.stat().st_size == 0:
        raise ValueError("O arquivo está vazio.")
    if not zipfile.is_zipfile(path):
        raise ValueError("O arquivo não parece ser um APK/ZIP válido (não é um ZIP).")


def extension_warning(path: Path) -> str | None:
    if path.suffix.lower() not in KNOWN_APK_EXTENSIONS:
        return f"Extensão incomum para APK ({path.suffix or 'sem extensão'}); analisando pelo conteúdo mesmo assim."
    return None


def inspect_apk(path: Path) -> dict[str, Any]:
    validate_apk(path)
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        dex_files = [name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", name)]
        native_libs = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        resource_count = sum(name.startswith("res/") for name in names)
        asset_count = sum(name.startswith("assets/") for name in names)
        manifest_info = next((item for item in infos if item.filename == "AndroidManifest.xml"), None)
        manifest_kind = "ausente"
        warnings: list[str] = []
        if manifest_info:
            try:
                content = _read_manifest_entry(archive, manifest_info)
                manifest_kind = "XML texto" if content.lstrip().startswith(b"<") else "XML binário Android (AXML)"
            except ManifestTooLarge as exc:
                manifest_kind = "não lido (acima do limite de tamanho)"
                warnings.append(f"{exc} Conteúdo do manifesto ignorado.")
            except (OSError, RuntimeError, zipfile.BadZipFile):
                manifest_kind = "não foi possível ler"
        warning = extension_warning(path)
        if warning:
            warnings.append(warning)
        return {
            "tool": "ReaDroid", "version": __version__,
            "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
            "file_name": path.name, "file_size_bytes": path.stat().st_size,
            "sha256": sha256_file(path), "zip_entry_count": len(infos),
            "manifest": {"present": manifest_info is not None, "format": manifest_kind},
            "dex_files": dex_files, "native_libraries": native_libs,
            "resource_file_count": resource_count, "asset_file_count": asset_count,
            "file_list_sample": names[:500],
            "warnings": warnings,
            "note": "Inspeção estática; a presença de um arquivo não prova comportamento malicioso."
        }


def _looks_like_text_xml(data: bytes) -> bool:
    return data.lstrip().startswith(b"<")


def _parse_manifest_xml(data: bytes) -> dict[str, Any]:
    """Extrai campos básicos quando o manifesto está em XML legível."""
    result: dict[str, Any] = {"decoded": False, "permissions": [], "components": [], "application": {}}
    # Um AndroidManifest.xml real nunca declara DTD/entidades. O ElementTree
    # expande entidades internas, então um manifesto de poucos KB com
    # <!ENTITY> aninhadas vira gigabytes na memória ("billion laughs").
    # Recusamos antes de entregar os dados ao parser.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        result["reason"] = ("Manifesto declara DTD/entidades, o que um AndroidManifest.xml válido "
                            "nunca faz; recusado para evitar expansão de entidades.")
        # Também não mandamos o APK para JADX/Apktool: eles parseariam o mesmo XML.
        result["dtd_rejected"] = True
        return result
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        result["reason"] = "Manifesto não é XML textual válido; tente JADX/Apktool para decodificar AXML."
        return result
    result["decoded"] = True
    result["package"] = root.attrib.get("package")
    result["version_code"] = root.attrib.get(A + "versionCode")
    result["version_name"] = root.attrib.get(A + "versionName")
    permission_tags = {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag in permission_tags:
            name = node.attrib.get(A + "name") or node.attrib.get("name")
            if name:
                result["permissions"].append({"name": name, "max_sdk": node.attrib.get(A + "maxSdkVersion")})
        if tag == "application":
            result["application"] = {
                "label": node.attrib.get(A + "label"),
                "debuggable": node.attrib.get(A + "debuggable"),
                "allow_backup": node.attrib.get(A + "allowBackup"),
                "uses_cleartext_traffic": node.attrib.get(A + "usesCleartextTraffic")
            }
        if tag in {"activity", "activity-alias", "service", "receiver", "provider"}:
            result["components"].append({
                "type": tag,
                "name": node.attrib.get(A + "name"),
                "exported": node.attrib.get(A + "exported"),
                "permission": node.attrib.get(A + "permission")
            })
    result["permissions"] = sorted(result["permissions"], key=lambda item: item["name"])
    return result


def analyze_manifest(path: Path, output_dir: Path) -> dict[str, Any]:
    validate_apk(path)
    too_large = None
    with zipfile.ZipFile(path) as archive:
        try:
            manifest_info = archive.getinfo("AndroidManifest.xml")
        except KeyError:
            raise ValueError("AndroidManifest.xml não foi encontrado dentro do APK.") from None
        try:
            manifest_data = _read_manifest_entry(archive, manifest_info)
        except ManifestTooLarge as exc:
            too_large = str(exc)
    if too_large:
        # Devolvemos um relatório normal (em vez de exceção) para o menu salvar
        # e mostrar o motivo, do mesmo jeito que um manifesto não decodificado.
        return {
            "tool": "ReaDroid", "apk": path.name, "sha256": sha256_file(path),
            "decoded": False, "permissions": [], "components": [], "application": {},
            "reason": f"{too_large} O manifesto não foi carregado para não consumir a memória do aparelho.",
            "warnings": [too_large],
            "security_note": "Manifesto fora do tamanho esperado é, por si só, um sinal para revisão manual.",
        }

    parsed: dict[str, Any]
    if _looks_like_text_xml(manifest_data):
        parsed = _parse_manifest_xml(manifest_data)
    else:
        # Praticamente todo APK real cai aqui: o manifesto é binário (AXML).
        # Decodificamos nativamente primeiro; só recorremos a JADX/Apktool/aapt2
        # se o nosso parser falhar (manifesto corrompido de propósito, por exemplo).
        try:
            events = axml.parse_events(manifest_data)
            parsed = axml.to_manifest_dict(events)
            parsed["decoded_by"] = "readroid (leitor AXML nativo)"
        except axml.AxmlError as exc:
            parsed = {"decoded": False, "permissions": [], "components": [],
                      "reason": f"Falha ao decodificar o AXML nativamente ({exc}); tentando ferramentas externas."}

    tools: dict[str, Any] = {}
    # Manifesto recusado por DTD/entidades não deve ser reenviado a outra
    # ferramenta que faria o mesmo parse (e a mesma expansão).
    can_fallback = not parsed.get("decoded") and not parsed.get("dtd_rejected")
    # JADX pode exportar o manifesto decodificado junto dos recursos. A saída é tratada como dado, não como comando.
    jadx = shutil.which("jadx")
    if can_fallback and jadx:
        jadx_out = output_dir / "jadx_manifest"
        result = _run([jadx, "-d", str(jadx_out), "--no-src", str(path)], timeout=240)
        tools["jadx"] = {"returncode": result["returncode"], "stderr": result["stderr"]}
        candidates = [jadx_out / "resources" / "AndroidManifest.xml", jadx_out / "AndroidManifest.xml"]
        for candidate in candidates:
            if candidate.is_file():
                parsed = _parse_manifest_xml(candidate.read_bytes())
                parsed["decoded_by"] = "jadx"
                break

    apktool = shutil.which("apktool")
    if can_fallback and apktool:
        apktool_out = output_dir / "apktool_manifest"
        result = _run([apktool, "d", "-f", "-s", "-o", str(apktool_out), str(path)], timeout=240)
        tools["apktool"] = {"returncode": result["returncode"], "stderr": result["stderr"]}
        candidate = apktool_out / "AndroidManifest.xml"
        if candidate.is_file():
            parsed = _parse_manifest_xml(candidate.read_bytes())
            parsed["decoded_by"] = "apktool"

    # aapt2 pode fornecer ao menos a lista de permissões quando não conseguimos obter XML.
    aapt2 = shutil.which("aapt2")
    if can_fallback and aapt2:
        result = _run([aapt2, "dump", "permissions", str(path)], timeout=120)
        tools["aapt2"] = {"returncode": result["returncode"], "stderr": result["stderr"]}
        permission_names = sorted(set(re.findall(
            r"(?:uses-permission(?:-sdk-\d+)?):\s*(?:name=)?['\"]?([A-Za-z0-9_.]+)",
            result["stdout"] + "\n" + result["stderr"])))
        if permission_names:
            parsed["permissions"] = [{"name": name, "max_sdk": None} for name in permission_names]
            parsed["permissions_source"] = "aapt2 dump permissions"

    parsed["tool"] = "ReaDroid"
    parsed["apk"] = path.name
    parsed["sha256"] = sha256_file(path)
    parsed["optional_tool_runs"] = tools
    parsed["security_note"] = "Permissões e flags são sinais para revisão; não classificam sozinhos um app como seguro ou malicioso."
    return parsed


def scan_strings(path: Path) -> dict[str, Any]:
    validate_apk(path)
    found: dict[str, set[str]] = {"urls": set(), "domains": set(), "ipv4_candidates": set()}
    truncated: set[str] = set()  # categorias que bateram no limite (o relatório pode estar incompleto)
    scanned = 0
    skipped_large = 0

    def add(category: str, value: str) -> None:
        bucket = found[category]
        if value in bucket:
            return
        if len(bucket) >= MAX_REPORT_ITEMS:
            truncated.add(category)
            return
        bucket.add(value)

    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            # Limites simples evitam que um APK com arquivos enormes consuma toda a memória.
            if info.file_size > MAX_ENTRY_BYTES:
                skipped_large += 1
                continue
            name = info.filename.lower()
            allowed = (name.endswith((".dex", ".xml", ".arsc", ".so", ".txt", ".json", ".js", ".html", ".properties", ".smali"))
                       or name.startswith("assets/"))
            if not allowed:
                continue
            if scanned >= MAX_TOTAL_SCAN_BYTES:
                break
            try:
                data = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            remaining = MAX_TOTAL_SCAN_BYTES - scanned
            data = data[:remaining]
            scanned += len(data)
            for item in URL_RE.findall(data):
                add("urls", item.decode("utf-8", "replace"))
            for item in DOMAIN_RE.findall(data):
                low = item.lower()
                if low.startswith(_NOT_DOMAIN_PREFIXES):
                    continue
                add("domains", low.decode("ascii", "replace"))
            for raw in IPV4_RE.findall(data):
                candidate = raw.decode("ascii", "replace")
                try:
                    ipaddress.IPv4Address(candidate)
                    add("ipv4_candidates", candidate)
                except ipaddress.AddressValueError:
                    pass
    return {
        "tool": "ReaDroid", "apk": path.name, "sha256": sha256_file(path),
        "bytes_scanned": scanned, "large_entries_skipped": skipped_large,
        "urls": sorted(found["urls"]),
        "domains": sorted(found["domains"]),
        "ipv4_candidates": sorted(found["ipv4_candidates"]),
        "truncated_categories": sorted(truncated),
        "note": "São correspondências textuais, não confirmação de conexões ou atividade maliciosa. "
                "Domínios podem ser nomes de bibliotecas, documentação ou exemplos. Categorias em "
                "'truncated_categories' bateram no limite de itens e podem estar incompletas."
    }


def decompile_with_jadx(path: Path, output_dir: Path, threads: int = 2) -> dict[str, Any]:
    """Decompila com JADX e distingue sucesso completo, parcial e falha real."""
    validate_apk(path)
    jadx = shutil.which("jadx")
    if not jadx:
        return {"ok": False, "partial": False, "status": "failed",
                "message": "JADX não encontrado. Instale-o pelo repositório do Termux e tente novamente."}
    output_dir.mkdir(parents=True, exist_ok=True)
    # Limitamos threads para reduzir a pressão sobre a RAM em celulares.
    command = [jadx, "--threads-count", str(max(1, min(threads, 4))), "-d", str(output_dir), str(path)]
    result = _run(command, timeout=900)
    files = [item for item in output_dir.rglob("*") if item.is_file()]
    java_count = sum(item.suffix.lower() == ".java" for item in files)
    resource_count = sum("/resources/" in item.as_posix() or item.parent.name == "resources" for item in files)
    produced_files = len(files)
    returncode = result["returncode"]
    complete = returncode == 0 and produced_files > 0
    partial = produced_files > 0 and not complete
    if complete:
        status = "success"
        message = f"Decompilação concluída. Arquivos gerados: {produced_files}; fontes Java: {java_count}."
    elif partial:
        status = "partial"
        message = (f"Decompilação parcial: o JADX retornou código {returncode}, mas gerou "
                   f"{produced_files} arquivo(s), incluindo {java_count} fonte(s) Java. "
                   "Confira os logs; alguns trechos podem estar incompletos.")
    else:
        status = "failed"
        message = (f"A decompilação falhou (código de retorno: {returncode}). "
                   "Nenhum arquivo foi encontrado na pasta de saída. Confira os logs.")
    return {"ok": complete, "partial": partial, "status": status,
            "command": command[0:3] + ["…"], "returncode": returncode,
            "output_dir": str(output_dir), "files_generated": produced_files,
            "java_files": java_count, "resource_files": resource_count,
            "stdout": result["stdout"], "stderr": result["stderr"], "message": message}


def extract_smali_with_apktool(path: Path, output_dir: Path) -> dict[str, Any]:
    validate_apk(path)
    apktool = shutil.which("apktool")
    if not apktool:
        return {"ok": False, "message": "Apktool não encontrado. O restante do ReaDroid continua funcionando sem ele."}
    output_dir.mkdir(parents=True, exist_ok=True)
    result = _run([apktool, "d", "-f", "-o", str(output_dir), str(path)], timeout=900)
    smali_dirs = [str(p) for p in output_dir.glob("smali*") if p.is_dir()]
    return {"ok": result["returncode"] == 0, "returncode": result["returncode"],
            "output_dir": str(output_dir), "smali_directories": smali_dirs,
            "stdout": result["stdout"], "stderr": result["stderr"]}


def write_report(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
