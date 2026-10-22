# ReaDroid

**Android Reverse Engineering Toolkit** — static analysis and APK rebuilding for Android 12–16, designed to run on Termux without root. The AI assistant is **optional**: ReaDroid works fully without it.

> **OffensiveTec** is a subtle watermark in the terminal interface.

## Features

- Inspection of APK ZIP structure, SHA-256 hashes, DEX files, and native libraries.
- **Native binary AndroidManifest.xml (AXML) parser**, in pure Python — decodes the manifest of
  any real-world APK without requiring JADX, Apktool, or aapt2. These tools remain available
  as fallbacks for the rare cases where the built-in parser cannot handle the structure.
- Static extraction of URLs, domains (validated against a list of real TLDs to avoid mistaking class names for domains),
  and IPv4 address candidates.
- Optional JADX integration to decompile DEX into approximate Java code.
- Optional Apktool integration to extract resources and smali.
- **Automated rebuilding, alignment, and signing**: after editing extracted smali/resources,
  a single workflow (`apktool b` + `zipalign` + `apksigner`/`jarsigner`) outputs an install-ready APK.
- **Quick edits** to the decoded manifest (debuggable, allowBackup, cleartext traffic, INTERNET permission)
  before rebuilding.
- **Package renaming (applicationId)**: moves smali folders and updates class references as well as the manifest —
  best-effort, intended for repackaging your own app under a different package name.
- Local JSON reports, without external services or telemetry.
- Terminal menu designed for mobile screens, with sanitized output (preventing malicious APKs
  from injecting ANSI escape sequences into your terminal).
- Interactive file explorer to browse and view Java, Kotlin, Smali, XML, JSON files, reports, and rebuilt APKs
  directly from the menu.
- JADX results classified as success, partial, or failure based on the exit code and generated files.
- Outputs saved in the active project directory, avoiding confusion with another `~/ReaDroid` path.

## Compatibility

ReaDroid relies on Python and the standard library for its core functionality (including manifest parsing). It was written targeting Termux ARM64 and Android 12–16, though it could not be tested across every device/version combination. Optional external tools depend on the packages and architecture available in the user's Termux repository. Compatible with Python 3.9 or newer.

JADX requires a compatible Java runtime; upstream documentation specifies Java 11 or later. The Termux JADX package typically depends on Termux's packaged OpenJDK. Apktool on Android has known official incompatibilities in certain configurations, so this feature is optional and should be validated on your device.

## Installation on Termux

Update packages:

```bash
pkg update && pkg upgrade
pkg install python openjdk-21 jadx apktool aapt unzip git
pkg install apksigner   # optional, but recommended - see "Rebuilding" below
```

`aapt` already includes `zipalign`. If `openjdk-21`, `jadx`, `apktool`, or `apksigner` are not available in your configured repository, install the available packages and consult the official Termux documentation/README. ReaDroid does not automatically download third-party executable binaries.

Clone the repository (replace with your repository URL after creating it):

```bash
git clone https://github.com/Mcsd7/ReaDroid.git
cd ReaDroid
python readroid.py
```

Alternatively, if you have already downloaded the files, run `bash install.sh` followed by `python readroid.py`.

To select APKs from the Download folder, enable storage access when prompted by Termux:

```bash
termux-setup-storage
```

Example path: `~/storage/shared/Download/app.apk`.

## Usage

1. Run `python readroid.py`.
2. Select the desired analysis from the menu.
3. Paste the APK path when prompted (or choose one automatically discovered in the Download folder).
4. Review reports in `reports/` and exported files in `output/` within the running project directory. Use option **9 — Explore and open generated files** to browse directories and view files.

The APK path can be absolute or relative to the current working directory. For the JADX option, the tool uses at most four threads (default: two) to reduce memory pressure. Large APKs may still require significant RAM and storage.

## Rebuilding, Alignment, and Signing (options 5, 10, 11, 12)

This workflow provides an install-ready APK without needing to memorize `apktool`/`zipalign`/`apksigner` commands:

1. **Option 5** decodes the APK using Apktool (smali + human-readable resources).
2. Edit files inside the generated directory (`output/<app>_apktool/`) using any text editor on your device.
   For common tweaks without manual editing, use **option 10** (quick manifest edits).
3. Also in **option 10** (or directly in option 11 before compiling), you can **rename the package**
   (applicationId). This moves the `smali`/`smali_classesN` directories from the old package path to the new one and updates
   class references found in `.smali` files and the manifest. This is best-effort: code
   that constructs package names via reflection or at runtime might not be covered — always test the rebuilt APK
   before relying on it.
4. **Option 11** rebuilds (`apktool b`), aligns (`zipalign`), and signs (`apksigner`, falling back to
   `jarsigner` if apksigner is not installed) sequentially. The final APK is placed in `builds/` and,
   if storage access is granted, a copy is also sent to `Downloads/ReaDroid/`.
5. **Option 12** inspects or recreates the signing key used (automatically generated during the first
   rebuild).

Without `apksigner`, ReaDroid uses Java's built-in `jarsigner` (v1/JAR signing only). This usually
works, but apps targeting `targetSdkVersion` 24 or higher may be rejected by the package installer on Android 7+
without a v2 signature. Install `pkg install apksigner` for full signing support (v1+v2+v3).

**Important:** Only use this on your own APKs or applications you have explicit permission to modify. Re-signing an app
changes the original developer identity — the output will not replace the app store version, and redistributing
someone else's modified APK without permission may violate their license. See `SECURITY.md`.

## Optional AI Assistant (option 13)

ReaDroid never needs AI. The assistant lives in a separate module (`readroid/ai.py`); if you do not want it,
just ignore option 13 — or delete that file and the option disappears.

**Setup is one step:** open option 13, paste your OpenRouter API key, done. ReaDroid then:

- stores the key in `~/.readroid/openrouter.key` (permission 600, **outside the project**, so it can't be committed);
- generates an `opencode.json` pointing to OpenRouter with a free NVIDIA Nemotron model
  (default `nvidia/nemotron-3.5-lightning:free`; if a free model goes away, ReaDroid switches to another `:free` one by itself, never to a paid one; you can also pick one in the menu);
- tests the key/model directly against the OpenRouter API, then tests opencode itself.

**Works from any folder.** ReaDroid always starts opencode inside the decoded APK folder
(`output/<app>_apktool`), passing the config (`OPENCODE_CONFIG`) and key (`OPENROUTER_API_KEY`) by environment
variable. You no longer need to `cd` into a specific folder first, and it refuses to open opencode in your home folder.

Menu: open the assistant interactively, summarize the app, **cross-check ReaDroid's JSON reports
(permissions, URLs, domains, IPs) against the code**, **edit with the AI and rebuild in a loop**, explain a rebuild
error, ask a free-form question, test/diagnose, switch model/key, or disable (deletes key and config).

**Edit → rebuild loop (option 4):** a backup of the decoded folder is made first (`builds/_backup_*`). The AI edits
only inside that folder, ReaDroid rebuilds/aligns/signs, and on failure (with your confirmation each time, up to 3
attempts) the build error is sent back to the AI. ReaDroid lists which files the AI changed.

**Privacy:** free models may log prompts, and everything the AI reads (code, strings, manifest) is sent over the
internet. Use only on your own APKs or ones you are authorized to analyze. AI output shown by ReaDroid is sanitized
against terminal escape sequences; the interactive opencode screen is drawn by opencode itself.

## Important Limitations

- ReaDroid performs static analysis. It does not execute the APK or monitor its runtime behavior.
- The native AXML parser covers what most analyses require (package, version, permissions,
  components, `<application>` flags); for manifests with unusual structures, the tool still
  attempts JADX/Apktool/aapt2 as fallbacks.
- JADX does not perfectly reconstruct all original code; identifiers may be obfuscated and original comments/variable names may be lost.
- URLs, domains, IPs, and permissions are leads for manual review, not definitive proof of malicious behavior.
- The string scanner enforces file size and item count limits per category to prevent excessive memory usage; the
  report notes in `truncated_categories` when a list might be incomplete.
- The `AndroidManifest.xml` is read with a size cap (16 MB): an APK with an abnormally large manifest is reported
  as not decoded instead of being loaded into memory. Text manifests that declare a DTD (`<!DOCTYPE`/`<!ENTITY`)
  are rejected, because a valid Android manifest never declares entities — this blocks "billion laughs" payloads
  that would otherwise be expanded by the XML parser.
- Rebuilding depends on `apktool`/`zipalign`/`apksigner` (or `jarsigner`) being installed; without
  them, each step details precisely what is missing.
- ReaDroid never modifies or signs the original APK — every rebuild generates a new file under `builds/`.

## Security and Responsible Use

Analyze only your own applications, test apps, or those you have explicit permission to inspect. APKs are untrusted files; avoid executing them. The tool invokes JADX/Apktool/zipalign/apksigner with separate arguments (without shell interpretation) and does not transmit APKs over the internet (the optional AI assistant sends the file contents you ask it to read to OpenRouter; it is off until you configure it). Tool outputs are saved locally. See `SECURITY.md` for specific guidelines regarding rebuilding and signing.

## Testing

Run:

```bash
python -m unittest discover -s tests -v
```

## License

MIT. See `LICENSE`.

## Credits

ReaDroid is an original interface and automation tool that integrates optional third-party tools. JADX, Apktool, and apksigner maintain their own projects, licenses, and terms; see the links below.

- JADX: https://github.com/skylot/jadx
- Apktool: https://github.com/iBotPeaches/Apktool
- apksigner (Termux): https://github.com/termux/termux-packages
- Termux: https://github.com/termux/termux-app
