import pefile, math, re, hashlib
from pathlib import Path

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    ent = 0.0
    for f in freq:
        if f:
            p = f/len(data)
            ent -= p*math.log2(p)
    return ent

def extract_strings(data: bytes, min_len=6):
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    return [s.decode("latin-1", errors="ignore") for s in pattern.findall(data)]

def pe_summary(path: str):
    f = Path(path)
    raw = f.read_bytes()

    sha256 = hashlib.sha256(raw).hexdigest()
    strings = extract_strings(raw)

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()

    sections = []
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").strip("\x00")
        data = s.get_data() or b""
        sections.append({
            "name": name,
            "vsize": int(s.Misc_VirtualSize),
            "rsize": int(s.SizeOfRawData),
            "entropy": round(calc_entropy(data), 3),
            "characteristics": hex(s.Characteristics),
        })

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append({
                "dll": dll.dll.decode(errors="ignore"),
                "functions": [imp.name.decode(errors="ignore") if imp.name else None
                              for imp in dll.imports]
            })

    indicators = {
        "high_entropy_sections": [s["name"] for s in sections if s["entropy"] > 7.0],
        "suspicious_strings": [s for s in strings
                               if any(k in s.lower() for k in ["cmd.exe","powershell","vssadmin","shadow",".lock",".enc"])],
        "network_hints": [s for s in strings if "://" in s or "http" in s.lower()],
    }

    return {
        "sha256": sha256,
        "size": f.stat().st_size,
        "sections": sections,
        "imports": imports,
        "strings_sample": strings[:300],
        "indicators": indicators,
    }
