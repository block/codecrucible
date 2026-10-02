#!/usr/bin/env python3
"""Regenerate catalog.json from the pinned official CWE XML; no runtime network."""
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

SOURCE_SHA256 = "1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e"
raw = Path(sys.argv[1]).read_bytes()
if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
    raise SystemExit("Expected the pinned CWE 4.20 XML; update provenance deliberately")
root = ET.fromstring(raw)
ns = {"c": "http://cwe.mitre.org/cwe-7"}
def text(node):
    return " ".join("".join(node.itertext()).split()) if node is not None else ""
entries = []
for w in root.findall("c:Weaknesses/c:Weakness", ns):
    entries.append({
        "id": "CWE-" + w.attrib["ID"],
        "name": w.attrib["Name"],
        "description": text(w.find("c:Description", ns)),
        "abstraction": w.attrib["Abstraction"],
        "status": w.attrib["Status"],
        "mapping": text(w.find("c:Mapping_Notes/c:Usage", ns)),
        "mapping_notes": text(w.find("c:Mapping_Notes/c:Comments", ns)),
        "parents": sorted({"CWE-" + rel.attrib["CWE_ID"] for rel in w.findall("c:Related_Weaknesses/c:Related_Weakness", ns) if rel.attrib["Nature"] == "ChildOf"}),
    })
entries.sort(key=lambda e: int(e["id"][4:]))
data = {"version": root.attrib["Version"], "source_sha256": SOURCE_SHA256,
        "notice": Path(__file__).with_name("NOTICE").read_text(), "entries": entries}
Path(__file__).with_name("catalog.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")
print(f"Generated {len(entries)} CWE entries")
