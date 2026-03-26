try:
    from Evtx.Evtx import Evtx
except Exception:
    Evtx = None
from xml.etree import ElementTree as ET


def parse_sysmon_evtx(path: str):
    if Evtx is None:
        raise RuntimeError("Thư viện 'python-evtx' chưa được cài. Cài bằng 'pip install python-evtx'.")

    events = []
    with Evtx(path) as log:
        for rec in log.records():
            try:
                xml = ET.fromstring(rec.xml())
                event_id = xml.findtext(".//EventID")
                time = xml.findtext(".//TimeCreated[@SystemTime]")
                image = xml.findtext(".//Data[@Name='Image']")
                tgt_file = xml.findtext(".//Data[@Name='TargetFilename']")
                reg_obj = xml.findtext(".//Data[@Name='TargetObject']")
                cmdline = xml.findtext(".//Data[@Name='CommandLine']")
                events.append({
                    "event_id": event_id, "time": time, "image": image,
                    "file": tgt_file, "registry": reg_obj, "cmdline": cmdline
                })
            except Exception:
                continue
    summary = {
        "process_create": sum(1 for e in events if e["event_id"] == "1"),
        "file_create": sum(1 for e in events if e["event_id"] == "11"),
        "registry_set": sum(1 for e in events if e["event_id"] == "13"),
        "network_connect": sum(1 for e in events if e["event_id"] == "3"),
    }
    return events, summary
