#!/usr/bin/env python3
import json
import sys
from pathlib import Path

from static_analysis import pe_summary
from dynamic_analysis.procmon_parser import parse_procmon_csv
from dynamic_analysis.sysmon_parser import parse_sysmon_evtx
from dynamic_analysis.pcap_parser import parse_pcap


def print_json(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def handle_pe():
    path = input("Đường dẫn tới file PE (.exe/.dll): ").strip()
    p = normalize_path(path)
    if not p.exists():
        print(f"Không tìm thấy file: {p}")
        print("- Nếu bạn copy đường dẫn từ Explorer có thể có dấu ngoặc kép bao quanh; đã được tự động loại bỏ.")
        print("- Nếu là DLL hệ thống Windows, thử dùng đường dẫn đầy đủ trong C:\\Windows\\System32\n")
        return
    try:
        res = pe_summary(str(p))
        print_json({"sha256": res["sha256"], "size": res["size"], "indicators": res["indicators"]})
        print("Các section:")
        for s in res["sections"]:
            print(f"  {s['name']}: entropy={s['entropy']} vsize={s['vsize']} rsize={s['rsize']}")
    except Exception as e:
        print("Lỗi khi phân tích PE:", e)


def handle_procmon():
    path = input("Đường dẫn tới Procmon CSV: ").strip()
    p = normalize_path(path)
    if not p.exists():
        print(f"Không tìm thấy file: {p}")
        return
    try:
        df, summary, top_paths, spawns = parse_procmon_csv(str(p))
        print_json(summary)
        print("Đường dẫn phổ biến:")
        for p in top_paths:
            print(" ", p)
        print("Các tiến trình được tạo (mẫu):")
        for s in spawns[:20]:
            print(" ", s)
    except Exception as e:
        print("Lỗi khi phân tích Procmon CSV:", e)


def handle_sysmon():
    path = input("Đường dẫn tới Sysmon EVTX: ").strip()
    p = normalize_path(path)
    if not p.exists():
        print(f"Không tìm thấy file: {p}")
        return
    try:
        events, summary = parse_sysmon_evtx(str(p))
        print_json(summary)
        print("Sự kiện gần đây (mẫu):")
        for e in events[:20]:
            print(" ", {k: e.get(k) for k in ("event_id","time","image","file")})
    except Exception as e:
        print("Lỗi khi phân tích Sysmon EVTX:", e)


def handle_pcap():
    path = input("Đường dẫn tới file PCAP: ").strip()
    p = normalize_path(path)
    if not p.exists():
        print(f"Không tìm thấy file: {p}")
        return
    try:
        flows, top_dsts = parse_pcap(str(p))
        print(f"Số luồng đã phân tích: {len(flows)}")
        print("Đích đến hàng đầu:")
        for dst, cnt in top_dsts:
            print(f"  {dst}: {cnt}")
    except Exception as e:
        print("Lỗi khi phân tích PCAP:", e)


def main():
    actions = {
        "1": ("Tĩnh: phân tích PE", handle_pe),
        "2": ("Động: phân tích Procmon CSV", handle_procmon),
        "3": ("Động: phân tích Sysmon EVTX", handle_sysmon),
        "4": ("Động: phân tích PCAP", handle_pcap),
        "q": ("Thoát", None),
    }

    while True:
        print("\nRansomware Analyzer - CLI (Dòng lệnh)")
        for k, (desc, _) in actions.items():
            print(f" {k}) {desc}")
        choice = input("Chọn hành động: ").strip()
        if choice == "q":
            sys.exit(0)
        if choice in actions:
            _, fn = actions[choice]
            try:
                fn()
            except Exception as e:
                print("Lỗi chưa xử lý:", e)
        else:
            print("Lựa chọn không hợp lệ")


def normalize_path(s: str) -> Path:
    """Clean user input path: strip surrounding quotes, expand env vars/user, and return Path."""
    if not s:
        return Path(s)
    # strip surrounding single/double quotes and whitespace
    s2 = s.strip().strip('"').strip("'")
    # expand environment variables and user
    s2 = Path(s2).expanduser()
    try:
        s2 = Path(str(s2).format(**dict()))
    except Exception:
        pass
    # expand environment vars manually
    s3 = Path(str(s2).replace('%USERPROFILE%', str(Path.home())))
    return s3


if __name__ == "__main__":
    main()
