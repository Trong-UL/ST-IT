import asyncio
import threading
try:
    import pyshark
except Exception:
    pyshark = None
from typing import Tuple, List, Dict, Any


class _BackgroundLoop:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def stop(self):
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join()


async def _capture_coroutine(path: str, limit: int):
    flows: List[Dict[str, Any]] = []
    count = 0
    cap = pyshark.FileCapture(path)
    try:
        for pkt in cap:
            try:
                if hasattr(pkt, "ip"):
                    flows.append({
                        "src": pkt.ip.src,
                        "dst": pkt.ip.dst,
                        "proto": getattr(pkt, "transport_layer", None),
                        "layer": pkt.highest_layer,
                    })
                    count += 1
                    if count >= limit:
                        break
            except Exception:
                continue
    finally:
        cap.close()

    by_dst: Dict[str, int] = {}
    for f in flows:
        by_dst[f["dst"]] = by_dst.get(f["dst"], 0) + 1
    top_dsts = sorted(by_dst.items(), key=lambda x: x[1], reverse=True)[:10]
    return flows, top_dsts


def parse_pcap(path: str, limit: int = 3000) -> Tuple[List[Dict[str, Any]], List[tuple]]:
    """Parse a PCAP file in a background event loop thread so asyncio-based libs work.

    This runs the sync pyshark capture inside an async coroutine on a dedicated
    loop thread so calls to `asyncio.get_running_loop()` inside pyshark succeed.
    """
    # If pyshark is not available, skip try and go to scapy fallback
    if pyshark:
        bg = _BackgroundLoop()
        try:
            fut = asyncio.run_coroutine_threadsafe(_capture_coroutine(path, limit), bg.loop)
            return fut.result()
        except Exception:
            pass
        finally:
            bg.stop()

    # Fallback to scapy if pyshark not usable
    # If pyshark fails because there's no event loop in the current
    # Streamlit thread, try parsing with scapy as a non-async fallback.
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except Exception:
        # scapy not available — return empty results so the app can show an error
        return [], []

    flows: List[Dict[str, Any]] = []
    try:
        pkts = rdpcap(path)
    except Exception:
        return [], []

    count = 0
    for pkt in pkts:
        if count >= limit:
            break
        try:
            if IP in pkt:
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(pkt[IP].proto)
                layer = pkt.lastlayer().name if hasattr(pkt, "lastlayer") else pkt.summary()
                flows.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": proto,
                    "layer": layer,
                })
                count += 1
        except Exception:
            continue

    by_dst: Dict[str, int] = {}
    for f in flows:
        by_dst[f["dst"]] = by_dst.get(f["dst"], 0) + 1
    top_dsts = sorted(by_dst.items(), key=lambda x: x[1], reverse=True)[:10]
    return flows, top_dsts

