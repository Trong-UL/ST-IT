# app.py (bổ sung try/except cho từng phần upload)

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io

from static_analysis import pe_summary
from dynamic_analysis.procmon_parser import parse_procmon_csv
from dynamic_analysis.sysmon_parser import parse_sysmon_evtx
from dynamic_analysis.pcap_parser import parse_pcap

st.set_page_config(page_title="Ransomware Analyzer", layout="wide")
st.title("Ransomware Analyzer - Phân tích Ransomware")
st.caption("Phân tích tĩnh & động (mục đích giáo dục)")

tab_static, tab_dynamic = st.tabs(["Static analysis", "Dynamic analysis"])

with tab_static:
    st.header("Tải lên file PE (.exe/.dll)")
    pe_file = st.file_uploader("Chọn file PE (Windows .exe/.dll)", type=["exe","dll"])
    if pe_file:
        try:
            tmp_path = "uploaded_pe.bin"
            with open(tmp_path, "wb") as f:
                f.write(pe_file.read())
            res = pe_summary(tmp_path)

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Kích thước (bytes)", res["size"]) 
                st.text(f"SHA-256: {res['sha256']}")
                st.subheader("Chỉ báo (Indicators)")
                st.json(res["indicators"])

            with col2:
                st.subheader("Các section")
                sec_df = pd.DataFrame(res["sections"])
                if not sec_df.empty:
                    st.dataframe(sec_df)
                    fig, ax = plt.subplots(figsize=(6,3))
                    sns.barplot(data=sec_df, x="name", y="entropy", ax=ax)
                    ax.set_title("Section entropy")
                    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
                    st.pyplot(fig)
                else:
                    st.warning("Không tìm thấy section nào trong file.")

            st.subheader("Imports (tóm tắt)")
            imp_df = pd.DataFrame([{"dll": i["dll"], "func_count": len(i["functions"])} for i in res["imports"]])
            st.dataframe(imp_df)

            st.subheader("Strings (sample)")
            st.text("\n".join(res["strings_sample"]))
        except Exception as e:
            st.error(f"Lỗi khi phân tích file PE: {e}")

with tab_dynamic:
    st.header("Tải lên logs runtime")
    c1, c2, c3 = st.columns(3)
    procmon_csv = c1.file_uploader("Procmon CSV", type=["csv"])
    sysmon_evtx = c2.file_uploader("Sysmon EVTX", type=["evtx"])
    pcap_file = c3.file_uploader("PCAP mạng", type=["pcap","pcapng"])

    # Procmon
    if procmon_csv:
        try:
            data = procmon_csv.read()
            df = pd.read_csv(io.BytesIO(data))
            df.to_csv("procmon_tmp.csv", index=False)
            df2, summary, top_paths, spawns = parse_procmon_csv("procmon_tmp.csv")
            st.subheader("Tóm tắt Procmon")
            st.json(summary)
            st.subheader("Đường dẫn phổ biến")
            st.write(top_paths)
            st.subheader("Tiến trình được tạo")
            st.dataframe(pd.DataFrame(spawns))
            st.subheader("Sự kiện (xem trước)")
            st.dataframe(df2.head(300))
        except Exception as e:
            st.error(f"Lỗi khi phân tích Procmon CSV: {e}")

    # Sysmon
    if sysmon_evtx:
        try:
            with open("sysmon_tmp.evtx", "wb") as f:
                f.write(sysmon_evtx.read())
            events, sum_sys = parse_sysmon_evtx("sysmon_tmp.evtx")
            st.subheader("Tóm tắt Sysmon")
            st.json(sum_sys)
            st.subheader("Sự kiện gần đây")
            st.dataframe(pd.DataFrame(events[:300]))
        except Exception as e:
            st.error(f"Lỗi khi phân tích Sysmon EVTX: {e}")

    # PCAP
    if pcap_file:
        try:
            with open("pcap_tmp.pcap", "wb") as f:
                f.write(pcap_file.read())
            flows, top_dsts = parse_pcap("pcap_tmp.pcap")
            st.subheader("Luồng mạng (xem trước)")
            st.dataframe(pd.DataFrame(flows[:300]))
            st.subheader("Đích đến hàng đầu")
            st.dataframe(pd.DataFrame(top_dsts, columns=["dst","count"]))
        except Exception as e:
            st.error(f"Lỗi khi phân tích PCAP: {e}")
