# Ransomware Analyzer (educational)

Mô tả
- Công cụ đơn giản phục vụ mục đích giáo dục: phân tích tĩnh (PE) và phân tích động từ log runtime (Procmon CSV, Sysmon EVTX) và network PCAP.

Yêu cầu
- Python 3.10+.
- Khuyến nghị tạo virtual environment để cách ly phụ thuộc.

Phụ thuộc (đã có trong `requirements.txt`)
- streamlit, pandas, matplotlib, seaborn, pefile, python-evtx, pyshark, scapy

Ghi chú hệ thống
- `pyshark` sử dụng `tshark` (đi kèm Wireshark). Trên Windows, cài Wireshark và đảm bảo `tshark.exe` nằm trong `PATH` để `pyshark` hoạt động.
- `scapy` được dùng như một fallback để đọc file pcap nếu `pyshark` không thể chạy (ví dụ do xung đột asyncio trong môi trường như Streamlit). Đọc file pcap bằng `scapy` không cần `tshark`.

Hướng dẫn cài đặt (Windows PowerShell)

```powershell
python -m venv .venv
# kích hoạt virtualenv (PowerShell)
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Hoặc (Linux/macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Chạy ứng dụng

```bash
streamlit run app.py
```

Vấn đề thường gặp & khắc phục nhanh
- Lỗi liên quan đến vòng lặp asyncio khi dùng `pyshark` trong Streamlit: mã đã có fallback sang `scapy`. Nếu vẫn gặp vấn đề, kiểm tra trong console lỗi chi tiết và đảm bảo `scapy` đã được cài.
- `pyshark` báo `tshark not found`: cài Wireshark (https://www.wireshark.org/) và đánh dấu đường dẫn `tshark.exe` vào biến môi trường `PATH`.

Gợi ý
- Thêm `.gitignore` để loại trừ thư mục virtualenv (ví dụ: `.venv/`).
- Nếu muốn, tôi có thể thêm hướng dẫn chi tiết cho cài `tshark` trên Windows hoặc thay toàn bộ parsing PCAP sang `scapy`/`dpkt` để loại bỏ phụ thuộc `tshark`.

Liên hệ
- Nếu cần mở rộng tính năng (ví dụ: phân tích luồng mạng đầy đủ, lưu kết quả, hay xuất báo cáo), nói tôi biết tôi sẽ hỗ trợ tiếp.
