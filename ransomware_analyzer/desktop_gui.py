import sys
import threading
import time
from pathlib import Path

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QFileDialog, QTableView, QTabWidget, QStatusBar,
        QTextEdit, QSizePolicy, QGroupBox
    )
    from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QObject, pyqtSignal
    from PyQt6.QtGui import QPixmap
    QT_IMPL = 'PyQt6'
except Exception:
    # fallback to PySide6 if PyQt6 is not available
    try:
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QPushButton, QFileDialog, QTableView, QTabWidget, QStatusBar,
            QTextEdit, QSizePolicy, QGroupBox
        )
        from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QObject, Signal as pyqtSignal
        from PySide6.QtGui import QPixmap
        QT_IMPL = 'PySide6'
    except Exception:
        raise

import pandas as pd
import matplotlib.pyplot as plt
import io

from static_analysis import pe_summary
from dynamic_analysis.procmon_parser import parse_procmon_csv
from dynamic_analysis.sysmon_parser import parse_sysmon_evtx
from dynamic_analysis.pcap_parser import parse_pcap


class DataFrameModel(QAbstractTableModel):
    def __init__(self, df=pd.DataFrame(), parent=None):
        super().__init__(parent)
        self._df = df

    def setDataFrame(self, df: pd.DataFrame):
        self.beginResetModel()
        self._df = df.copy()
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._df.index)

    def columnCount(self, parent=QModelIndex()):
        return len(self._df.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            value = self._df.iat[index.row(), index.column()]
            return str(value)
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            try:
                return str(self._df.columns[section])
            except Exception:
                return None
        else:
            try:
                return str(self._df.index[section])
            except Exception:
                return None


class AnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ransomware Analyzer - Giao diện Desktop")
        self.resize(1100, 700)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Header / banner
        header = QLabel("<h2>Hệ thống phân tích Ransomware</h2>")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Dependency / security warnings
        missing = []
        try:
            import Evtx  # type: ignore
        except Exception:
            missing.append("python-evtx")
        try:
            import pyshark  # type: ignore
        except Exception:
            missing.append("pyshark (cần tshark nếu dùng pyshark)")

        if missing:
            miss_html = "<b>Thiếu phụ thuộc:</b> " + ", ".join(missing) + ". Cài bằng `pip install -r requirements.txt`."
            warn = QLabel(f"<div style='background:#fff3cd;padding:8px;border-radius:6px;color:#856404;'>{miss_html}</div>")
            warn.setWordWrap(True)
            layout.addWidget(warn)

        # Security banner
        sec_html = "<b>Cảnh báo bảo mật:</b> Không phân tích mẫu thực thi nguy hiểm trên hệ thống thật. Chạy trong máy ảo hoặc sandbox để tránh rủi ro."
        sec = QLabel(f"<div style='background:#f8d7da;padding:8px;border-radius:6px;color:#721c24;'>{sec_html}</div>")
        sec.setWordWrap(True)
        layout.addWidget(sec)

        # Controls: file selection and buttons
        ctrl = QHBoxLayout()

        self.file_label = QLabel("Chưa chọn file")
        self.file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        ctrl.addWidget(self.file_label)

        btn_choose = QPushButton("Chọn file")
        btn_choose.clicked.connect(self.choose_file)
        ctrl.addWidget(btn_choose)

        self.btn_check = QPushButton("Kiểm tra")
        self.btn_check.clicked.connect(self.run_analysis)
        ctrl.addWidget(self.btn_check)

        layout.addLayout(ctrl)

        # Tabs for Static / Dynamic
        self.tabs = QTabWidget()

        # =========================
        # Static tab (Phân tích tĩnh)
        # =========================
        self.tab_static = QWidget()
        st_layout = QVBoxLayout(self.tab_static)

        # --- Khung biểu đồ Entropy ---
        grp_entropy = QGroupBox("Biểu đồ Entropy")
        grp_entropy_layout = QVBoxLayout(grp_entropy)
        self.entropy_label = QLabel()
        self.entropy_label.setFixedHeight(220)
        self.entropy_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        grp_entropy_layout.addWidget(self.entropy_label)
        st_layout.addWidget(grp_entropy)

        # --- Khung chỉ báo ---
        grp_indicators = QGroupBox("Chỉ báo")
        grp_ind_layout = QVBoxLayout(grp_indicators)
        self.indicators_view = QTextEdit()
        self.indicators_view.setReadOnly(True)
        self.indicators_view.setMaximumHeight(140)
        self.indicators_view.setAcceptRichText(True)
        grp_ind_layout.addWidget(self.indicators_view)
        st_layout.addWidget(grp_indicators)

        # --- Khung chi tiết phân tích ---
        grp_static = QGroupBox("Chi tiết phân tích")
        grp_static_layout = QVBoxLayout(grp_static)
        self.static_text = QTextEdit()
        self.static_text.setReadOnly(True)
        grp_static_layout.addWidget(self.static_text)
        st_layout.addWidget(grp_static)

        self.tabs.addTab(self.tab_static, "Phân tích tĩnh")

        # =========================
        # Dynamic tab (giữ nguyên)
        # =========================
        self.tab_dynamic = QWidget()
        dyn_layout = QVBoxLayout(self.tab_dynamic)
        self.dynamic_table = QTableView()
        self.dynamic_model = DataFrameModel(pd.DataFrame())
        self.dynamic_table.setModel(self.dynamic_model)
        dyn_layout.addWidget(self.dynamic_table)
        self.tabs.addTab(self.tab_dynamic, "Phân tích động")

        layout.addWidget(self.tabs)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Sẵn sàng")

        # internal state
        self.current_path = None

    # =========================
    # Các hàm xử lý (giữ nguyên)
    # =========================
    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Chọn file để phân tích", str(Path.cwd()), "All Files (*)")
        if path:
            self.current_path = path
            self.file_label.setText(path)
            self.status.showMessage("Đã chọn file")

    def run_analysis(self):
        if not self.current_path:
            self.status.showMessage("Vui lòng chọn file trước")
            return
        self.btn_check.setEnabled(False)
        self.status.showMessage("Đang phân tích...")

        thread = threading.Thread(target=self._worker, args=(self.current_path,), daemon=True)
        thread.start()

    def _worker(self, path: str):
        p = Path(path)
        lower = p.suffix.lower()
        try:
            if lower in ('.exe', '.dll'):
                res = pe_summary(str(p))
                text = []
                text.append(f"SHA-256: {res['sha256']}")
                text.append(f"Kích thước: {res['size']} bytes")
                text.append("\nChỉ báo:")
                for k, v in res['indicators'].items():
                    text.append(f"- {k}: {v}")
                text.append("\nCác section:")
                for s in res['sections']:
                    text.append(f"  {s['name']}: entropy={s['entropy']} vsize={s['vsize']} rsize={s['rsize']}")
                out = "\n".join(text)
                self._update_static(out)
                try:
                    html = self._format_indicators_html(res.get('indicators', {}))
                    self._update_indicators(html)
                except Exception:
                    pass
                try:
                    sections = res.get('sections', [])
                    if sections:
                        self._update_entropy_chart(sections)
                except Exception:
                    pass
            elif lower in ('.csv',):
                df, summary, top_paths, spawns = parse_procmon_csv(str(p))
                out = f"Tóm tắt: {summary}\nTop paths: {top_paths}\nMẫu tiến trình tạo: {spawns[:10]}"
                self._update_static(out)
                self._update_dynamic(df)
            elif lower in ('.evtx',):
                events, summary = parse_sysmon_evtx(str(p))
                df = pd.DataFrame(events)
                out = f"Tóm tắt: {summary}"
                self._update_static(out)
                self._update_dynamic(df)
            elif lower in ('.pcap', '.pcapng'):
                flows, top_dsts = parse_pcap(str(p))
                df = pd.DataFrame(flows)
                out = f"Đích đến hàng đầu: {top_dsts}"
                self._update_static(out)
                self._update_dynamic(df)
            else:
                self._update_static(f"Không hỗ trợ định dạng: {lower}")
        except Exception as e:
            self._update_static(f"Lỗi: {e}")
        finally:
            self._done()

    def _update_static(self, text: str):
        def fn():
            self.static_text.setPlainText(text)
        invoker.callSignal.emit(fn)

    def _update_dynamic(self, df: pd.DataFrame):
        def fn():
            self.dynamic_model.setDataFrame(df.fillna(''))
        invoker.callSignal.emit(fn)

    def _done(self):
        def fn():
            self.btn_check.setEnabled(True)
            self.status.showMessage(f"Hoàn tất: {time.strftime('%H:%M:%S')}")
        invoker.callSignal.emit(fn)

    def _update_indicators(self, html: str):
        def fn():
            self.indicators_view.setHtml(html)
        invoker.callSignal.emit(fn)

    def _update_entropy_chart(self, sections: list):
        def render():
            try:
                names = [s.get('name','') for s in sections]
                entropy = [float(s.get('entropy', 0.0)) for s in sections]
                fig, ax = plt.subplots(figsize=(6,2.5))
                bars = ax.bar(names, entropy, color='tab:blue')
                ax.set_ylim(0,8)
                ax.set_ylabel('Entropy')
                ax.set_title('Entropy các section')
                ax.tick_params(axis='x', rotation=45)
                try:
                    ax.bar_label(bars, fmt='%.2f', padding=3)
                except Exception:
                    for b, val in zip(bars, entropy):
                        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.05,
                                f"{val:.2f}", ha='center', va='bottom', fontsize=8)

                details = []
                for s in sections:
                    details.append(f"{s.get('name','')}: entropy={s.get('entropy','')}, "
                                   f"vsize={s.get('vsize','')}, rsize={s.get('rsize','')}")
                tooltip_html = '<br>'.join(details)

                buf = io.BytesIO()
                fig.tight_layout()
                fig.savefig(buf, format='png')
                plt.close(fig)
                buf.seek(0)
                data = buf.read()
                pix = QPixmap()
                pix.loadFromData(data)
                self.entropy_label.setPixmap(
                    pix.scaled(self.entropy_label.width(),
                               self.entropy_label.height(),
                               Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation))
                self.entropy_label.setToolTip(tooltip_html)
            except Exception as e:
                self.entropy_label.setText(f"Không thể vẽ biểu đồ: {e}")

        invoker.callSignal.emit(render)

    @staticmethod
    def _format_indicators_html(indicators: dict) -> str:
        parts = ["<div style='font-family:Segoe UI, Arial;'>"]
        def badge(color, label, content):
            return (f"<div style='margin:4px 0;'><b>{label}:</b> "
                    f"<span style='background:{color};color:#fff;padding:2px 6px;"
                    f"border-radius:4px;margin-left:8px;'>{content}</span></div>")

        mapping = {
            'high_entropy_sections': ('#d9534f', 'Section entropy cao'),
            'suspicious_strings': ('#f0ad4e', 'Chuỗi đáng ngờ'),
            'network_hints': ('#5bc0de', 'Gợi ý mạng')
        }
        for k, v in indicators.items():
            color, label = mapping.get(k, ('#6c757d', k))
            summary = ', '.join(v) if v else 'Không tìm thấy'
            if len(summary) > 300:
                summary = summary[:297] + '...'
            parts.append(badge(color, label, summary))

        parts.append('</div>')
        return '\n'.join(parts)


class Invoker(QObject):
    callSignal = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.callSignal.connect(self._on_call)

    def _on_call(self, fn):
        try:
            fn()
        except Exception:
            pass


# single global invoker used to marshal calls to the main thread
invoker = Invoker()


def main():
    app = QApplication(sys.argv)
    w = AnalyzerWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
