package com.groupft.sftp.lite.client;

import com.jcraft.jsch.*;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.util.Vector;

public class SftpLiteClient extends JFrame {

    // --- Form ---
    private final JTextField txtHost = new JTextField("127.0.0.1");
    private final JTextField txtPort = new JTextField("5000");
    private final JTextField txtUser = new JTextField("ftuser");
    private final JPasswordField txtPass = new JPasswordField("12345");

    private final JButton btnConnect = new JButton("Connect");
    private final JButton btnDisconnect = new JButton("Disconnect");
    private final JButton btnRefresh = new JButton("Refresh");
    private final JButton btnUpload = new JButton("Upload");
    private final JButton btnDownload = new JButton("Download");
    private final JButton btnDelete = new JButton("Delete");

    private final JCheckBox chkEncrypt = new JCheckBox("Encrypt at rest (.slen)", true);
    private final JTextField txtRemoteDir = new JTextField("/");
    private final DefaultListModel<String> remoteModel = new DefaultListModel<>();
    private final JList<String> lstRemote = new JList<>(remoteModel);
    private final JProgressBar bar = new JProgressBar(0, 100);

    // --- SFTP state ---
    private Session session;
    private ChannelSftp sftp;

    public SftpLiteClient() {
        super("SFTP-Lite Client (Group-FT)");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(860, 560);
        buildUI();
        bindEvents();
    }

    private void buildUI() {
        JPanel top = new JPanel(new GridLayout(2,1,8,6));

        JPanel r1 = new JPanel(new GridLayout(1,8,6,0));
        r1.add(new JLabel("Host:")); r1.add(txtHost);
        r1.add(new JLabel("Port:")); r1.add(txtPort);
        r1.add(new JLabel("User:")); r1.add(txtUser);
        r1.add(new JLabel("Pass:")); r1.add(txtPass);

        JPanel r2 = new JPanel(new FlowLayout(FlowLayout.LEFT,8,0));
        r2.add(btnConnect); r2.add(btnDisconnect);
        r2.add(new JLabel("Remote dir:"));
        txtRemoteDir.setColumns(26); r2.add(txtRemoteDir);
        r2.add(btnRefresh); r2.add(btnUpload); r2.add(btnDownload); r2.add(btnDelete); r2.add(chkEncrypt);

        top.add(r1); top.add(r2);

        lstRemote.setBorder(new TitledBorder("Remote files"));
        bar.setStringPainted(true);
        add(top, BorderLayout.NORTH);
        add(new JScrollPane(lstRemote), BorderLayout.CENTER);
        add(bar, BorderLayout.SOUTH);
    }

    private void bindEvents() {
        btnConnect.addActionListener(e -> connect());
        btnDisconnect.addActionListener(e -> disconnect());
        btnRefresh.addActionListener(e -> refreshList());
        btnUpload.addActionListener(e -> upload());
        btnDownload.addActionListener(e -> download());
        btnDelete.addActionListener(e -> deleteRemote());
    }

    // ---------------- Connect/Disconnect ----------------
    private void connect() {
        if (sftp != null && sftp.isConnected()) { info("Đã kết nối."); return; }

        String host = txtHost.getText().trim();
        String user = txtUser.getText().trim();
        String pass = new String(txtPass.getPassword());
        int port;
        try { port = Integer.parseInt(txtPort.getText().trim()); }
        catch (NumberFormatException ex) { error("Port phải là số (vd 5000)."); return; }

        try {
            JSch jsch = new JSch();

            // Khuyến nghị nộp đồ án: dùng known_hosts + StrictHostKeyChecking=yes
            // jsch.setKnownHosts("known_hosts");
            java.util.Properties cfg = new java.util.Properties();
            cfg.put("StrictHostKeyChecking", "no");

            session = jsch.getSession(user, host, port);
            session.setPassword(pass);
            session.setConfig(cfg);
            session.connect(10_000);

            Channel ch = session.openChannel("sftp");
            ch.connect(5_000);
            sftp = (ChannelSftp) ch;
            try { sftp.setFilenameEncoding("UTF-8"); } catch (Exception ignore) {}

            String home = "."; try { home = sftp.realpath("."); } catch (Exception ignore) {}
            txtRemoteDir.setText(home);

            info("Kết nối thành công!");
            refreshList();
        } catch (JSchException ex) {
            session = null; sftp = null;
            error("Kết nối thất bại: " + ex.getMessage()
                  + "\n• Kiểm tra server đã chạy\n• Host/Port/User/Pass\n• Firewall");
        } catch (Exception ex) {
            session = null; sftp = null;
            error("Lỗi: " + ex.getMessage());
        }
    }

    private void disconnect() {
        try { if (sftp != null) sftp.disconnect(); } catch (Exception ignore) {}
        try { if (session != null) session.disconnect(); } catch (Exception ignore) {}
        sftp = null; session = null;
        remoteModel.clear();
        info("Đã ngắt kết nối.");
    }

    // ---------------- Actions ----------------
    private void refreshList() {
        try {
            ensureConnected();
            String dir = txtRemoteDir.getText().trim().replace('\\','/');
            if (dir.isEmpty()) dir = ".";
            Vector<ChannelSftp.LsEntry> list;
            try { list = sftp.ls(dir); }
            catch (SftpException bad) {
                // fallback an toàn
                dir = "."; list = sftp.ls(dir);
                try { dir = sftp.realpath(dir); } catch (Exception ignore) {}
                txtRemoteDir.setText(dir);
            }
            remoteModel.clear();
            for (ChannelSftp.LsEntry e : list) {
                String name = e.getFilename();
                if (!".".equals(name) && !"..".equals(name)) remoteModel.addElement(name);
            }
        } catch (Exception ex) {
            error("Không truy cập được thư mục: " + ex.getMessage());
        }
    }

    private void upload() {
        try {
            ensureConnected();
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            File src = fc.getSelectedFile();

            String base = txtRemoteDir.getText().trim().replace('\\','/');
            if (base.isEmpty()) base = ".";
            try { base = sftp.realpath(base); } catch (Exception ignore) {}
            String remoteName = src.getName() + (chkEncrypt.isSelected() ? ".slen" : "");
            String target = (base.endsWith("/")?base:base+"/") + remoteName;

            // Mã hoá trước khi gửi (server bắt buộc .slen)
            File toSend = src;
            if (chkEncrypt.isSelected()) {
                File tmp = File.createTempFile("enc-", ".slen");
                AesGcm.encryptFile(src, tmp, txtPass.getPassword());
                toSend = tmp;
            }

            long total = toSend.length();
            SftpProgressMonitor mon = new BarProgress("Upload", total);
            try {
                sftp.put(toSend.getAbsolutePath(), target, mon, ChannelSftp.OVERWRITE);
            } catch (SftpException se) {
                // server có rule .slen → giải thích rõ nếu user tắt Encrypt
                if (!chkEncrypt.isSelected())
                    error("Server chỉ nhận file đã mã hoá (.slen). Hãy bật 'Encrypt at rest'.\n" + se.getMessage());
                else error("Upload lỗi: " + se.getMessage());
                return;
            } finally {
                if (chkEncrypt.isSelected()) toSend.delete();
            }

            info("Upload OK: " + remoteName);
            refreshList();
        } catch (Exception ex) {
            error("Upload lỗi: " + ex.getMessage());
        }
    }

    private void download() {
        try {
            ensureConnected();
            String sel = lstRemote.getSelectedValue();
            if (sel == null) { info("Chọn file ở danh sách trước."); return; }

            JFileChooser fc = new JFileChooser();
            // nếu là .slen → gợi ý tên bỏ đuôi
            fc.setSelectedFile(new File(sel.endsWith(".slen") ? sel.substring(0, sel.length()-5) : sel));
            if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
            File save = fc.getSelectedFile();

            String base = txtRemoteDir.getText().trim().replace('\\','/');
            if (base.isEmpty()) base = ".";
            try { base = sftp.realpath(base); } catch (Exception ignore) {}
            String src = (base.endsWith("/")?base:base+"/") + sel;

            File tmp = File.createTempFile("dl-", ".bin");
            SftpProgressMonitor mon = new BarProgress("Download", -1);
            sftp.get(src, tmp.getAbsolutePath(), mon);

            if (sel.endsWith(".slen")) {
                AesGcm.decryptFile(tmp, save, txtPass.getPassword());
                tmp.delete();
            } else {
                // hiếm khi gặp vì server đang bắt buộc .slen, nhưng vẫn hỗ trợ
                tmp.renameTo(save);
            }
            info("Download OK: " + save.getAbsolutePath());
        } catch (Exception ex) {
            error("Download lỗi: " + ex.getMessage());
        }
    }

    private void deleteRemote() {
        try {
            ensureConnected();
            String sel = lstRemote.getSelectedValue();
            if (sel == null) { info("Chọn file cần xoá."); return; }
            int c = JOptionPane.showConfirmDialog(this, "Xoá '" + sel + "'?", "Xác nhận", JOptionPane.YES_NO_OPTION);
            if (c != JOptionPane.YES_OPTION) return;

            String base = txtRemoteDir.getText().trim().replace('\\','/');
            if (base.isEmpty()) base = ".";
            try { base = sftp.realpath(base); } catch (Exception ignore) {}
            String path = (base.endsWith("/")?base:base+"/") + sel;

            sftp.rm(path);
            refreshList();
        } catch (SftpException se) {
            // server sẽ chặn user readOnly
            error("Xoá lỗi (có thể tài khoản chỉ đọc): " + se.getMessage());
        } catch (Exception ex) {
            error("Xoá lỗi: " + ex.getMessage());
        }
    }

    // ---------------- Helpers ----------------
    private void ensureConnected() {
        if (sftp == null || !sftp.isConnected()) throw new IllegalStateException("Chưa kết nối SFTP.");
    }
    private void info(String m) { JOptionPane.showMessageDialog(this, m); }
    private void error(String m) { JOptionPane.showMessageDialog(this, m, "Lỗi", JOptionPane.ERROR_MESSAGE); }

    /** Thanh tiến trình cho upload/download */
    private class BarProgress implements SftpProgressMonitor {
        private final String title; private final long total; private long count=0;
        BarProgress(String t, long tot){ title=t; total=tot; bar.setValue(0); bar.setString(title); }
        @Override public void init(int op, String src, String dest, long max) {}
        @Override public boolean count(long bytes) {
            count += bytes;
            int pct = (total > 0) ? (int)(count * 100 / total) : Math.min(100, (int)(count/1_000_00));
            SwingUtilities.invokeLater(() -> { bar.setValue(pct); bar.setString(title + " " + pct + "%"); });
            return true;
        }
        @Override public void end() { SwingUtilities.invokeLater(() -> { bar.setValue(100); bar.setString(title + " ✓"); }); }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SftpLiteClient().setVisible(true));
    }
}
