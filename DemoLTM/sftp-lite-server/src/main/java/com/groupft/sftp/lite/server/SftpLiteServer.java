package com.groupft.sftp.lite.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;

import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.apache.sshd.sftp.server.AbstractSftpEventListenerAdapter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.mindrot.jbcrypt.BCrypt;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

public class SftpLiteServer {

    // Model user nạp từ users.json
@JsonIgnoreProperties(ignoreUnknown = true)    // bỏ qua field lạ nếu có
public static class User {
    public String username;
    public String passwordHash;   // BCrypt (tùy chọn)
    public String passwordPlain;  // mật khẩu thường (tùy chọn, dùng cho test nhanh)
    public String role;           // readWrite | readOnly
    public String home;           // ví dụ: storage/ftuser
}

    private static Map<String, User> loadUsers(Path root) throws IOException {
        File f = root.resolve("users.json").toFile();
        if (!f.exists()) throw new IOException("Không thấy users.json cạnh pom.xml");
        ObjectMapper om = new ObjectMapper();
        JsonNode arr = om.readTree(f).get("users");
        Map<String, User> map = new HashMap<>();
        for (JsonNode n : arr) {
            User u = om.convertValue(n, User.class);
            map.put(u.username, u);
        }
        return map;
    }

    public static void main(String[] args) throws Exception {
        final int port = 5000;

        Path projectRoot = Paths.get("").toAbsolutePath().normalize();
        Path storageRoot = projectRoot.resolve("storage").toAbsolutePath().normalize();
        Files.createDirectories(storageRoot);

        Map<String, User> users = loadUsers(projectRoot);

        // BCrypt password auth
// BCrypt + fallback mật khẩu thường (passwordPlain) để test nhanh
PasswordAuthenticator authenticator = (username, password, session) -> {
    User u = users.get(username);
    if (u == null) return false;

    // ưu tiên passwordPlain nếu có
    if (u.passwordPlain != null && !u.passwordPlain.isEmpty()) {
        return u.passwordPlain.equals(password);
    }
    // còn lại kiểm tra BCrypt
    return u.passwordHash != null && org.mindrot.jbcrypt.BCrypt.checkpw(password, u.passwordHash);
};


        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setPasswordAuthenticator(authenticator);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(projectRoot.resolve("hostkey.ser")));

        // SFTP + rule: chỉ nhận file .slen (đã mã hoá); chặn ghi/xoá/move với readOnly
       SftpSubsystemFactory.Builder sftpBuilder = new SftpSubsystemFactory.Builder();
sftpBuilder.addSftpEventListener(new AbstractSftpEventListenerAdapter() {

    private boolean isRO(ServerSession s) {
        User u = users.get(s.getUsername());
        return u != null && "readOnly".equalsIgnoreCase(u.role);
    }
    private boolean isEncrypted(java.nio.file.Path p) {
        String name = p.getFileName().toString().toLowerCase();
        return name.endsWith(".slen");
    }

    // ---- ĐÚNG chữ ký 2.12.1 (giữ lại @Override) ----
    @Override
    public void creating(ServerSession session, java.nio.file.Path path, java.util.Map<String, ?> attrs)
            throws java.io.IOException {
        if (isRO(session)) throw new java.io.IOException("ReadOnly user không được tạo/ghi");
        if (!isEncrypted(path)) throw new java.io.IOException("Chỉ nhận file đã mã hoá (.slen)");
    }

    @Override
    public void created(ServerSession session, java.nio.file.Path path,
                        java.util.Map<String, ?> attrs, Throwable thrown) throws java.io.IOException {
        if (thrown != null) return;
        long sz = java.nio.file.Files.size(path);
        if (sz < 32) {
            try { java.nio.file.Files.deleteIfExists(path); } catch (Exception ignore) {}
            throw new java.io.IOException("Tệp mã hoá không hợp lệ (quá nhỏ)");
        }
    }

    // ---- Các biến thể KHÔNG @Override để tương thích mọi chữ ký ----
    // removing – biến thể 1 (nhiều version dùng)
    public void removing(ServerSession session, java.nio.file.Path path) throws java.io.IOException {
        if (isRO(session)) throw new java.io.IOException("ReadOnly user không được xoá");
    }
    // removing – biến thể 2 (một số version có thêm cờ thư mục)
    public void removing(ServerSession session, java.nio.file.Path path, boolean isDirectory) throws java.io.IOException {
        if (isRO(session)) throw new java.io.IOException("ReadOnly user không được xoá");
    }

    // moving – biến thể 1 (2.12.1 hay gặp)
    public void moving(ServerSession session,
                       java.nio.file.Path src,
                       java.nio.file.Path dst,
                       java.util.Map<String, ?> opts) throws java.io.IOException {
        if (isRO(session)) throw new java.io.IOException("ReadOnly user không được đổi tên/di chuyển");
        if (!isEncrypted(dst)) throw new java.io.IOException("Đích phải kết thúc bằng .slen");
    }
    // moving – biến thể 2 (một số version khác)
    public void moving(ServerSession session,
                       java.nio.file.Path src,
                       java.nio.file.Path dst,
                       boolean atomic,
                       java.nio.file.CopyOption... options) throws java.io.IOException {
        if (isRO(session)) throw new java.io.IOException("ReadOnly user không được đổi tên/di chuyển");
        if (!isEncrypted(dst)) throw new java.io.IOException("Đích phải kết thúc bằng .slen");
    }
});
sshd.setSubsystemFactories(java.util.Collections.singletonList(sftpBuilder.build()));


        // Chroot vào home từng user
        VirtualFileSystemFactory vfs = new VirtualFileSystemFactory(storageRoot);
        for (User u : users.values()) {
            Path home = projectRoot.resolve(u.home).toAbsolutePath().normalize();
            Files.createDirectories(home);
            vfs.setUserHomeDir(u.username, home);
        }
        sshd.setFileSystemFactory(vfs);

        sshd.start();
        System.out.println("SFTP-Lite Server started on port " + port +
                "\nprojectRoot = " + projectRoot +
                "\nstorageRoot = " + storageRoot);
        Thread.currentThread().join();
    }
}
