package com.groupft.sftp.lite.client;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

/** Định dạng file: "SLEN"(4B) | ver(1) | salt(16) | iv(12) | ciphertext(+tag) */
public final class AesGcm {
    private static final int SALT_LEN = 16, IV_LEN = 12, TAG_BITS = 128, KEY_BITS = 256;
    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] kdf(char[] pass, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pass, salt, 120_000, KEY_BITS);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    public static void encryptFile(File in, File out, char[] password) throws Exception {
        byte[] salt = new byte[SALT_LEN]; RNG.nextBytes(salt);
        byte[] iv   = new byte[IV_LEN];   RNG.nextBytes(iv);
        byte[] key  = kdf(password, salt);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));

        try (DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(out)));
             FileInputStream fis = new FileInputStream(in);
             CipherOutputStream cos = new CipherOutputStream(dos, c)) {
            dos.writeBytes("SLEN"); dos.writeByte(1); dos.write(salt); dos.write(iv);
            fis.transferTo(cos);
        } finally { Arrays.fill(key, (byte)0); }
    }

    public static void decryptFile(File in, File out, char[] password) throws Exception {
        try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(in)))) {
            byte[] magic = dis.readNBytes(4);
            if (!"SLEN".equals(new String(magic))) throw new IOException("Sai định dạng mã hoá");
            if (dis.readUnsignedByte() != 1) throw new IOException("Sai version SLEN");

            byte[] salt = dis.readNBytes(SALT_LEN);
            byte[] iv   = dis.readNBytes(IV_LEN);
            byte[] key  = kdf(password, salt);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            try (CipherInputStream cis = new CipherInputStream(dis, c);
                 FileOutputStream fos = new FileOutputStream(out)) {
                cis.transferTo(fos);
            } finally { Arrays.fill(key, (byte)0); }
        }
    }

    private AesGcm() {}
}
