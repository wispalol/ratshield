package com.ratshield.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class HashEngine {
    public static final String SHA256 = "SHA-256";

    private HashEngine() {
    }

    public static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance(SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String sha256(Path file) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return toHex(digest.digest());
    }

    public static String sha256(byte[] data) {
        return toHex(sha256Digest().digest(data));
    }

    public static String sha256OfString(String data) {
        return sha256(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static String fromHex(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("invalid hex");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return new String(out, java.nio.charset.StandardCharsets.ISO_8859_1);
    }
}
