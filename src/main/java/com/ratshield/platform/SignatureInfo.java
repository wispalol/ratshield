package com.ratshield.platform;

import java.time.Instant;

/**
 * Result of inspecting a file's Authenticode signature.
 *
 * @param present    whether the PE image contains a certificate table
 * @param status     verification outcome
 * @param signer     subject name of the signing certificate, when available
 * @param issuer     issuer name of the signing certificate, when available
 * @param notBefore  certificate validity start
 * @param notAfter   certificate validity end
 * @param method     how the result was obtained (for transparency in the UI)
 */
public record SignatureInfo(boolean present, Status status, String signer, String issuer,
                            Instant notBefore, Instant notAfter, String method) {

    public enum Status {
        UNKNOWN,
        NOT_SIGNED,
        VALID,
        UNTRUSTED,
        HASH_MISMATCH,
        NOT_TRUSTED_ROOT,
        ERROR
    }

    public static SignatureInfo unsigned() {
        return new SignatureInfo(false, Status.NOT_SIGNED, "", "", null, null, "none");
    }

    public static SignatureInfo unavailable(String reason) {
        return new SignatureInfo(false, Status.UNKNOWN, "", "", null, null, reason);
    }

    public boolean isVerified() {
        return status == Status.VALID;
    }
}
