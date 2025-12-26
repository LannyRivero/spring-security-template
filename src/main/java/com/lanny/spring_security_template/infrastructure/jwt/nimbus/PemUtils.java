package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.lanny.spring_security_template.infrastructure.jwt.exception.JwtKeyLoadingException;

/**
 * {@code PemUtils}
 *
 * <p>
 * Low-level utility for loading RSA keys from PEM-encoded sources.
 * </p>
 *
 * <h2>Supported formats</h2>
 * <ul>
 * <li>PKCS#8 private keys ({@code -----BEGIN PRIVATE KEY-----})</li>
 * <li>PKCS#1 private keys ({@code -----BEGIN RSA PRIVATE KEY-----})</li>
 * <li>X.509 public keys ({@code -----BEGIN PUBLIC KEY-----})</li>
 * </ul>
 *
 * <h2>Supported sources</h2>
 * <ul>
 * <li>Classpath resources</li>
 * <li>Filesystem paths</li>
 * <li>{@link InputStream} (KMS, Vault, Secrets Managers)</li>
 * </ul>
 *
 * <h2>Design guarantees</h2>
 * <ul>
 * <li>Fail-fast: invalid keys prevent application startup</li>
 * <li>No external crypto dependencies</li>
 * <li>Infrastructure-only responsibility</li>
 * </ul>
 */
public final class PemUtils {

    private PemUtils() {
        // utility class
    }

    // ==========================================================
    // Public API — String location
    // ==========================================================

    public static RSAPrivateKey readPrivateKey(String location) {
        try {
            return parsePrivateKey(loadPem(location));
        } catch (Exception e) {
            throw new JwtKeyLoadingException("rsa.private.load_failed", e);
        }
    }

    public static RSAPublicKey readPublicKey(String location) {
        try {
            return parsePublicKey(loadPem(location));
        } catch (Exception e) {
            throw new JwtKeyLoadingException("rsa.public.load_failed", e);
        }
    }

    // ==========================================================
    // Public API — InputStream
    // ==========================================================

    public static RSAPrivateKey readPrivateKey(InputStream is) {
        try {
            return parsePrivateKey(new String(is.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new JwtKeyLoadingException("rsa.private.load_failed", e);
        }
    }

    public static RSAPublicKey readPublicKey(InputStream is) {
        try {
            return parsePublicKey(new String(is.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new JwtKeyLoadingException("rsa.public.load_failed", e);
        }
    }

    // ==========================================================
    // Parsing logic
    // ==========================================================

    private static RSAPrivateKey parsePrivateKey(String pem) throws Exception {

        // PKCS#8
        if (pem.contains("BEGIN PRIVATE KEY") && !pem.contains("BEGIN RSA PRIVATE KEY")) {
            byte[] decoded = decodePem(pem);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(decoded));
        }

        // PKCS#1
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            byte[] decoded = decodePem(pem);
            return parsePkcs1PrivateKey(decoded);
        }

        throw new JwtKeyLoadingException("rsa.private.unsupported_format");
    }

    private static RSAPublicKey parsePublicKey(String pem) throws Exception {
        if (!pem.contains("BEGIN PUBLIC KEY")) {
            throw new JwtKeyLoadingException("rsa.public.invalid_format");
        }

        byte[] decoded = decodePem(pem);
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static byte[] decodePem(String pem) {
        String sanitized = pem
                .replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                .replaceAll("-----END ([A-Z ]+)-----", "")
                .replaceAll("\\s+", "");

        return Base64.getDecoder().decode(sanitized);
    }

    // ==========================================================
    // PKCS#1 ASN.1 DER parsing
    // ==========================================================

    private static RSAPrivateKey parsePkcs1PrivateKey(byte[] data) throws Exception {

        int offset = 0;

        if (data[offset++] != 0x30) {
            throw new JwtKeyLoadingException("rsa.pkcs1.invalid_sequence");
        }

        offset += readLengthBytes(data, offset);
        offset = skipInteger(data, offset); // version

        BigInteger modulus = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger publicExponent = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger privateExponent = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger primeP = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger primeQ = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger primeExponentP = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger primeExponentQ = readInteger(data, offset);
        offset = skipInteger(data, offset);

        BigInteger crtCoefficient = readInteger(data, offset);

        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                modulus,
                publicExponent,
                privateExponent,
                primeP,
                primeQ,
                primeExponentP,
                primeExponentQ,
                crtCoefficient);

        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // ==========================================================
    // ASN.1 helpers
    // ==========================================================

    private static int readLength(byte[] data, int offset) {
        int length = data[offset] & 0xFF;
        if (length < 0x80) {
            return length;
        }
        int numBytes = length & 0x7F;
        int result = 0;
        for (int i = 0; i < numBytes; i++) {
            result = (result << 8) | (data[offset + 1 + i] & 0xFF);
        }
        return result;
    }

    private static int readLengthBytes(byte[] data, int offset) {
        return (data[offset] & 0x80) == 0 ? 1 : 1 + (data[offset] & 0x7F);
    }

    private static BigInteger readInteger(byte[] data, int offset) {
        if (data[offset] != 0x02) {
            throw new JwtKeyLoadingException("asn1.expected_integer");
        }
        int length = readLength(data, offset + 1);
        int lengthBytes = readLengthBytes(data, offset + 1);
        byte[] value = new byte[length];
        System.arraycopy(data, offset + 1 + lengthBytes, value, 0, length);
        return new BigInteger(value);
    }

    private static int skipInteger(byte[] data, int offset) {
        int length = readLength(data, offset + 1);
        int lengthBytes = readLengthBytes(data, offset + 1);
        return offset + 1 + lengthBytes + length;
    }

    // ==========================================================
    // Resource loading
    // ==========================================================

    private static String loadPem(String location) throws IOException {

        String normalized = location.startsWith("/") ? location : "/" + location;

        try (InputStream is = PemUtils.class.getResourceAsStream(normalized)) {
            if (is != null) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        Path path = Path.of(location);
        if (Files.exists(path)) {
            return Files.readString(path, StandardCharsets.UTF_8);
        }

        throw new JwtKeyLoadingException("rsa.key.not_found: " + location);
    }
}
