package com.lanny.spring_security_template.util;

import java.io.FileOutputStream;
import java.nio.file.*;
import java.security.*;
import java.util.Base64;

/**
 * Ejecuta este main para generar un par de claves RSA válidas (2048 bits)
 * en formato PKCS#8 (compatible con Nimbus y Spring Security).
 */
public class GenerateRsaKeys {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        Path keyDir = Paths.get("src/main/resources/keys");
        Files.createDirectories(keyDir);

        try (FileOutputStream out = new FileOutputStream(keyDir.resolve("rsa-private.pem").toFile())) {
            out.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            out.write(Base64.getMimeEncoder(64, "\n".getBytes())
                    .encode(pair.getPrivate().getEncoded()));
            out.write("\n-----END PRIVATE KEY-----\n".getBytes());
        }

        try (FileOutputStream out = new FileOutputStream(keyDir.resolve("rsa-public.pem").toFile())) {
            out.write("-----BEGIN PUBLIC KEY-----\n".getBytes());
            out.write(Base64.getMimeEncoder(64, "\n".getBytes())
                    .encode(pair.getPublic().getEncoded()));
            out.write("\n-----END PUBLIC KEY-----\n".getBytes());
        }

        System.out.println("✅ RSA key pair generated in src/main/resources/keys/");
    }
}
