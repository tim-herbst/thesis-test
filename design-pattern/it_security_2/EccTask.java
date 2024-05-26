package de.hft_stuttgart.it_security_2;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

@Slf4j
class EccTask {

    @SneakyThrows
    public static void main(String[] args) {
        // Generate ECC key pair
        log.atInfo().log("Generating ECC key pair...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256); // Can be adjusted or use ECParameterSpec
        KeyPair kp = kpg.generateKeyPair();
        log.atInfo().log("ECC key pair generated.");

        // Convert keys to string format
        String encodedPrivateKey =
                Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
        String encodedPublicKey =
                Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        log.atInfo().addKeyValue("private key", encodedPrivateKey).log("Private Key generated");
        log.atInfo().addKeyValue("public key", encodedPublicKey).log("Public Key generated");

        // Signing the message
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(kp.getPrivate());
        final String plaintext = "This is a message to sign";
        log.atInfo().log("Signing the message...");
        ecdsa.update(plaintext.getBytes());
        byte[] signature = ecdsa.sign();
        log.atInfo().addKeyValue("signature", Base64.getEncoder().encodeToString(signature)).log("Message signed");

        // Verifying the signature
        log.atInfo().log("Verifying the signature...");
        ecdsa.initVerify(kp.getPublic());
        ecdsa.update(plaintext.getBytes());
        boolean verified = ecdsa.verify(signature);
        log.atInfo().addKeyValue("verified", verified).log("Signature verified");
    }
}
