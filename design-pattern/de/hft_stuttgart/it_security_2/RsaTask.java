package de.hft_stuttgart.it_security_2;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

@Slf4j
class RsaTask {

    public static void main(String[] args) {
        try {
            // Generate RSA key pair
            log.atInfo().log("Generating RSA key pair...");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            log.atInfo().addArgument(pair::getPublic).log("Public key: {}");

            // Save keys to files
            log.atInfo().log("Saving public key to 'public.key'...");
            saveKeyToFile("public.key", pair.getPublic());
            log.atInfo()
                    .addKeyValue("encoded public key", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))
                    .log("Public key saved.");
            log.atInfo().log("Saving private key to 'private.key'...");
            saveKeyToFile("private.key", pair.getPrivate());
            log.atInfo()
                    .addKeyValue("encoded private key", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()))
                    .log("Private key saved.");

            // Encrypt and decrypt message
            final var msg = "Encrypt this message!";
            final String cipherText = encryptMessage(msg, pair.getPrivate());
            log.atInfo().addKeyValue("encrypted message", cipherText).log("Msg successfully encrypted");
            final String decryptedMessage = decryptMessage(cipherText, pair.getPublic());
            log.atInfo().addKeyValue("decrypted message", decryptedMessage).log("Msg successfully decrypted");
        } catch (final Exception e) {
            log.atError().log(e.getLocalizedMessage());
        }
    }

    private static void saveKeyToFile(String fileName, Key key) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(key);
        }
    }

    private static String encryptMessage(String msg, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(msg.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decryptMessage(String cipherText, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }
}
