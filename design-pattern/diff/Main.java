package de.hft_stuttgart.it_security_2;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

class Main {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    @SneakyThrows
    public static void main(String[] args) {
        String input = generateRandomString(1000);
        SecretKey key128 = generateKey(128);
        SecretKey key256 = generateKey(256);
        IvParameterSpec iv = generateIv();

        performEncryptionDecryption("AES-128", input, key128, iv);
        performEncryptionDecryption("AES-256", input, key256, iv);
    }

    @SneakyThrows
    private static SecretKey generateKey(int n) {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(ALPHABET.length());
            char randomChar = ALPHABET.charAt(index);
            sb.append(randomChar);
        }
        return sb.toString();
    }

    private static void performEncryptionDecryption(String aesType, String input, SecretKey key, IvParameterSpec iv) throws Exception {
        String cipherText = encrypt(ALGORITHM, input, key, iv);
        String plainText = decrypt(ALGORITHM, cipherText, key, iv);

        System.out.println(aesType + " Cipher Text start: " + cipherText.substring(0, 10) + "...");
        System.out.println(aesType + " Decrypted Text: " + plainText.substring(0, 10) + "...");
        System.out.println("Texts are equal: " + plainText.equals(input));

        measurePerformance(aesType + " Encryption", () -> encrypt(ALGORITHM, input, key, iv));
        measurePerformance(aesType + " Decryption", () -> decrypt(ALGORITHM, cipherText, key, iv));
    }

    @SneakyThrows
    private static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    @SneakyThrows
    private static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    private static void measurePerformance(String operation, Runnable task) {
        long startTime = System.nanoTime();
        task.run();
        long endTime = System.nanoTime();
        System.out.println("Elapsed Time for " + operation + ": " + (endTime - startTime) / 1000000f + " mikroseconds");
    }
}