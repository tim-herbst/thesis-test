package de.hft_stuttgart.it_security_2;

import lombok.SneakyThrows;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

class EccTaskV2 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SneakyThrows
    public static void main(String[] args) {
        System.out.println("Generating ECC key pair...");
        var ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        final var ecDom = new ECDomainParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH());
        generator.init(new ECKeyGenerationParameters(ecDom, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        System.out.println("Private Key: "
                + Base64.getEncoder().encodeToString(privateKey.getD().toByteArray()));
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        System.out.println("Public Key: "
                + Base64.getEncoder().encodeToString(publicKey.getQ().getEncoded(false)));

        byte[] message = "Hello, world!".getBytes();
        System.out.println("Message: " + new String(message));
        byte[] encryptedData = encrypt(message, publicKey, privateKey);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encryptedData));

        byte[] decryptedData = decrypt(encryptedData, privateKey, publicKey);
        System.out.println("Decrypted: " + new String(decryptedData));
        System.out.println("Decryption successful: " + new String(message).equals(new String(decryptedData)));
    }

    private static byte[] encrypt(byte[] data, ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
            throws Exception {
        IESEngine iesEngine = new IESEngine(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new HMac(new SHA256Digest()),
                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        byte[] d = new byte[16];
        new SecureRandom().nextBytes(d);
        final var parameters = new IESWithCipherParameters(new byte[0], new byte[0], 128, 128);
        iesEngine.init(true, privateKey, publicKey, parameters);
        return iesEngine.processBlock(data, 0, data.length);
    }

    private static byte[] decrypt(byte[] encrypted, ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
            throws Exception {
        IESEngine iesEngine = new IESEngine(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new HMac(new SHA256Digest()),
                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
        byte[] d = new byte[16];
        new SecureRandom().nextBytes(d);
        final var parameters = new IESWithCipherParameters(new byte[0], new byte[0], 128, 128);
        iesEngine.init(false, privateKey, publicKey, parameters);
        return iesEngine.processBlock(encrypted, 0, encrypted.length);
    }
}
