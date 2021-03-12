package in.ndhm.fidelius.encryotion;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

import static in.ndhm.fidelius.Constants.*;

@RestController
public class EncryptionController {

    @PostMapping(value = "/encrypt")
    public EncryptionResponse encrypt(@RequestBody EncryptionRequest encryptionRequest) throws Exception {

        byte[] xorOfRandom = xorOfRandom(encryptionRequest.getSenderNonce(), encryptionRequest.getReceiverNonce());

        String encryptedData = encrypt(xorOfRandom, encryptionRequest.getSenderPrivateKey(), encryptionRequest.getReceiverPublicKey(), encryptionRequest.getPlainTextData());
        return new EncryptionResponse(encryptedData);
    }

    private byte[] xorOfRandom(String senderNonce, String receiverNonce) {
        byte[] randomSender = getBytesForBase64String(senderNonce);
        byte[] randomReceiver = getBytesForBase64String(receiverNonce);

        byte[] combinedRandom = new byte[randomSender.length];
        for (int i = 0; i < randomSender.length; i++) {
            combinedRandom[i] = (byte) (randomSender[i] ^ randomReceiver[i % randomReceiver.length]);
        }
        return combinedRandom;
    }

    public byte[] getBytesForBase64String(String value) {
        return org.bouncycastle.util.encoders.Base64.decode(value);
    }

    public String encrypt(byte[] xorOfRandom, String senderPrivateKey, String receiverPublicKey, String stringToEncrypt) throws Exception {
        System.out.println("<------------------- ENCRYPTION -------------------->");
        // Generating shared secret
        String sharedKey = doECDH(getBytesForBase64String(senderPrivateKey), getBytesForBase64String(receiverPublicKey));
        System.out.println("Shared key: " + sharedKey);

        // Generating iv and HKDF-AES key
        byte[] iv = Arrays.copyOfRange(xorOfRandom, xorOfRandom.length - 12, xorOfRandom.length);
        byte[] aesKey = generateAesKey(xorOfRandom, sharedKey);
        System.out.println("HKDF AES key: " + getBase64String(aesKey));

        // Perform Encryption
        String encryptedData = "";
        try {
            byte[] stringBytes = stringToEncrypt.getBytes();

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters =
                    new AEADParameters(new KeyParameter(aesKey), 128, iv, null);

            cipher.init(true, parameters);
            byte[] plainBytes = new byte[cipher.getOutputSize(stringBytes.length)];
            int retLen = cipher.processBytes
                    (stringBytes, 0, stringBytes.length, plainBytes, 0);
            cipher.doFinal(plainBytes, retLen);

            encryptedData = getBase64String(plainBytes);
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
        }

        System.out.println("EncryptedData: " + encryptedData);
        System.out.println("<---------------- Done ------------------->");
        return encryptedData;
    }

    private String doECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        byte[] secret = ka.generateSecret();
        return getBase64String(secret);
    }

    private PrivateKey loadPrivateKey(byte[] data) throws Exception {
        X9ECParameters ecP = CustomNamedCurves.getByName(CURVE);
        ECParameterSpec params = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(data), params);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        return kf.generatePrivate(privateKeySpec);
    }

    private PublicKey loadPublicKey(byte[] data) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X9ECParameters ecP = CustomNamedCurves.getByName(CURVE);
        ECParameterSpec ecNamedCurveParameterSpec = new ECParameterSpec(ecP.getCurve(), ecP.getG(),
                ecP.getN(), ecP.getH(), ecP.getSeed());

        return KeyFactory.getInstance(ALGORITHM, PROVIDER)
                .generatePublic(new ECPublicKeySpec(ecNamedCurveParameterSpec.getCurve().decodePoint(data),
                        ecNamedCurveParameterSpec));
    }

    private byte[] generateAesKey(byte[] xorOfRandoms, String sharedKey) {
        byte[] salt = Arrays.copyOfRange(xorOfRandoms, 0, 20);
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters hkdfParameters = new HKDFParameters(getBytesForBase64String(sharedKey), salt, null);
        hkdfBytesGenerator.init(hkdfParameters);
        byte[] aesKey = new byte[32];
        hkdfBytesGenerator.generateBytes(aesKey, 0, 32);
        return aesKey;
    }


    public String getBase64String(byte[] value) {
        return new String(org.bouncycastle.util.encoders.Base64.encode(value));
    }
}
