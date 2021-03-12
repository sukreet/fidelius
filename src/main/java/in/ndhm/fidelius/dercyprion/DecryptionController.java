package in.ndhm.fidelius.dercyprion;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static in.ndhm.fidelius.Constants.*;

@RestController
public class DecryptionController {

    @PostMapping(value = "/decrypt")
    public DecryptionResponse decrypt(@RequestBody DecryptionRequest decryptionRequest) throws Exception {
        byte[] xorOfRandom = xorOfRandom(decryptionRequest.getSenderNonce(), decryptionRequest.getReceiverNonce());
        String decryptedData = decrypt(xorOfRandom, decryptionRequest.getReceiverPrivateKey(), decryptionRequest.getSenderPublicKey(), decryptionRequest.getEncryptedData());
        return new DecryptionResponse(decryptedData);
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

    public String decrypt(byte[] xorOfRandom, String receiverPrivateKey, String senderPublicKey, String stringToDecrypt) throws Exception {
        String sharedKey = doECDH(getBytesForBase64String(receiverPrivateKey), getBytesForBase64String(senderPublicKey));

        // Generating iv and HKDF-AES key
        byte[] iv = Arrays.copyOfRange(xorOfRandom, xorOfRandom.length - 12, xorOfRandom.length);
        byte[] aesKey = generateAesKey(xorOfRandom, sharedKey);

        // Perform Decryption
        String decryptedData = "";
        byte[] encryptedBytes = getBytesForBase64String(stringToDecrypt);

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        AEADParameters parameters =
                new AEADParameters(new KeyParameter(aesKey), 128, iv, null);

        cipher.init(false, parameters);
        byte[] plainBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
        int retLen = cipher.processBytes
                (encryptedBytes, 0, encryptedBytes.length, plainBytes, 0);
        cipher.doFinal(plainBytes, retLen);

        decryptedData = new String(plainBytes);

        return decryptedData;
    }

    private String doECDH(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKeyForProjectEKAHIU(dataPub), true);
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

    private PublicKey loadPublicKeyForProjectEKAHIU(byte[] data) throws Exception {
        KeyFactory ecKeyFac = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(data);
        PublicKey publicKey = ecKeyFac.generatePublic(x509EncodedKeySpec);
        return publicKey;
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
