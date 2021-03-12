package in.ndhm.fidelius.dercyprion;

public class DecryptionRequest {

    private String receiverPrivateKey;
    private String receiverNonce;
    private String senderPublicKey;
    private String senderNonce;
    private String encryptedData;

    public DecryptionRequest(String receiverPublicKey, String receiverNonce, String senderPublicKey, String senderNonce, String encryptedData) {
        this.receiverPrivateKey = receiverPublicKey;
        this.receiverNonce = receiverNonce;
        this.senderPublicKey = senderPublicKey;
        this.senderNonce = senderNonce;
        this.encryptedData = encryptedData;
    }

    public String getReceiverPrivateKey() {
        return receiverPrivateKey;
    }

    public void setReceiverPrivateKey(String receiverPrivateKey) {
        this.receiverPrivateKey = receiverPrivateKey;
    }

    public String getReceiverNonce() {
        return receiverNonce;
    }

    public void setReceiverNonce(String receiverNonce) {
        this.receiverNonce = receiverNonce;
    }

    public String getSenderPublicKey() {
        return senderPublicKey;
    }

    public void setSenderPublicKey(String senderPublicKey) {
        this.senderPublicKey = senderPublicKey;
    }

    public String getSenderNonce() {
        return senderNonce;
    }

    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }
}
