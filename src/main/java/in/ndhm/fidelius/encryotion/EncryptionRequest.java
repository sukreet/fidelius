package in.ndhm.fidelius.encryotion;

public class EncryptionRequest {

    private String receiverPublicKey;
    private String receiverNonce;
    private String senderPrivateKey;

    private String senderPublicKey;
    private String senderNonce;
    private String plainTextData;

    public EncryptionRequest(String receiverPublicKey, String receiverNonce, String senderPrivateKey, String senderPublicKey, String senderNonce, String plainTextData) {
        this.receiverPublicKey = receiverPublicKey;
        this.receiverNonce = receiverNonce;
        this.senderPrivateKey = senderPrivateKey;
        this.senderPublicKey = senderPublicKey;
        this.senderNonce = senderNonce;
        this.plainTextData = plainTextData;
    }

    public String getReceiverPublicKey() {
        return receiverPublicKey;
    }

    public void setReceiverPublicKey(String receiverPublicKey) {
        this.receiverPublicKey = receiverPublicKey;
    }

    public String getReceiverNonce() {
        return receiverNonce;
    }

    public void setReceiverNonce(String receiverNonce) {
        this.receiverNonce = receiverNonce;
    }

    public String getSenderPrivateKey() {
        return senderPrivateKey;
    }

    public void setSenderPrivateKey(String senderPrivateKey) {
        this.senderPrivateKey = senderPrivateKey;
    }

    public String getSenderNonce() {
        return senderNonce;
    }

    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    public String getSenderPublicKey() {
        return senderPublicKey;
    }

    public void setSenderPublicKey(String senderPublicKey) {
        this.senderPublicKey = senderPublicKey;
    }

    public String getPlainTextData() {
        return plainTextData;
    }

    public void setPlainTextData(String plainTextData) {
        this.plainTextData = plainTextData;
    }
}
