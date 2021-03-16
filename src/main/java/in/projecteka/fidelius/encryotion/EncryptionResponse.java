package in.projecteka.fidelius.encryotion;

public class EncryptionResponse {

    private String encryptedData;
    private String keyToShare;


    public EncryptionResponse(String encryptedData, String keyToShare) {
        this.encryptedData = encryptedData;
        this.keyToShare = keyToShare;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    public String getKeyToShare() {
        return keyToShare;
    }

    public void setKeyToShare(String keyToShare) {
        this.keyToShare = keyToShare;
    }
}
