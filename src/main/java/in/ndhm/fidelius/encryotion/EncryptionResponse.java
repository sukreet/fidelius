package in.ndhm.fidelius.encryotion;

public class EncryptionResponse {

    private String encryptedData;


    public EncryptionResponse(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }
}
