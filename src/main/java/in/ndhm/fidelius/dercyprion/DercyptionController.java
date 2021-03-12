package in.ndhm.fidelius.dercyprion;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DercyptionController {

    @PostMapping(value = "/decrypt")
    public DecryptionResponse decrypt(@RequestBody DecryptionRequest encryptionRequest) {
        return new DecryptionResponse("yet to implement" + encryptionRequest.getEncryptedData());
    }
}
