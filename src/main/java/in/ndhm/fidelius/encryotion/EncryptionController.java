package in.ndhm.fidelius.encryotion;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EncryptionController {

    @PostMapping(value = "/encrypt")
    public EncryptionResponse encrypt(@RequestBody EncryptionRequest encryptionRequest) {
        return new EncryptionResponse("yet to implement" + encryptionRequest.getPlainTextData()) ;
    }
}
