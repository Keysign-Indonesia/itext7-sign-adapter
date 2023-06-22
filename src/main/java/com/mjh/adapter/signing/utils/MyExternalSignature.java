package com.mjh.adapter.signing.utils;

import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.ServerSigningResponse;
import com.mjh.adapter.signing.services.RTSigningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyExternalSignature implements IExternalSignature {
    Logger logger = LoggerFactory.getLogger(MyExternalSignature.class);

    private String profileName;

    private String hashAlgorithm;

    private String encryptionAlgorithm;

    private String signingUrl;

    private String jwToken;

    private String refToken;

    private String systemId;

    private String keyId;

    private String shaChecksum;

    private String retryFlag;

    private String trxId;

    private RTSigningService rtSigningService;

    public MyExternalSignature(
            String profileName, String signingUrl, String hashAlgorithm, String jwToken
            , String refToken, String systemId, String keyId, String shaChecksum
            , String retryFlag, String trxId, RTSigningService rtSigningService
    ) {
        this.logger.debug("TrxID [{}] Create new external signing", trxId);
        this.profileName = profileName;
        this.signingUrl = signingUrl;
        this.jwToken = jwToken;
        this.refToken = refToken;
        this.shaChecksum = shaChecksum;
        this.retryFlag = retryFlag;
        this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(hashAlgorithm));
        this.logger.debug("External signing hashAlgorithm : " + this.hashAlgorithm);
        this.encryptionAlgorithm = "RSA";
        this.systemId = systemId;
        this.keyId = keyId;
        this.trxId = trxId;
        this.rtSigningService = rtSigningService;
    }

    public String getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public String getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    public byte[] sign(byte[] bytes) throws SignAdapterException {
        this.logger.debug("TrxID [{}] Processing External Sign method process", this.trxId);
        try {
            ServerSigningResponse signingResponse = rtSigningService.POSTHashV3RequestResponse(this.signingUrl, this.profileName, MyUtil.base64encode(bytes)
                    , this.jwToken, this.refToken, this.systemId, this.keyId, this.shaChecksum
                    , this.retryFlag, this.trxId);
            return MyUtil.base64decode(signingResponse.getData());
        } catch (SignAdapterException sae) {
            throw sae;
        } catch (Exception ex) {
            throw new SignAdapterException("Error while signing [" + ex.getMessage() + "]", ex.getCause(), "96");
        }
    }
}
