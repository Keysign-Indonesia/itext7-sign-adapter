package com.mjh.adapter.signing.services;

import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.GetSignerCertChainRequest;
import com.mjh.adapter.signing.model.GetSignerCertChainResponse;
import com.mjh.adapter.signing.model.ServerSigningResponse;
import com.mjh.adapter.signing.model.SigningRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

@Service
public class RTSigningService {
    private final Logger logger = LoggerFactory.getLogger(RTSigningService.class);

    @Autowired
    private RestTemplate restTemplate;

    public ServerSigningResponse POSTHashV3RequestResponse
            (String urlEndpoint, String profileName, String processData, String jwToken
                    , String refToken, String systemId, String keyId, String shaChecksum
                    , String retryFlag, String trxId) throws SignAdapterException {

        HttpHeaders headers = getHeaders();
        String token = "Bearer " + jwToken;
        headers.set("x-Gateway-APIKey", keyId);
        headers.set("Authorization", token);

        SigningRequest signingRequest = new SigningRequest();
        signingRequest.setProfileName(profileName);
        signingRequest.setData(processData);
        signingRequest.setShaChecksum(shaChecksum);
        signingRequest.setSystemId(systemId);
        signingRequest.setRefToken(refToken);
        signingRequest.setRetryFlag(retryFlag);

        HttpEntity<SigningRequest> request = new HttpEntity<>(signingRequest, headers);

        ResponseEntity<ServerSigningResponse> response = restTemplate.postForEntity(urlEndpoint, request , ServerSigningResponse.class);
        ServerSigningResponse signingResponse = response.getBody();

        if(HttpStatus.OK.equals(response.getStatusCode()) && signingResponse != null){
            if(!"00".equals(signingResponse.getErrorCode())) {
                throw new SignAdapterException("Error while signing [" + signingResponse.getErrorMessage() + "]", signingResponse.getErrorCode());
            }
            return signingResponse;
        } else {
            logger.warn("TrxID [{}] Failed invoke service", trxId);
            throw new SignAdapterException("Http status [" + response.getStatusCodeValue() + "] : Not Success", "95");
        }
    }

    private HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    public List<Certificate> getSignerCertChainRequestResponse(String urlEndpoint, String profileName
            , String jwToken, String refToken, String systemId, String keyId
            , String trxId) throws SignAdapterException, Exception {
        GetSignerCertChainResponse signerCertChain = getSignerCertChain(urlEndpoint, profileName, jwToken, refToken, systemId, keyId, trxId);

        List<Certificate> certs = new ArrayList<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        for(byte[] certByte: signerCertChain.getCerts()) {
            Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(certByte));
            certs.add(certificate);
        }
        return certs;
    }

    public GetSignerCertChainResponse getSignerCertChain(String urlEndpoint, String profileName
            , String jwToken, String refToken, String systemId, String keyId
            , String trxId) throws SignAdapterException, Exception {

        HttpHeaders headers = getHeaders();
        String token = "Bearer " + jwToken;
        headers.set("x-Gateway-APIKey", keyId);
        headers.set("Authorization", token);

        GetSignerCertChainRequest signerCertChainRequest = new GetSignerCertChainRequest();
        signerCertChainRequest.setProfileName(profileName);
        signerCertChainRequest.setSystemId(systemId);
        signerCertChainRequest.setRefToken(refToken);

        HttpEntity<GetSignerCertChainRequest> request = new HttpEntity<>(signerCertChainRequest, headers);

        ResponseEntity<GetSignerCertChainResponse> response = restTemplate.postForEntity(urlEndpoint, request , GetSignerCertChainResponse.class);
        GetSignerCertChainResponse signerCertChainResponse = response.getBody();

        if(HttpStatus.OK.equals(response.getStatusCode()) && signerCertChainResponse != null){
            if(!"00".equals(signerCertChainResponse.getErrorCode())) {
                throw new SignAdapterException("Error while get signer certificate chain [" + signerCertChainResponse.getErrorMessage() + "]", signerCertChainResponse.getErrorCode());
            }
            return signerCertChainResponse;
        } else {
            logger.warn("TrxID [{}] Failed invoke service", trxId);
            throw new SignAdapterException("Http status [" + response.getStatusCodeValue() + "] : Not Success", "95");
        }
    }

//    private String getBody(final User user) throws JsonProcessingException {
//        return new ObjectMapper().writeValueAsString(user);
//    }
}
