package com.mjh.adapter.signing.model;

import lombok.Data;

@Data
public class SigningRequest {
    private String profileName;
    private String data;
    private String systemId;
    private String shaChecksum;
    private String retryFlag;
    private String refToken;

}
