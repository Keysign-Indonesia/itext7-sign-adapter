package com.mjh.adapter.signing.model;

import lombok.Data;

@Data
public class GetSignerCertChainRequest {
    private String profileName;
    private String systemId;
    private String refToken;

}
