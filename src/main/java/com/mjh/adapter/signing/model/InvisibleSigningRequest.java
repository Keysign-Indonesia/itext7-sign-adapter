package com.mjh.adapter.signing.model;

import io.swagger.v3.oas.annotations.media.Schema;

public class InvisibleSigningRequest {
    //    @ApiModelProperty(notes = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED")
    private String certificatelevel;

    //    @ApiModelProperty(notes = "Signing Profile name", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String profileName;

    //    @ApiModelProperty(notes = "Document source path", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String src;

    //    @ApiModelProperty(notes = "Document destination path", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String dest;

    //    @ApiModelProperty(notes = "Digital signature reason", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String reason;

    //    @ApiModelProperty(notes = "Digital signature location", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String location;

    //    @ApiModelProperty(notes = "Signing doc password if any | not implemented yet")
    private String docpass;

    //    @ApiModelProperty(notes = "Json Web Token for security purpose")
    private String jwToken;

    //    @ApiModelProperty(notes = "Reference Token for relation purpose")
    private String refToken;

    //    @ApiModelProperty(notes = "Signing retry flag, fill 1 for retry")
    private String retryFlag;
    private String systemId;

    public String getRetryFlag() {
        return this.retryFlag;
    }

    public void setRetryFlag(String retryFlag) {
        this.retryFlag = retryFlag;
    }

    public String getProfileName() {
        return this.profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getDocpass() {
        return this.docpass;
    }

    public void setDocpass(String docpass) {
        this.docpass = docpass;
    }

    public String getSrc() {
        return this.src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public String getDest() {
        return this.dest;
    }

    public void setDest(String dest) {
        this.dest = dest;
    }

    public String getReason() {
        return this.reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getLocation() {
        return this.location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getCertificatelevel() {
        return this.certificatelevel;
    }

    public void setCertificatelevel(String certificatelevel) {
        this.certificatelevel = certificatelevel;
    }

    public String checkInput() {
        String check = "";
        if (this.profileName == null || "".equals(this.profileName.trim())) {
            check = "Profile name should not be empty";
        } else if (this.src == null || "".equals(this.src.trim())) {
            check = "Source file path should not be empty";
        } else if (this.dest == null || "".equals(this.dest.trim())) {
            check = "Destination file path should not be empty";
        } else if (this.reason == null || "".equals(this.reason.trim())) {
            check = "Reason should not be empty";
        } else if (this.location == null || "".equals(this.location.trim())) {
            check = "Location should not be empty";
        } else if (this.certificatelevel == null || "".equals(this.certificatelevel.trim())) {
            check = "Certificate level should not be empty";
        } else {
            check = "ALLOK";
        }
        return check;
    }

    public String getSystemId() {
        return systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId;
    }

    public String getJwToken() {
        return this.jwToken;
    }

    public void setJwToken(String jwToken) {
        this.jwToken = jwToken;
    }

    public String getRefToken() {
        return this.refToken;
    }

    public void setRefToken(String refToken) {
        this.refToken = refToken;
    }
}
