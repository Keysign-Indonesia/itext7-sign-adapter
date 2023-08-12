package com.mjh.adapter.signing.model;

import io.swagger.v3.oas.annotations.media.Schema;

public class VisibleSigningRequest {
    //    @ApiModelProperty(notes = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Digital signature certificate level, NOT_CERTIFIED or NO_CHANGES_ALLOWED")
    private String certificatelevel;

    //    @ApiModelProperty(notes = "Signing Profile name", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String profileName;

    //    @ApiModelProperty(notes = "Document source path", required = true)
    private String src;

    //    @ApiModelProperty(notes = "Document destination path", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String dest;

    private String spesimenPath;

    private String spesimenBase64;

    //    @ApiModelProperty(notes = "Digital signature reason", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String reason;

    //    @ApiModelProperty(notes = "Digital signature location", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private String location;

    //    @ApiModelProperty(notes = "Digital signature page", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int visSignaturePage = 1;

    //    @ApiModelProperty(notes = "Digital signature rectangle left lower x coordinate", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int visLLX = 0;

    //    @ApiModelProperty(notes = "Digital signature rectangle left lower y coordinate", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int visLLY = 0;

    //    @ApiModelProperty(notes = "Digital signature rectangle upper right x coordinate", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int visURX = 0;

    //    @ApiModelProperty(notes = "Digital signature rectangle upper right y coordinate", required = true)
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED)
    private int visURY = 0;

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

    public String getSpesimenPath() {
        return this.spesimenPath;
    }

    public void setSpesimenPath(String spesimenPath) {
        this.spesimenPath = spesimenPath;
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

    public int getVisSignaturePage() {
        return this.visSignaturePage;
    }

    public void setVisSignaturePage(int visSignaturePage) {
        this.visSignaturePage = visSignaturePage;
    }

    public int getVisLLX() {
        return this.visLLX;
    }

    public void setVisLLX(int visLLX) {
        this.visLLX = visLLX;
    }

    public int getVisLLY() {
        return this.visLLY;
    }

    public void setVisLLY(int visLLY) {
        this.visLLY = visLLY;
    }

    public int getVisURX() {
        return this.visURX;
    }

    public void setVisURX(int visURX) {
        this.visURX = visURX;
    }

    public int getVisURY() {
        return this.visURY;
    }

    public void setVisURY(int visURY) {
        this.visURY = visURY;
    }

    public String getCertificatelevel() {
        return this.certificatelevel;
    }

    public void setCertificatelevel(String certificatelevel) {
        this.certificatelevel = certificatelevel;
    }

    public String getSpesimenBase64() {
        return spesimenBase64;
    }

    public void setSpesimenBase64(String spesimenBase64) {
        this.spesimenBase64 = spesimenBase64;
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
        } else if (
                (this.spesimenPath == null || "".equals(this.spesimenPath.trim()))
                && (this.spesimenBase64 == null || "".equals(this.spesimenBase64.trim()))
        ){
            check = "Spesimen path/base64 should not be empty";
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
