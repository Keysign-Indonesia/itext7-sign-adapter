package com.mjh.adapter.signing.common;

public class ConstantID {
    public static final String checkInputOK = "ALLOK";

    public static final String responStatusSuccess = "True";

    public static final String responStatusFail = "False";

    public static final String errCodeSUCCESS = "00";

    public static final String errCodeInvalidInput = "90";
    public static final String errCodeProfilenameNotFound = "91";

    public static final String errCodeInternalServerError = "92";

    public static final String errCodeGetCertChain = "93";

    public static final String errCodeGetCertificate = "94";

    public static final String errCodePostHashSigning = "95";

    public static final String errCodeExternalHashSigning = "96";

    public static final String errCodeAbnormalErrorHashSigning = "97";

    public static final String errCodeIntegrityCheckRevisionFailed = "80";

    public static final String errCodeIntegrityCheckSignatureFailed = "81";

    public static final String errCodeUpgradeDocumentException = "82";

    public static final String errCodeCertifiedDocException = "83";
    public static final String errMsgCertifiedDocException = "No changes to the document are permitted due to DocMDP transform parameters dictionary";

    public static final String errMsgSuccess = "-";

    public static final String errInternalApiServer = "Internal API Server Error";

    public static String snVisibleSigning = "Visible Signing Service";
    public static String snVisibleBoxSigning = "Visible BoxSigning Service";
    public static String snInvisibleSigning = "Invisible Signing Service";
    public static String snInvisibleBoxSigning = "Invisible BoxSigning Service";
    public static String snPdfSignatureValidation = "PDF Signature Validation Service";
    public static String snPdfSignatureExtraction = "PDF Signature Extraction Service";

    public static String errCodeOcspCrlExtend = "70";

}
