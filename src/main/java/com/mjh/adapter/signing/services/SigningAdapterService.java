package com.mjh.adapter.signing.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import com.mjh.adapter.signing.common.ConstantID;
import com.mjh.adapter.signing.common.SignAdapterException;
import com.mjh.adapter.signing.model.InvisibleSigningRequest;
import com.mjh.adapter.signing.model.SigningResponse;
import com.mjh.adapter.signing.model.VisibleSigningRequest;
import com.mjh.adapter.signing.utils.MyExternalSignature;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("signingadapterservices")
@RequestMapping({"/adapter/pdfsigning/rest"})
@Tag(name="Signing Adapter Service", description="Operations to signing document")
public class SigningAdapterService {
    @Value("${MJ_HASH_URL}")
    private String hashUrl;

    @Value("${MJ_CERTCHAIN_URL}")
    private String certChainUrl;

    @Value("${ADAPTER_VALIDATION}")
    private String adapterValidation;

    @Value("${TSA_URL}")
    private String tsaURL;

    @Value("${tsa.service-user}")
    private String tsaUsername;

    @Value("${tsa.service-pass}")
    private String tsaPassword;

    @Value("${apg.keyId}")
    private String strKeyId;

    @Value("${apg.systemId}")
    private String systemId;

    @Autowired
    private RTSigningService rtSigningService;

    Logger logger = LoggerFactory.getLogger(SigningAdapterService.class);

    @PostMapping({"/visibleSign"})
    @Operation(summary = "visibleSign", description = "Visible Signing Rest Service")
    public ResponseEntity<SigningResponse> visibleSign(@RequestBody VisibleSigningRequest input) throws Exception {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());

        SigningResponse signingResponse = new SigningResponse();

        long start = System.currentTimeMillis();
        String trxId = UUID.randomUUID().toString();
        boolean visibleSign = true;
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.logger.info(serviceStart(trxId, ConstantID.snVisibleSigning));
            this.logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(input));
        } catch (Exception ignored) {}
        try {
            if (input != null && "ALLOK".equals(input.checkInput())) {
                checkAndWarningSpesificEmptyParam(input.getJwToken(), input.getRefToken());
                MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
                String shaChecksum = getFileChecksum(sha256Digest, new File(input.getSrc()));
                if (this.adapterValidation != null && "1".equals(this.adapterValidation.trim())) {
                    String newSrc = validateOrUpgrade(input.getSrc(), input.getDest(), input.getDocpass());
                    if (!input.getSrc().equals(newSrc))
                        input.setSrc(newSrc);
                }
                String signerProfileName = input.getProfileName();
                if (signerProfileName != null && !"".equals(signerProfileName.trim())) {
                    List<Certificate> certs = rtSigningService.getSignerCertChainRequestResponse(this.certChainUrl, signerProfileName, input.getJwToken(), input.getRefToken(), this.systemId, this.strKeyId, trxId);
                    Certificate[] chain = certs.<Certificate>toArray(new Certificate[certs.size()]);
                    this.logger.debug("TrxID [{}] Finish getting certificate chain", trxId);
                    ITSAClient tsaClient = populateTsaClient();
                    List<ICrlClient> crlList = populateCrlList(chain);
                    this.logger.debug("TrxID [{}] Setup spesimen rectangle", trxId);
                    float newWidth = (input.getVisURX() - input.getVisLLX());
                    float newHeight = (input.getVisURY() - input.getVisLLY());
                    Rectangle rectangle = new Rectangle(input.getVisLLX(), input.getVisLLY()
                            , newWidth
                            , newHeight);
                    try {
                        this.logger.debug("TrxID [{}] Setup spesimen image", trxId);
                        ImageData img;
                        if(input.getSpesimenPath() != null && !"".equals(input.getSpesimenPath())) {
                            img = ImageDataFactory.create(input.getSpesimenPath());
                        } else {
                            img = ImageDataFactory.create(Base64.decode(input.getSpesimenBase64()));
                        }
                        this.logger.debug("TrxID [{}] Finish setup spesimen image", trxId);
                        sign(input.getSrc(), input.getDest(), input.getDocpass(), chain, "SHA-256", PdfSigner.CryptoStandard.CMS,
                                input.getReason(), input.getLocation(), true, rectangle, input
                                .getVisSignaturePage(), img, input.getCertificatelevel(), crlList, tsaClient, signerProfileName, input
                                .getJwToken(), input.getRefToken(), shaChecksum, input
                                .getRetryFlag(), trxId);
                        signingResponse.setStatus("True");
                        signingResponse.setErrorCode("00");
                        signingResponse.setErrorMessage("-");
                    } catch (SignAdapterException sae) {
                        signingResponse.setStatus("False");
                        signingResponse.setErrorCode(sae.getCode());
                        signingResponse.setErrorMessage(sae.getMessage());
                    } catch (Exception ex) {
                        this.logger.error("TrxID [{}] ERROR process signing ", trxId, ex);
                        signingResponse.setStatus("False");
                        signingResponse.setErrorCode("92");
                        signingResponse.setErrorMessage(ex.getMessage());
                    }
                } else {
                    signingResponse.setStatus("False");
                    signingResponse.setErrorCode("91");
                    signingResponse.setErrorMessage("Profilename not found");
                }
            } else {
                signingResponse.setStatus("False");
                signingResponse.setErrorCode("90");
                signingResponse.setErrorMessage(input.checkInput());
            }
        } catch (SignAdapterException sae) {
            signingResponse.setStatus("False");
            signingResponse.setErrorCode(sae.getCode());
            signingResponse.setErrorMessage(sae.getMessage());
        } catch (Exception ex) {
            this.logger.error("TrxID [{}] ERROR process signing ", trxId, ex);
            signingResponse.setStatus("False");
            signingResponse.setErrorCode("92");
            signingResponse.setErrorMessage(ex.getMessage());
        }
        try {
            this.logger.info(serviceStop(trxId, ConstantID.snVisibleSigning));
            this.logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingResponse));
        } catch (Exception ignored) {}
        this.logger.info("TrxID [{}] Service [{}] execution time [{}] ms",trxId, ConstantID.snVisibleSigning, System.currentTimeMillis() - start);
        return new ResponseEntity<>(signingResponse, HttpStatus.OK);
    }

    @PostMapping({"/invisibleSign"})
    @Operation(summary = "invisibleSign", description = "Invisible Signing Rest Service")
    public ResponseEntity<SigningResponse> invisibleSign(@RequestBody InvisibleSigningRequest input) throws Exception {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());

        SigningResponse signingResponse = new SigningResponse();
        long start = System.currentTimeMillis();
        String trxId = UUID.randomUUID().toString();
        boolean visibleSign = false;
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.logger.info(serviceStart(trxId, ConstantID.snInvisibleSigning));
            this.logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(input));
        } catch (Exception ignored) {}
        try {
            if (input != null && "ALLOK".equals(input.checkInput())) {
                checkAndWarningSpesificEmptyParam(input.getJwToken(), input.getRefToken());
                MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
                String shaChecksum = getFileChecksum(sha256Digest, new File(input.getSrc()));
                if (this.adapterValidation != null && "1".equals(this.adapterValidation.trim())) {
                    String newSrc = validateOrUpgrade(input.getSrc(), input.getDest(), input.getDocpass());
                    if (!input.getSrc().equals(newSrc))
                        input.setSrc(newSrc);
                }
                String signerProfileName = input.getProfileName();
                if (signerProfileName != null && !"".equals(signerProfileName.trim())) {
                    List<Certificate> certs = rtSigningService.getSignerCertChainRequestResponse(this.certChainUrl, signerProfileName, input.getJwToken(), input.getRefToken(), this.systemId, this.strKeyId, trxId);
                    Certificate[] chain = certs.<Certificate>toArray(new Certificate[certs.size()]);
                    this.logger.debug("TrxID [{}] Finish getting certificate chain", trxId);
                    ITSAClient tsaClient = populateTsaClient();
                    List<ICrlClient> crlList = populateCrlList(chain);
                    Rectangle rectangle = null;
                    try {
                        ImageData img = null;
                        sign(input.getSrc(), input.getDest(), input.getDocpass(), chain, "SHA-256", PdfSigner.CryptoStandard.CMS, input
                                .getReason(), input.getLocation(), false, rectangle, 1, img, input
                                .getCertificatelevel(), crlList, tsaClient, signerProfileName, input
                                .getJwToken(), input.getRefToken(), shaChecksum, input
                                .getRetryFlag(), trxId);
                        signingResponse.setStatus("True");
                        signingResponse.setErrorCode("00");
                        signingResponse.setErrorMessage("-");
                    } catch (SignAdapterException sae) {
                        signingResponse.setStatus("False");
                        signingResponse.setErrorCode(sae.getCode());
                        signingResponse.setErrorMessage(sae.getMessage());
                    } catch (Exception ex) {
                        this.logger.error("TrxID [{}] ERROR process signing ", trxId, ex);
                        signingResponse.setStatus("False");
                        signingResponse.setErrorCode("92");
                        signingResponse.setErrorMessage(ex.getMessage());
                    }
                } else {
                    signingResponse.setStatus("False");
                    signingResponse.setErrorCode("91");
                    signingResponse.setErrorMessage("Profilename not found");
                }
            } else {
                signingResponse.setStatus("False");
                signingResponse.setErrorCode("90");
                signingResponse.setErrorMessage(input.checkInput());
            }
        } catch (SignAdapterException sae) {
            signingResponse.setStatus("False");
            signingResponse.setErrorCode(sae.getCode());
            signingResponse.setErrorMessage(sae.getMessage());
        } catch (Exception ex) {
            this.logger.error("TrxID [{}] ERROR process signing ", trxId, ex);
            signingResponse.setStatus("False");
            signingResponse.setErrorCode("92");
            signingResponse.setErrorMessage(ex.getMessage());
        }
        try {
            this.logger.info(serviceStop(trxId, ConstantID.snInvisibleSigning));
            this.logger.debug(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signingResponse));
        } catch (Exception ignored) {}
        this.logger.info("TrxID [{}] Service [{}] execution time [{}] ms",trxId, ConstantID.snInvisibleSigning, System.currentTimeMillis() - start);
        return new ResponseEntity<>(signingResponse, HttpStatus.OK);
    }

    private ITSAClient populateTsaClient() {
        TSAClientBouncyCastle tSAClientBouncyCastle = null;
        ITSAClient tsaClient = null;
        this.logger.debug("Try setup TSAClient");
        if (this.tsaURL != null && !"".equals(this.tsaURL.trim())) {
            if (this.tsaUsername != null && !"".equals(this.tsaUsername.trim()) && !"yourusername".equals(this.tsaUsername.trim()) &&
                    this.tsaPassword != null && !"".equals(this.tsaPassword.trim()) && !"yourpassword".equals(this.tsaPassword.trim())) {
                this.logger.info("Setup TSA Client with user password");
                tSAClientBouncyCastle = new TSAClientBouncyCastle(this.tsaURL, this.tsaUsername, this.tsaPassword);
            }
            if (tSAClientBouncyCastle == null)
                this.logger.debug("Setup TSA Client without user password");
            tSAClientBouncyCastle = new TSAClientBouncyCastle(this.tsaURL);
        }
        return (ITSAClient)tSAClientBouncyCastle;
    }

    private List<ICrlClient> populateCrlList(Certificate[] chain) {
        List<ICrlClient> crlList = new ArrayList<>();
        this.logger.debug("Try to setup CrlClient");
        try {
            this.logger.debug("Setup Crl Client using cert chain info");
            CrlClientOnline crlClientOnline = new CrlClientOnline(chain);
            crlList.add(crlClientOnline);
        } catch (Exception exception) {}
        if (crlList.size() < 1) {
            this.logger.debug("Empty Crl Client, remove crl list object");
            crlList = null;
        }
        return crlList;
    }

    private void checkAndWarningSpesificEmptyParam(String strJWT, String strRefToken) {
        if (strJWT == null || "".equals(strJWT.trim()))
            this.logger.warn("JwToken parameter is empty");
        if (strRefToken == null || "".equals(strRefToken.trim()))
            this.logger.warn("RefToken parameter is empty");
    }

    private void sign(String src, String dest, String docPass, Certificate[] chain, String digestAlgorithm,
                      PdfSigner.CryptoStandard subfilter, String reason, String location,
                      boolean visibleSign, Rectangle rectangle, int visPage, ImageData img, String certificateLevel,
                      List<ICrlClient> crlList, ITSAClient tsaClient, String signerProfileName, String jwToken,
                      String refToken, String shaChecksum, String retryFlag, String trxId)
            throws IOException
    {
        PdfReader reader;
        this.logger.debug("Entering Sign method process");
        boolean successProcess = true;
        if (docPass != null && !"".equals(docPass.trim())) {
            ReaderProperties props = new ReaderProperties();
            props.setPassword(docPass.getBytes());
            reader = new PdfReader(src, props).setUnethicalReading(true);
        } else {
            reader = new PdfReader(src);
        }
        FileOutputStream os = new FileOutputStream(dest);
        PdfSigner signer = new PdfSigner(reader, os, new StampingProperties().useAppendMode());
        PdfDocument pdfDocument = signer.getDocument();

        int numberOfPages = pdfDocument.getNumberOfPages();
        if (numberOfPages < visPage) {
            this.logger.warn("TrxID [{}] visible page more than doc number of pages, using last page", trxId);
            visPage = numberOfPages;
        } else if (visPage < 1) {
            visPage = 1;
        }

        try {
            if (refToken != null && !"".equals(refToken))
                reason = "[" + refToken + "] " + reason;

            String sigFieldName = "sig" + System.currentTimeMillis();
            signer.setFieldName(sigFieldName);
            //final signature
            signer.setCertificationLevel(1);

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance.setReason(reason);
            appearance.setLocation(location);

            if (visibleSign) {
                this.logger.debug("Process visible sign");
                appearance
                        .setPageRect(rectangle)
                        .setSignatureGraphic(img)
                        .setImageScale(0)
                        .setPageNumber(visPage)
                        .setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            } else {
                this.logger.debug("TrxID [{}] Process invisible sign", trxId);
            }

            this.logger.debug("TrxID [{}] Prepare to create external signature", trxId);
            BouncyCastleDigest bouncyCastleDigest = new BouncyCastleDigest();
            MyExternalSignature myExternalSignature = new MyExternalSignature(signerProfileName, this.hashUrl
                    , digestAlgorithm, jwToken, refToken, this.systemId, this.strKeyId, shaChecksum
                    , retryFlag, trxId, rtSigningService);
            try {
                signer.signDetached((IExternalDigest)bouncyCastleDigest
                        , (IExternalSignature)myExternalSignature, chain
                        , crlList, null, tsaClient, 0, subfilter);
            } catch (Exception e) {
                this.logger.error("TrxID [{}] Error Signing document", trxId, e);
                String recommendC = "you can retry signing request, using same api with specified parameter 'retryFlag':'1'";
                throw new SignAdapterException(e.getMessage() + ",  *****" + recommendC, e.getCause(), "97");
            }
        } catch (Exception e) {
            this.logger.error("TrxID [{}] Error Processing document", trxId, e);
            successProcess = false;
            throw e;
        } finally {
            if (reader != null)
                try {
                    reader.close();
                } catch (Exception ignored) {}
            if (os != null)
                try {
                    os.close();
                } catch (Exception exception) {}
            if (!successProcess) {
                File destFile = new File(dest);
                if (destFile.exists())
                    destFile.delete();
            }
        }
    }

    private String getFileChecksum(MessageDigest digest, File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;
        while ((bytesCount = fis.read(byteArray)) != -1)
            digest.update(byteArray, 0, bytesCount);
        fis.close();
        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++)
            sb.append(Integer.toString((bytes[i] & 0xFF) + 256, 16).substring(1));
        return sb.toString();
    }

    private boolean isApprovalSignatureExistForFinalSignature(String src, String docPass) {
        logger.debug("===== isApprovalSignatureExistForFinalSignature =====");
        PdfReader reader = null;
        if(src != null && !"".equals(src.trim())) {
            logger.debug("opening pdf doc");
            try {
                if (docPass != null && !"".equals(docPass.trim())) {
                    ReaderProperties props = new ReaderProperties();
                    props.setPassword(docPass.getBytes());
                    reader = new PdfReader(src, props).setUnethicalReading(true);
                } else {
                    reader = new PdfReader(src);
                }
                PdfDocument pdfDoc = new PdfDocument(reader);
                PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDoc, false);
                SignaturePermissions perms = null;
                SignatureUtil signUtil = new SignatureUtil(pdfDoc);
                List<String> names = signUtil.getSignatureNames();
                logger.debug("pdf doc having {} signature(s)", names.size());
                if(names.size() > 0) {
                    for (String name : names) {
                        logger.debug("===== " + name + " =====");
                        PdfDictionary sigDict = signUtil.getSignatureDictionary(name);
                        perms = new SignaturePermissions(sigDict, perms);
                        logger.debug("********#####******>>Certificate LEVEL::: "+ (perms.isCertification() ? "certification" : "approval"));
                        return !perms.isCertification();
                    }
                }
            } catch (Exception ignored) {
                ignored.printStackTrace();
            } finally {
                if(reader != null) {
                    try {
                        reader.close();
                    }catch (Exception ignored){}
                }
            }
        }
        return false;
    }

    private String validateOrUpgrade(String src, String destOrig, String docPass) throws SignAdapterException {
        PdfReader reader = null;
        String dest = src;
        int validateResult = 0;
        String exectionErrMessage = "";
        try {
            boolean blnEncrypted = false;
            if (docPass != null && !"".equals(docPass.trim())) {
                ReaderProperties props = new ReaderProperties();
                props.setPassword(docPass.getBytes());
                reader = new PdfReader(src, props).setUnethicalReading(true);
                blnEncrypted = true;
            } else {
                reader = new PdfReader(src);
            }
            PdfDocument srcDoc = new PdfDocument(reader);
            PdfAcroForm form = PdfAcroForm.getAcroForm(srcDoc, false);
            SignaturePermissions perms = null;
            SignatureUtil signatureUtil = new SignatureUtil(srcDoc);
            List<String> names = signatureUtil.getSignatureNames();
            if (names.size() > 0) {
                for(String name : names) {
                    logger.debug("Inspect signature name : {}", name);
                    PdfPKCS7 pkcs7 = verifySignatureX(signatureUtil, name);

                    PdfDictionary sigDict = signatureUtil.getSignatureDictionary(name);
                    perms = new SignaturePermissions(sigDict, perms);
                    logger.debug("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
                    if(perms.isCertification() && !perms.isFillInAllowed()){
                        throw new SignAdapterException("Document already Certified, No changes are allowed", ConstantID.errCodeCertifiedDocException);
                    }
                }
            }
        } catch (IOException e) {
            validateResult = 4;
            exectionErrMessage = "IOException-" + e.getMessage();
            this.logger.warn("IOException while processing document with message [" + e.getMessage() + "]");
        } catch (GeneralSecurityException e) {
            validateResult = 1;
            exectionErrMessage = "GeneralSecurityException-" + e.getMessage();
            this.logger.warn("GeneralSecurityException while processing document with message [" + e.getMessage() + "]");
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception e) {
                    this.logger.warn("Exception closing reader with message [" + e.getMessage() + "]");
                }
            }
        }
        if (validateResult == 1)
            throw new SignAdapterException("Source Document has been change since it was signed", ConstantID.errCodeIntegrityCheckRevisionFailed);
        if (validateResult == 2)
            throw new SignAdapterException("Source Document has invalid signature", ConstantID.errCodeIntegrityCheckSignatureFailed);
        if (validateResult == 3)
            throw new SignAdapterException("Failed to upgrade document version", ConstantID.errCodeUpgradeDocumentException);
        if (validateResult == 4)
            throw new SignAdapterException("Cannot upgrade document version, with message [" + exectionErrMessage + "]", ConstantID.errCodeUpgradeDocumentException);
        return src;
    }

    private PdfPKCS7 verifySignatureX(SignatureUtil signUtil, String name) throws GeneralSecurityException {
        PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

        logger.debug("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
        logger.debug("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
        logger.debug("Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());

        return pkcs7;
    }

    private String serviceStart(String trxId, String service) throws Exception {
        return "===== [" + trxId + "] " + service + " [S] =====";
    }

    private String serviceStop(String trxId, String service) throws Exception {
        return "===== [" + trxId + "] " + service + " [E] =====";
    }
}