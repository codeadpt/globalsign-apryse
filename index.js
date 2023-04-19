const { PDFNet } = require('@pdftron/pdfnet-node');
const fs = require('fs');
const https = require('https');
const axios = require('axios');

const pathToCert = '/app/trust/globalsign.pem';
const pathToKey = '/app/trust/globalsign.key';
const keyPassPhrase = 'K2c3Tro8A8WN87Sf';
const apiKey = '01f2d0ced7c82464';
const apiSecret = '4e056dd2989b85ddfd9e4b2ca638c7c6be34418a';
const pathToAatlCert = '/app/trust/aatl.crt';

const pathToSourceDoc = '/app/sample.pdf';
const pathToFinalDoc = '/app/sample-signed.pdf';

const main = async () => {

    /* PREPARE GLOBALSIGN DATA */

    // prepare globalsign api request
    const baseApiUrl = 'https://emea.api.dss.globalsign.com:8443/v2';
    const httpsAgent = new https.Agent({
        cert: fs.readFileSync(pathToCert),
        key: fs.readFileSync(pathToKey),
        passphrase: keyPassPhrase,
    });
    const config = {
        httpsAgent,
        headers: {
            "Content-Type": "application/json; charset=UTF-8",
        },
    };

    // authenticate with globalsign api
    const loginResponse = await axios.post(`${baseApiUrl}/login`, {
        api_key: apiKey,
        api_secret: apiSecret,
    }, config);
    const { access_token } = loginResponse.data;
    config.headers['Authorization'] = `Bearer ${access_token}`;

    // get the signing certificate from globalsign
    const identityResponse = await axios.post(`${baseApiUrl}/identity`, {
        "subject_dn": {
            "organizational_unit": ["Administration"],
        },
    }, config);
    const { id, signing_cert: signer_cert_value, ocsp_response } = identityResponse.data;
    const signer_cert_buff = Buffer.from(signer_cert_value, 'utf-8');
    const signer_cert = await new PDFNet.X509Certificate.createFromBuffer(signer_cert_buff);

    // get the certificate chain from globalsign
    const certPathResp = await axios.get(`${baseApiUrl}/certificate_path`, config);
    const { path: signer_ca_value } = certPathResp.data;
    const signer_ca_buff = Buffer.from(signer_ca_value, 'utf-8');
    const signer_ca = await new PDFNet.X509Certificate.createFromBuffer(signer_ca_buff);

    /* PREPARE THE DOCUMENT */

    // create a PDFDoc object from a pdf file by path
    const in_docpath = pathToSourceDoc;
    const doc = await PDFNet.PDFDoc.createFromFilePath(in_docpath);

    // find the first page of the document
    const page1 = await doc.getPage(1);
    const pageHeight = await page1.getPageHeight();

    /* PREPARE THE SIGNATURE FIELD */

    // Create a digital signature field and associated widget.
    const in_sig_field_name = 'MavSig';
    const digsig_field = await doc.createDigitalSignatureField(in_sig_field_name);
    const widgetAnnot = await PDFNet.SignatureWidget.createWithDigitalSignatureField(doc,
        new PDFNet.Rect(10, pageHeight - 60, 60, pageHeight - 10),
        digsig_field);
    await page1.annotPushBack(widgetAnnot);

    // Create a digital signature dictionary inside the digital signature field, in preparation for signing.
    const in_PAdES_signing_mode = true;
    await digsig_field.createSigDictForCustomSigning('Adobe.PPKLite',
        in_PAdES_signing_mode ? PDFNet.DigitalSignatureField.SubFilterType.e_ETSI_CAdES_detached : PDFNet.DigitalSignatureField.SubFilterType.e_adbe_pkcs7_detached,
        11500);

    // save the document with the added signature field
    const in_outpath = pathToFinalDoc;
    await doc.save(in_outpath, PDFNet.SDFDoc.SaveOptions.e_incremental);

    /* PREPARE THE SIGNING DATA */

    // Digest the relevant bytes of the document in accordance with ByteRanges surrounding the signature.
    const pdf_digest = await digsig_field.calculateDigest(PDFNet.DigestAlgorithm.Type.e_SHA256);

    /* Optionally, you can add a custom signed attribute at this point, such as one of the PAdES ESS attributes. The function we provide takes care of generating the correct PAdES ESS attribute depending on your digest algorithm. */
    const pades_versioned_ess_signing_cert_attribute = await PDFNet.DigitalSignatureField.generateESSSigningCertPAdESAttribute(signer_cert, PDFNet.DigestAlgorithm.Type.e_SHA256);

    // generate the signedAttrs timestampOnNextSave of CMS
    const signedAttrs = await PDFNet.DigitalSignatureField.generateCMSSignedAttributes(pdf_digest, pades_versioned_ess_signing_cert_attribute);

    // Calculate the digest of the signedAttrs (i.e. not the PDF digest, this time).
    const signedAttrs_digest = await PDFNet.DigestAlgorithm.calculateDigest(PDFNet.DigestAlgorithm.Type.e_SHA256, signedAttrs);
    const digest = Buffer.from(signedAttrs_digest).toString('hex').toUpperCase();

    /* SIGN DIGEST USING GLOBALSIGN */

    const timestampResp = await axios.get(`${baseApiUrl}/timestamp/${digest}`, config);
    const { token } = timestampResp.data;

    const signResp = await axios.get(`${baseApiUrl}/identity/${id}/sign/${digest}`, config);
    const { signature: signature_value_hex } = signResp.data;

    /* APPLY SIGNATURE TO DOC */

    const signature_value_buff = Buffer.from(signature_value_hex, 'hex');

    // Then, load all your chain certificates into a container of X509Certificate.
    const chain_certs = [signer_cert, signer_ca];

    // Then, create ObjectIdentifiers for the algorithms you have used.
    const digest_algorithm_oid = await PDFNet.ObjectIdentifier.createFromDigestAlgorithm(PDFNet.DigestAlgorithm.Type.e_SHA256);
    const signature_algorithm_oid = await PDFNet.ObjectIdentifier.createFromIntArray([1, 2, 840, 113549, 1, 1, 1]);

    // Then, put the CMS signature components together.
    const cms_signature = await PDFNet.DigitalSignatureField.generateCMSSignature(
        signer_cert, chain_certs, digest_algorithm_oid, signature_algorithm_oid, signature_value_buff,
        signedAttrs);

    // Write the signature to the document.
    doc.saveCustomSignature(cms_signature, digsig_field, in_outpath);

    /* TIMESTAMP THE DOC */

    // From Apryse
    const tst_config = await PDFNet.TimestampingConfiguration.createFromURL('http://aatl-timestamp.globalsign.com/tsa/v4v5effk07zor410rew22z');
    const opts = await PDFNet.VerificationOptions.create(PDFNet.VerificationOptions.SecurityLevel.e_compatibility_and_archiving);
    await opts.addTrustedCertificateUString(pathToAatlCert);
    await opts.enableOnlineCRLRevocationChecking(true);
    const result = await digsig_field.generateContentsWithEmbeddedTimestamp(tst_config, opts);
    if (!(await result.getStatus())) {
        console.log('Result: ' + (await result.getString()));
        if (await result.hasResponseVerificationResult()) {
            const tst_result = await result.getResponseVerificationResult();
            console.log('CMS digest status: ' + (await tst_result.getCMSDigestStatusAsString()));
            console.log('Message digest status: ' + (await tst_result.getMessageImprintDigestStatusAsString()));
            console.log('Trust status: ' + (await tst_result.getTrustStatusAsString()));
        }
        return false;
    }
    await doc.saveCustomSignature(await result.getData(), digsig_field, in_outpath);

    /* APPLY LTV */

    const verify_opts = await PDFNet.VerificationOptions.create(PDFNet.VerificationOptions.SecurityLevel.e_compatibility_and_archiving);
    await verify_opts.addTrustedCertificate(signer_ca_buff, PDFNet.VerificationOptions.CertificateTrustFlag.e_default_trust || PDFNet.VerificationOptions.CertificateTrustFlag.e_certification_trust);
    await verify_opts.enableOnlineCRLRevocationChecking(true);

    const verification_result = await digsig_field.verify(verify_opts);
    const ltvRes = await digsig_field.enableLTVOfflineVerification(verification_result);
    if (!ltvRes) {
        console.log('Could not enable LTV for DocTimeStamp.');
        return false;
    }
    await doc.save(in_outpath, PDFNet.SDFDoc.SaveOptions.e_incremental);
    
    console.log('Document signing complete');
};

PDFNet.runWithCleanup(main, 'demo:1677233651784:7d37e54e0300000000787c5b980ca265db369d39d653492e45c7be4a7f').catch(error => {
    console.log('Error: ', error);
}).then(() => { PDFNet.shutdown(); });