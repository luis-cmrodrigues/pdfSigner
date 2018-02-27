/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import java.util.Calendar;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTerminalField;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

/**
 *
 * @author Luis Rodrigues
 */
public class PdfBox {

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfTestFile.pdf";
    public static final String savePdfPATH_pdfbox = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfbox_signed.pdf";
    public static final char[] password = "123456".toCharArray();

    public static void signPDF() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, CMSException, UnrecoverableEntryException, OperatorCreationException, TSPException {
        FileInputStream fis = new FileInputStream("keystore.p12");

        File pdfFile = new File(pdfPATH);

        java.security.KeyStore keystore = java.security.KeyStore.getInstance("PKCS12");
        keystore.load(fis, password);

        // nota: PDSignature -- This represents a digital signature that can be attached to a document. To learn more about digital signatures, read Digital Signatures in a PDF by Adobe.
        PDDocument doc = PDDocument.load(pdfFile);
        FileOutputStream fos = new FileOutputStream(savePdfPATH_pdfbox);

        PDSignature sig = new PDSignature();

        sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        sig.setName("Luis rodrigues");
        sig.setLocation("Lisboa");
        sig.setReason("testing using pdfBOX library");

        sig.setSignDate(Calendar.getInstance());



        //External signing
        doc.addSignature(sig);
        ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(fos);            //ver jdocs desta funcao!!!!!
        InputStream sigIs = externalSigning.getContent();                                           // obter um byte[] que e a assinatura em forma CMS

        //Obter a assinatura em formato CMS que vai ser aplicada ao PDF
        byte[] cmsSignature = sign(sigIs);

        //aplicar a assinatura em cms ao PDF
        externalSigning.setSignature(cmsSignature);
        //fechar o inputstream e o ficheiro pdf
        sigIs.close();
        doc.close();

    }

    public static byte[] sign(InputStream content) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, CMSException, UnrecoverableEntryException, OperatorCreationException, TSPException {
        // cannot be done private (interface)
        FileInputStream fis = new FileInputStream("keystore.p12");

        File pdfFile = new File(pdfPATH);

        //inicializa keystore, tira a private key
        java.security.KeyStore keystore = java.security.KeyStore.getInstance("PKCS12");
        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);
        keystore.load(fis, password);
        String alias = keystore.aliases().nextElement();
        java.security.KeyStore.PrivateKeyEntry pkEntry = (java.security.KeyStore.PrivateKeyEntry) keystore.getEntry(alias, protParam);
        PrivateKey privateKey = pkEntry.getPrivateKey();

        //Obtenção da lista de certificados
        Certificate[] certChain = keystore.getCertificateChain(alias);
        List<Certificate> certList = new ArrayList<>();
        certList.addAll(Arrays.asList(certChain));

        Store certs = new JcaCertStore(certList);

        // CMSSignedDataGenerator é a classe que gera uma mensagem no formato PKCS7 == formato CMS
        //inicialização dos componentes necessários
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(certChain[0].getEncoded()); //certificado no formado ANS.1
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, new X509CertificateHolder(cert)));
        gen.addCertificates(certs);

        //É uma classe dos exemplos. As maneiras alternativas que tentei fazer nao funcionam
        CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
        //CMSProcessableFile msg = new CMSProcessableFile(pdfFile);
        //CMSTypedData tpData = (CMSTypedData) msg.getContentType();

        //não entendo muito bem como é que o CMSProcessableInputStream devolve algo do tipo CMSsignedData
        CMSSignedData signedData = gen.generate(msg, false);

        byte[] timeStamp = getTimeStamp(IOUtils.toByteArray(content));

        signedData = addSignedTimestamp(signedData, timeStamp);

        // Time stamping
        return signedData.getEncoded();

    }

    /**
     * junta o timestamp à assinatura em formato CMS
     *
     * @param signedData
     * @param timeStamp
     * @return
     * @throws IOException
     */
    public static CMSSignedData addSignedTimestamp(CMSSignedData signedData, byte[] timeStamp) throws IOException {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<>();

        for (SignerInformation signer : signerStore.getSigners()) {
            newSigners.add(signTampStamp(signer, timeStamp));
        }

        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    /**
     * Introduz o timestamp no campo dos unsigned attributes da assinatura
     *
     * @param signer
     * @param timeStamp
     * @return
     * @throws IOException
     */
    private static SignerInformation signTampStamp(SignerInformation signer, byte[] timeStamp) throws IOException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(timeStamp)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(signedAttributes));
    }

    /**
     * devolve um byte[] com o timestamp obtido a partir da resposta de uma TSA
     *
     * @param messageImprint
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws TSPException
     */
    public static byte[] getTimeStamp(byte[] messageImprint) throws NoSuchAlgorithmException, IOException, TSPException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();

        byte[] hash = digest.digest(messageImprint);

        //generate TSA request
        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = getHashObjectIdentifier(digest.getAlgorithm());

        // inicializa a timestamp request com um valor aleatório
        SecureRandom random = new SecureRandom();
        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(random.nextInt()));

        //get TSA response
        byte[] tsaResponse = getTSAResponse(request.getEncoded());
        TimeStampResponse response = new TimeStampResponse(tsaResponse);

        //ve se a reposta está bem formada para a request que foi feita. depois e obtido o token da resposta
        response.validate(request);

        TimeStampToken token = response.getTimeStampToken();

        return token.getEncoded();

    }

    /**
     * faz a ligação a um servidor TSA e devolve a resposta
     *
     * @param request
     * @return
     * @throws MalformedURLException
     * @throws IOException
     */
    private static byte[] getTSAResponse(byte[] request) throws MalformedURLException, IOException {
        URL url = new URL("http://sha256timestamp.ws.symantec.com/sha256/timestamp");
        URLConnection connection = url.openConnection();
        connection.setDoInput(true); //desnecessário, por default ja e true
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");

        OutputStream output = connection.getOutputStream();
        output.write(request);
        IOUtils.closeQuietly(output);

        InputStream input = connection.getInputStream();
        byte[] response = IOUtils.toByteArray(input);
        IOUtils.closeQuietly(input);

        return response;
    }

    // devolve a ASN.1 OID do algoritmo de hash fornecido 
    private static ASN1ObjectIdentifier getHashObjectIdentifier(String algorithm) {
        switch (algorithm) {
            case "MD2":
                return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md2.getId());
            case "MD5":
                return new ASN1ObjectIdentifier(PKCSObjectIdentifiers.md5.getId());
            case "SHA-1":
                return new ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.getId());
            case "SHA-224":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha224.getId());
            case "SHA-256":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.getId());
            case "SHA-384":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha384.getId());
            case "SHA-512":
                return new ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha512.getId());
            default:
                return new ASN1ObjectIdentifier(algorithm);
        }
    }

}
