/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import static com.mycompany.pdfsigner.pdfMain.password;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import java.util.Calendar;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

/**
 *
 * @author Luis Rodrigues
 */
public class PdfBox {

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfTestFile.pdf";
    public static final String savePdfPATH_pdfbox = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfbox_signed.pdf";
    public static final char[] password = "123456".toCharArray();

    public static void signPDF() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, CMSException, UnrecoverableEntryException, OperatorCreationException {
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
        InputStream sigIs = externalSigning.getContent();   // obter um byte[] que e a assinatura em forma CMS

        //Obter a assinatura em formato CMS que vai ser aplicada ao PDF
        byte[] cmsSignature = sign(sigIs);

        //aplicar a assinatura em cms ao PDF
        externalSigning.setSignature(cmsSignature);
        //fechar o inputstream e o ficheiro pdf
        sigIs.close();
        doc.close();

    }

    public static byte[] sign(InputStream content) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, CMSException, UnrecoverableEntryException, OperatorCreationException {
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

        
        // Time stamping
        
        
        
        
        
        
        
        
        return signedData.getEncoded();

    }

}
