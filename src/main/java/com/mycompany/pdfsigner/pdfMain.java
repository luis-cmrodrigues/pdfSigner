/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.pdfa.PdfADocument;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Luis Rodrigues
 */
public class pdfMain {

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfTestFile.pdf";
    public static final String savePdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\SIGNED_pdfTestFile.pdf";
    public static final char[] password = "projetolab".toCharArray();
    final static String Algoritmo = "SHA1withRSA";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("clientkeystore");
        FileOutputStream fos = new FileOutputStream(savePdfPATH);

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        // inicializa a keystore
        java.security.KeyStore ks = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
        java.security.KeyStore.ProtectionParameter protParam = new java.security.KeyStore.PasswordProtection(password);

        try {
            ks.load(fis, password);
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(pdfMain.class.getName()).log(Level.SEVERE, null, ex);
        }

        String alias = ks.aliases().nextElement();

        //obtem a chave privada, e a cadeia de certificados
        java.security.KeyStore.PrivateKeyEntry pkEntry = (java.security.KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
        PrivateKey pk = pkEntry.getPrivateKey();
        //System.out.println(Utilities.bytesToHex(pk.getEncoded()));
        Certificate[] chain = (Certificate[]) ks.getCertificateChain(alias);

        //parte da abertura do pdf
        File pdfFile = new File(pdfPATH);
        PdfReader pdfReader = new PdfReader(pdfFile);
        PdfDocument pdf = new PdfDocument(pdfReader);

        //prints para teste
        //System.out.println(Utilities.bytesToHex(pk.getEncoded()));
        //System.out.println("private key format: " + pk.getFormat());
        //System.out.println("privatekey algorithm: " + pk.getAlgorithm());
        //outra maneira, atraves daquela funcao
        sign(pdfPATH, savePdfPATH, chain, pk, DigestAlgorithms.SHA1, provider.getName(), PdfSigner.CryptoStandard.CMS, "test", "Covilha");

        
       
    }

    public static void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);

        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance().setReason(reason).setLocation(location).setReuseAppearance(false);
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        appearance.setPageRect(rect).setPageNumber(1);
        signer.setFieldName("sig");

        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);

        
    }

    public static void checkSignature() throws FileNotFoundException, IOException {

    }
}
