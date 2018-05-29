/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfSigner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Luis Rodrigues
 *
 * NOTA: para gerar certificados autoassinados usando a keytool: keytool
 * -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365 -v
 * -keyalg RSA -keystore keystore.p12
 */
public class pdfMain {

    final static String Algoritmo = "SHA1withRSA";

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfTestFile.pdf";
    public static final String savePdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\SIGNED_pdfTestFile.pdf";
    public static final String savePdfPATH_pdfbox = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfbox_signed.pdf";
    public static final char[] password = "123456".toCharArray();

    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("keystore.p12");
        FileOutputStream fos = new FileOutputStream(savePdfPATH);
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        // inicializa a keystore
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
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
        //assinar e verificar parametros da assinatura usando Itext
  //      Itext.signItext(pdfPATH, savePdfPATH, chain, pk, DigestAlgorithms.SHA1, provider.getName(), PdfSigner.CryptoStandard.CMS, "test Signature using itext", "Covilha");
//        Itext.checkSignatureItext();
        //pdfbox 
        
        
  //      PdfBox.signPDF();

     //   WinKeyStoreTests.init();
  
          CardConnect.initCard();
    
    }

}
