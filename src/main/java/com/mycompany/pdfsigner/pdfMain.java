/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Luis Rodrigues
 */
public class pdfMain {

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\pdfTestFile.pdf";
    public static final char[] password = "projetolab".toCharArray();

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, UnrecoverableKeyException {
        FileInputStream fis = new FileInputStream("clientkeystore");
        
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
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
        Certificate[] chain = (Certificate[]) ks.getCertificateChain(alias);

        //parte da abertura do pdf
        File pdfFile = new File(pdfPATH);
        PdfReader pdfReader = null;
        PdfDocument pdf = null;

        try {
            pdfReader = new PdfReader(pdfFile);
            pdf = new PdfDocument(pdfReader);
            //System.out.println(pdf.getDocumentInfo().getAuthor() + " " + pdf.getDocumentInfo().getKeywords());
        } catch (IOException ex) {
            Logger.getLogger(pdfMain.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("ERROR: File not Found");
            return;
        }

    }

}
