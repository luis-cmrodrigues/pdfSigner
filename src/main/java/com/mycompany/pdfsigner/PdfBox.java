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
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;




/**
 *
 * @author Luis Rodrigues
 */
public class PdfBox {
    
    
    
    
    
    public static void signPDF(KeyStore keystore, FileInputStream fis, String password, FileOutputStream fos) throws IOException, NoSuchAlgorithmException, CertificateException{
        keystore.load(fis, password.toCharArray());
        
        PDSignature sig = new PDSignature();
        sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        sig.setName("Luis rodrigues");
        sig.setLocation("Lisboa");
        sig.setReason("testing using pdfBOX library");
        
        sig.setSignDate(Calendar.getInstance());
        
        
        
        
        
        
        
        
        
    }
    
    
}
