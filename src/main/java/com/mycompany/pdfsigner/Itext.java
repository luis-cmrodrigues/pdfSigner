/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfObject;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.SignatureUtil;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Luis Rodrigues
 */
public class Itext {

    public static final String pdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\ccSigned.pdf";
    public static final String savePdfPATH = (Paths.get(".").toAbsolutePath().normalize().toString()) + "\\SIGNED_pdfTestFile.pdf";
    public static final char[] password = "projetolab".toCharArray();

    public static void signItext(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter, String reason, String location) throws GeneralSecurityException, IOException {
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

    public static void checkSignatureItext() throws FileNotFoundException, IOException {
        //parte da abertura do pdf
        File pdfFile = new File(pdfMain.pdfPATH);
        PdfReader pdfReader = new PdfReader(pdfFile);
        PdfDocument pdf = new PdfDocument(pdfReader);
        SignatureUtil utl = new SignatureUtil(pdf);
        List<String> names = utl.getSignatureNames();
        System.out.println("Numero de campos assinados no pdf: " + Integer.toString(names.size()));
        System.out.println("lista de fieldnames assinados: ");
        for (String name : names) {
            System.out.println("Field Name:" + name);
        }
        //print do signature dictionary
        PdfDictionary dict = utl.getSignatureDictionary(names.get(0));
        //System.out.println(dict.toString());
        //Files.write(new File("signature.txt").toPath(), utl.getSignatureDictionary(names.get(0)).toString().getBytes());
        Set<PdfName> dicSet = dict.keySet();
        Collection<PdfObject> dicValues = dict.values();
        Object[] valueObj = dicValues.toArray();
        //usefull: http://127.0.0.1:8082/resource/jar%3Afile%3A/C%3A/Users/Luis%2520Rodrigues/.m2/repository/com/itextpdf/kernel/7.1.0/kernel-7.1.0-javadoc.jar!/com/itextpdf/kernel/pdf/PdfDictionary.html
        //basicamente um dictionary faz o mapping entre keys e o seu respetivo value
        for (Object object : valueObj) {
            //valor contido no campo dos values, neste caso PdfObjects
            System.out.println(object.toString());
        }
        for (PdfName pdfName : dicSet) {
            // valores das keys, neste caso PdfName
            System.out.println(pdfName.toString());
        }
        System.out.println(dict.getAsString(PdfName.Name));
        System.out.println(dict.getAsString(PdfName.Reason));
    }
    
}
