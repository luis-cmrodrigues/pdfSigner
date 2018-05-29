/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author Luis Rodrigues
 */
public class WinKeyStoreTests {

    public static void init() {
        try {
            KeyStore keyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            keyStore.load(null, null);  // Load keystore

            Enumeration<String> lista = keyStore.aliases();
            
            while (lista.hasMoreElements()) {
                String alias = lista.nextElement();
                System.out.println(alias);
                Certificate c = keyStore.getCertificate(alias);
                //System.out.println(c.getType());
                
                if(alias.equals("Carla Valido")){
                    System.out.println("dasdasdas");
                }
                
                PrivateKey pk = (PrivateKey) keyStore.getKey("Carla Valido", null);
                if(pk == null){
                    System.out.println("NULL PRIVATE KEY");
                }
                
            }
            
            
            
            
            
            
            
            //_fixAliases(keyStore);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    private static void _fixAliases(KeyStore keyStore)
            throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        Field field;
        KeyStoreSpi keyStoreVeritable;

        field = keyStore.getClass().getDeclaredField("keyStoreSpi");
        field.setAccessible(true);
        keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

        if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
            Collection entries;
            String alias, hashCode;
            X509Certificate[] certificates;

            field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
            field.setAccessible(true);
            
            //entries =  (Collection) field.get(keyStoreVeritable);
            
            entries = ((HashMap) field.get(keyStoreVeritable)).values();
            
            for (Object entry : entries) {
                field = entry.getClass().getDeclaredField("certChain");
                field.setAccessible(true);
                certificates = (X509Certificate[]) field.get(entry);

                hashCode = Integer.toString(certificates[0].hashCode());

                field = entry.getClass().getDeclaredField("alias");
                field.setAccessible(true);
                alias = (String) field.get(entry);

                if (!alias.equals(hashCode)) {
                    field.set(entry, alias.concat(" - ").concat(hashCode));
                } // if
            } // for
        } // if

    } // _fixAliases  

    static public String chooseAlias(KeyStore ks) throws KeyStoreException {
        final String autenticar = "Autenticação";
        final String assinar = "Assinatura";

        Enumeration<String> aliases = ks.aliases();

        int kssize = ks.size();
        System.out.println("ks size=" + kssize);
        int cnt = 0;

        while (aliases.hasMoreElements()) {
            String aliasKey = aliases.nextElement();
            System.out.println("cnt=" + cnt++ + " alias =" + aliasKey);
            if (aliasKey.contains(assinar)) {
                Certificate c = ks.getCertificate(aliasKey);
                if (c.getType().equalsIgnoreCase("X.509")) {
                    X509Certificate Chosecert = (X509Certificate) c;
                    String issuedto = Chosecert.getSubjectDN().getName().toString();
                    System.out.println(" issued to " + issuedto);
                    if (Chosecert.getSubjectDN().getName().toString().contains("Carla")) {
                        return aliasKey;
                    }
                }
            }
        }
        return null;
    }

    static ArrayList<X509Certificate> getCerts(KeyStore ks) throws KeyStoreException {
        //final String autenticar = "Autenticação";
        final String assinar = "Assinatura";

        ArrayList<X509Certificate> certs = new ArrayList();

        Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String aliasKey = aliases.nextElement();

            if (aliasKey.contains(assinar) || aliasKey.contains("Signature")) {
                Certificate c = ks.getCertificate(aliasKey);
                if (c.getType().equalsIgnoreCase("X.509")) {
                    System.out.println(aliasKey);
                    certs.add((X509Certificate) c);
                }
            }
        }
        System.out.println("returning " + certs.size());
        return certs;
    }

}
