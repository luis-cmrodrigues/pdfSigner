/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.pdfsigner;

import java.util.List;
import java.util.Scanner;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Luis Rodrigues
 */
public class CardConnect {

    public static void initCard() throws CardException {
        TerminalFactory tf = TerminalFactory.getDefault();
        List< CardTerminal> terminals = tf.terminals().list();
        System.out.println("Available Readers:");
        System.out.println(terminals + "\n");

        CardTerminal cardTerminal = terminals.get(0);

        Card card = cardTerminal.connect("*");

        System.out.println("card: " + card);
        System.out.println("card protocol: " + card.getProtocol());

        CardChannel channel = card.getBasicChannel();

        // Send Select Applet command
        byte[] aid = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01};
        ResponseAPDU answer = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
        System.out.println("answer: " + answer.toString());

        // Send test command
        answer = channel.transmit(new CommandAPDU(0x00, 0x00, 0x00, 0x00));
        System.out.println("answer: " + answer.toString());
        byte r[] = answer.getData();
        for (int i = 0; i < r.length; i++) {
            System.out.print((char) r[i]);
        }
        System.out.println();

        //ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, 0x84, 0x00, 0x00, 0x08));
        //String hex = DatatypeConverter.printHexBinary(r.getBytes());
        //System.out.println("Response: " + hex);
        // disconnect card:
        card.disconnect(false);
    }

}
