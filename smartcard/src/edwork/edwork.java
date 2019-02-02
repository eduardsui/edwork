package edwork;

import javacard.framework.*;
import javacard.security.ECPublicKey;
import javacard.security.*;

public class edwork extends Applet {
    private byte[] hello;
    private static final byte INS_HELLO                    = (byte)0x01;
    private static final byte INS_ECC_GEN_KEYPAIR          = (byte)0x41;
    private static final byte INS_ECC_GENW                 = (byte)0x45;
    private static final byte INS_ECC_SIGN                 = (byte)0x48;
    private static final byte INS_ECC_VERIFY               = (byte)0x49;
    
    private KeyPair eccKey;
    private Signature ecdsa;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        edwork ed = new edwork();
        if (bLength > 0) {
            ed.hello = new byte[bLength];
            Util.arrayCopy(bArray, bOffset, ed.hello, (short)0, (byte)bLength);
        }
        ed.register();
    }
    
    public edwork() {
        eccKey = SecP256r1.newKeyPair();
        eccKey.genKeyPair();
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != (byte)0x10)
             ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        short len = apdu.setIncomingAndReceive();
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_HELLO:
                if ((hello != null) && (hello.length > 0)) {
                    Util.arrayCopy(hello, (byte)0, buf, ISO7816.OFFSET_CDATA, (byte)hello.length);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)hello.length);
                }
                break;
            // DEBUG ONLY!
            // case INS_ECC_GEN_KEYPAIR:
            //     GenEccKeyPair(apdu, len);
            //     break;
            case INS_ECC_SIGN:
                Ecc_Sign(apdu, len);
                break;
            case INS_ECC_VERIFY:
                Ecc_Verify(apdu, len);
                break;
            case INS_ECC_GENW:
                {
                    ECPublicKey pubKey = (ECPublicKey) eccKey.getPublic();
                    short sendlen = pubKey.getW(apdu.getBuffer(), (short)0);
                    apdu.setOutgoingAndSend((short)0, sendlen);                 
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    private void GenEccKeyPair(APDU apdu, short len){
        byte[] buffer = apdu.getBuffer();
        short keyLen = (short)0;
        switch (buffer[ISO7816.OFFSET_P1]) {
            case (byte)0x01:
                //Constructs a KeyPair instance for the specified algorithm and keylength;
                eccKey = SecP256r1.newKeyPair();
                keyLen = (short)32;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
        eccKey.genKeyPair();
        
        ECPublicKey pubKey = (ECPublicKey) eccKey.getPublic();
        
        short sendlen = pubKey.getW(apdu.getBuffer(), (short)0);
        apdu.setOutgoingAndSend((short)0, sendlen); 
    }    

    private void Ecc_Sign(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        ecdsa.init(eccKey.getPrivate(), Signature.MODE_SIGN);
        short lenTmp = ecdsa.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, lenTmp);
    }
    
    private void Ecc_Verify(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();  
        short signLen = buffer[ISO7816.OFFSET_P1];
        short plainLen = (short)(len - signLen);
        short tmpOff = (short)(ISO7816.OFFSET_CDATA + signLen);
        ecdsa.init(eccKey.getPublic(), Signature.MODE_VERIFY);
        boolean ret = ecdsa.verify(buffer, (short)tmpOff, plainLen, buffer, ISO7816.OFFSET_CDATA, signLen);
        buffer[(short)0] = ret ? (byte)1 : (byte)0;
        apdu.setOutgoingAndSend((short)0, (short)1);
    }
}
