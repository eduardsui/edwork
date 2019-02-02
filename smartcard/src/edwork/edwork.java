package edwork;

import javacard.framework.*;
import javacard.security.ECPublicKey;
import javacard.security.*;

public class edwork extends Applet {
    private byte[] hello;
    private byte[] password                                = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private static final byte INS_HELLO                    = (byte)0x01;
    private static final byte INS_ECC_GEN_KEYPAIR          = (byte)0x41;
    private static final byte INS_ECC_GENW                 = (byte)0x45;
    private static final byte INS_ECC_SIGN                 = (byte)0x48;
    private static final byte INS_ECC_VERIFY               = (byte)0x49;
    
    private KeyPair eccKey;
    private Signature ecdsa;
    short wrong_pin = 0;
    
    private byte[] flags;

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
        flags = JCSystem.makeTransientByteArray((short)0, JCSystem.CLEAR_ON_DESELECT);
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (wrong_pin > 10)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (buf[ISO7816.OFFSET_CLA] == (byte)0x10) {
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
        } else
        if (buf[ISO7816.OFFSET_CLA] == (byte)0x00) {
            switch (buf[ISO7816.OFFSET_INS]) {
                case (byte)0x2A:
                    if (!flags[0])
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    if ((buf[ISO7816.OFFSET_P1] == (byte)0x9E) && (buf[ISO7816.OFFSET_P2] == (byte)0x9A))
                        Ecc_Sign(apdu, len);
                    else
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    break;
                case (byte)0x20:
                    if ((buf[ISO7816.OFFSET_P1] == (byte)0x00) && ((buf[ISO7816.OFFSET_P2] == (byte)0x81) || (buf[ISO7816.OFFSET_P2] == (byte)0x82))) {
                        if (len >= 6) {
                            if ((password.length != len) || (Utils.arrayCompare(buf, ISO7816.OFFSET_CDATA, password, (byte)0, password.length) != 0)) {
                                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                                wrong_pin ++;
                            } else {
                                flags[0] = 1;
                                if (wrong_pin > 0)
                                    wrong_pin = 0;
                            }
                        } else {
                            ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
                            wrong_pin ++;
                        }
                    } else
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    break;
                case (byte)0x24:
                    if ((buf[ISO7816.OFFSET_P1] == (byte)0x00) && (buf[ISO7816.OFFSET_P2] == (byte)0x81)) {
                        if ((len >= password.length + 6) && (buf[ISO7816.OFFSET_LC] + password.length == len)) {
                            if ((password.length != len) || (Utils.arrayCompare(buf, ISO7816.OFFSET_CDATA, password, (byte)0, password.length) != 0)) {
                                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                                wrong_pin ++;
                            } else {
                                byte new_len = buf[ISO7816.OFFSET_LC] - password.length;
                                byte offset = ISO7816.OFFSET_CDATA + password.length;
                                flags[0] = 0;
                                if (wrong_pin > 0)
                                    wrong_pin = 0;
                                password = new byte[new_len];
                                Util.arrayCopy(buf, offset, password, (short)0, (byte)new_len);
                            }
                        } else
                            ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
                    } else
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    protected static boolean isContactless() {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A);
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
