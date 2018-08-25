package de.upb.crypto.clarc.protocols.fiatshamir;

import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.ProtocolProvider;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSigningKey;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirVerificationKey;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocolProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;


import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FiatShamirSignatureTest {

    private int n = 3;
    private int m = 2;
    private Zp zp;
    private Group[] groups;

    private GeneralizedSchnorrProtocol protocolForProver;
    private GeneralizedSchnorrProtocol protocolForVerifier;

    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 260;

    private FiatShamirSignatureScheme fsScheme;
    private FiatShamirVerificationKey verificationKey;
    private FiatShamirSigningKey signingKey;
    private FiatShamirVerificationKey falseVerificationKey;
    private FiatShamirSigningKey falseSigningKey;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;


    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        groups = provider.generateGenSchnorrGroups();
        zp = provider.generateGenSchnorrZPGroup(groups[0]);
        protocolForProver = provider.getGenSchorrProtocol(m, n, groups);
        ProtocolProvider instanteProvider = new GeneralizedSchnorrProtocolProvider(zp);
        fsScheme = new FiatShamirSignatureScheme(instanteProvider, new SHA256HashFunction());
        SignatureKeyPair keyPair = generateKeyPair(protocolForProver);
        signingKey = (FiatShamirSigningKey) keyPair.getSigningKey();
        verificationKey = (FiatShamirVerificationKey) keyPair.getVerificationKey();
        GeneralizedSchnorrProtocol falseProtocolForProver;
        do {
            falseProtocolForProver = provider.getGenSchorrProtocol(m, n, groups);
        } while (protocolForProver.equals(falseProtocolForProver));
        SignatureKeyPair falseKeyPair = generateKeyPair(falseProtocolForProver);
        falseSigningKey = (FiatShamirSigningKey) falseKeyPair.getSigningKey();
        falseVerificationKey = (FiatShamirVerificationKey) falseKeyPair.getVerificationKey();
        System.out.println("Generate message block and sign it... ");
        RingElementPlainText[] messages = new RingElementPlainText[NUM_MESSAGES];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
        }
        messageBlock = new MessageBlock(messages);
        System.out.println("Message Block: " + messageBlock);
        RingElementPlainText[] wrongMessages = new RingElementPlainText[NUM_MESSAGES];
        for (int i = 0; i < wrongMessages.length; i++) {
            do {
                wrongMessages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
            } while (wrongMessages[i].equals(messages[i]));
        }
        wrongMessageBlock = new MessageBlock(wrongMessages);
    }

    @Test
    public void testFSSignatureSchemeSignAndVerify() {

        // signing a block of messages

        FiatShamirSignature signature = fsScheme.sign(messageBlock, signingKey);
        System.out.println("Signature: " + signature);

        // representation test of the signature signature
        System.out.println("Testing representation of class PSSignature... ");
        FiatShamirSignature sigmaTest = new FiatShamirSignature(signature.getRepresentation());

        assertEquals(signature, sigmaTest);

        // verify test with valid signature
        System.out.println("Testing Verify with a valid signature... ");
        Boolean verify = fsScheme.verify(messageBlock, signature, verificationKey);

        assertTrue(verify);
    }


    @Test
    public void testNegativeFSSignatureSchemeSignAndVerify() {

        SignatureSchemeTester.testSignatureSchemeSignAndVerify(fsScheme, messageBlock,
                verificationKey, signingKey);
        // signing a block of messages
        System.out.println("Generate message block and sign it... ");
        RingElementPlainText[] messages = new RingElementPlainText[NUM_MESSAGES];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
        }
        MessageBlock msg = new MessageBlock(messages);
        System.out.println("Message Block: " + msg);
        FiatShamirSignature signature = fsScheme.sign(msg, signingKey);
        System.out.println("Signature: " + signature);

        // representation test of the signature signature
        System.out.println("Testing representation of class PSSignature... ");
        FiatShamirSignature sigmaTest = new FiatShamirSignature(signature.getRepresentation());

        assertEquals(signature, sigmaTest);

        // verify test with valid signature
        System.out.println("Testing Verify with a valid signature... ");
        Boolean verify = fsScheme.verify(msg, signature, falseVerificationKey);

        assertFalse(verify);
    }

    @Test
    public void testPSExtendedSignatureSchemeRepresentationText() {

        SignatureSchemeTester.testRepresentationSignatureSchemeSignAndVerify(fsScheme, messageBlock,
                verificationKey, signingKey);
        System.out.println("Testing representation of classes PSPublicParameters, PSSignatureScheme, " +
                "PSVerificationKey, PSSigningKey... ");

        // signature scheme representation test using the extended pk
        FiatShamirSignatureScheme psSchemeTest = new FiatShamirSignatureScheme(fsScheme.getRepresentation());
        assertEquals(fsScheme, psSchemeTest);  //Using extended pk

        // public key representation test

        FiatShamirVerificationKey pkTest = new FiatShamirVerificationKey(verificationKey.getRepresentation());
        assertEquals(verificationKey, pkTest);

        // secret key representation test
        SigningKey skTest;
        skTest = new FiatShamirSigningKey(signingKey.getRepresentation());

        assertEquals(signingKey, skTest);
    }


    private SignatureKeyPair<FiatShamirVerificationKey, FiatShamirSigningKey> generateKeyPair(
            GeneralizedSchnorrProtocol protocolForProver) {

        GeneralizedSchnorrProtocol protocolForVerifier = new GeneralizedSchnorrProtocol(protocolForProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolForProver
                .getPublicParameters());
        FiatShamirSigningKey signingKey =
                new FiatShamirSigningKey(protocolForProver.getProblems(), protocolForProver.getWitnesses());
        FiatShamirVerificationKey verificationKey = new FiatShamirVerificationKey(protocolForVerifier.getProblems());
        return new SignatureKeyPair<>(verificationKey, signingKey);
    }

    @Test
    public void testNegativeWrongMessageFSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(fsScheme,
                messageBlock, wrongMessageBlock, verificationKey, signingKey);
    }

    @Test
    public void testNegativeWrongKeyfSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(fsScheme, messageBlock,
                verificationKey, signingKey, falseVerificationKey, falseSigningKey);
    }

    @Test
    public void mapToPlainTextTest() {
        PlainText mtpPlainText = fsScheme.mapToPlaintext(messageBlock.getUniqueByteRepresentation(), signingKey);
        PlainText mtpWrongPlainText =
                fsScheme.mapToPlaintext(wrongMessageBlock.getUniqueByteRepresentation(), signingKey);

        Signature signature = fsScheme.sign(mtpPlainText, signingKey);
        assertTrue(fsScheme.verify(mtpPlainText, signature, verificationKey));

        signature = fsScheme.sign(mtpWrongPlainText, signingKey);
        assertFalse(fsScheme.verify(mtpPlainText, signature, verificationKey));
    }
}
