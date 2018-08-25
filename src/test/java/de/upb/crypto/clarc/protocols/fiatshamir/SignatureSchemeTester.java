package de.upb.crypto.clarc.protocols.fiatshamir;

import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.serialization.Representation;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureSchemeTester {

    /**
     * Test checking that given a {@link SignatureScheme}, its {@link SigningKey} and {@link VerificationKey}, a
     * given {@link PlainText} can be signed, and that the resulting signature can be successfully verified.
     *
     * @param signatureScheme {@link SignatureScheme} to be checked
     * @param plainText       {@link PlainText} to be signed
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     * @return Successfully created and verified {@link Signature} for a given {@link PlainText}
     */
    public static Signature testSignatureSchemeSignAndVerify(SignatureScheme signatureScheme, PlainText plainText,
                                                             VerificationKey verificationKey, SigningKey signingKey) {

        Signature signature = signatureScheme.sign(plainText, signingKey);
        assertTrue(signatureScheme.verify(plainText, signature, verificationKey));
        return signature;
    }

    /**
     * Test checking the representations of a {@link Signature}, a {@link SigningKey} and a {@link VerificationKey}
     * equal their original instances and that given a {@link SignatureScheme} still verifies the recreated instances
     * successfully.
     *
     * @param signatureScheme {@link SignatureScheme}
     * @param plainText       {@link PlainText} to be signed
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     */
    public static void testRepresentationSignatureSchemeSignAndVerify(SignatureScheme signatureScheme,
                                                                      PlainText plainText,
                                                                      VerificationKey verificationKey,
                                                                      SigningKey signingKey) {
        Signature signature = signatureScheme.sign(plainText, signingKey);

        Representation signatureRepresentation = signature.getRepresentation();
        Representation signingKeyRepresentation = signingKey.getRepresentation();
        Representation verificationKeyRepresentation = verificationKey.getRepresentation();

        Signature signatureFromRepr = signatureScheme.getSignature(signatureRepresentation);
        SigningKey signingKeyFromRepr = signatureScheme.getSigningKey(signingKeyRepresentation);
        VerificationKey verificationKeyFromRepr = signatureScheme.getVerificationKey(verificationKeyRepresentation);

        assertEquals(signature, signatureFromRepr);
        assertEquals(signingKey, signingKeyFromRepr);
        assertEquals(verificationKey, verificationKeyFromRepr);

        Representation plainTextRepresentation = plainText.getRepresentation();
        PlainText plainTextFromRepr = signatureScheme.getPlainText(plainTextRepresentation);
        assertTrue(signatureScheme.verify(plainTextFromRepr, signatureFromRepr, verificationKey));
        assertEquals(plainText, plainTextFromRepr);

        assertEquals(signatureScheme.verify(plainText, signature, verificationKey),
                signatureScheme.verify(plainText, signatureFromRepr, verificationKeyFromRepr));
    }

    /**
     * Test signing one {@link PlainText} and using this {@link Signature} to check that
     * {@link SignatureScheme#verify} returns false for a different {@link PlainText}
     *
     * @param signatureScheme {@link SignatureScheme} to be checked
     * @param plainText       {@link PlainText} to be signed
     * @param wrongPlainText  different {@link PlainText} which will be verified with the other {@link PlainText}'s
     *                        {@link Signature}
     * @param verificationKey {@link VerificationKey} of for the tested {@link SignatureScheme} and {@link SigningKey}
     * @param signingKey      {@link SigningKey} of for the tested {@link SignatureScheme} and {@link VerificationKey}
     */
    public static void testNegativeWrongMessageSignatureSchemeSignAndVerify(SignatureScheme signatureScheme,
                                                                            PlainText plainText,
                                                                            PlainText wrongPlainText,
                                                                            VerificationKey verificationKey,
                                                                            SigningKey signingKey) {
        Signature signature = signatureScheme.sign(plainText, signingKey);

        assertFalse(signatureScheme.verify(wrongPlainText, signature, verificationKey));
    }

    /**
     * Test using two different {@link de.upb.crypto.craco.interfaces.signature.SignatureKeyPair}. The {@link PlainText} is
     * signed with each {@link SigningKey}, thus creating to {@link Signature}s.
     * Then it is checked that {@link SignatureScheme#verify} returns false for invalid combinations of
     * {@link Signature}s and {@link VerificationKey}s
     *
     * @param signatureScheme      {@link SignatureScheme} to be checked
     * @param plainText            {@link PlainText} to be signed
     * @param verificationKey      {@link VerificationKey} of for the tested {@link SignatureScheme} and
     *                             {@link SigningKey}
     * @param signingKey           {@link SigningKey} of for the tested {@link SignatureScheme} and
     *                             {@link VerificationKey}
     * @param wrongVerificationKey different {@link VerificationKey} of for the tested {@link SignatureScheme} and
     *                             {@link SigningKey}
     * @param wrongSigningKey      different {@link SigningKey} of for the tested {@link SignatureScheme} and
     *                             {@link VerificationKey}
     */
    public static void testNegativeWrongKeysSignatureSchemeSignAndVerify(SignatureScheme signatureScheme,
                                                                         PlainText plainText,
                                                                         VerificationKey verificationKey,
                                                                         SigningKey signingKey,
                                                                         VerificationKey wrongVerificationKey,
                                                                         SigningKey wrongSigningKey) {
        Signature signature = signatureScheme.sign(plainText, signingKey);
        Signature wrongSignature = signatureScheme.sign(plainText, wrongSigningKey);

        assertFalse(signatureScheme.verify(plainText, signature, wrongVerificationKey));
        assertFalse(signatureScheme.verify(plainText, wrongSignature, verificationKey));
    }
}
