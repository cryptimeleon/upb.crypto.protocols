package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.math.expressions.bool.BooleanExpression;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

import java.math.BigInteger;

/**
 * Output of one Schnorr homomorphism (there's one image per SchnorrStatement)
 */
public interface SchnorrImage extends UniqueByteRepresentable, Representable {
    SchnorrImage op(SchnorrImage operand);
    SchnorrImage pow(BigInteger exponent);
    BooleanExpression isEqualTo(SchnorrImage image);
}
