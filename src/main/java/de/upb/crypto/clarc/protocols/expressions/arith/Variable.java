package de.upb.crypto.clarc.protocols.expressions.arith;

public interface Variable extends ArithExpression {

    /**
     * @return the name of the variable
     */
    String getName();
}
