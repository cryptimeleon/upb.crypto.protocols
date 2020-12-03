package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

import java.math.BigInteger;

public interface SchnorrVariableValue extends Representable, UniqueByteRepresentable {
    /**
     * Returns a VariableValue that is factor*this + summand
     */
    SchnorrVariableValue evalLinear(BigInteger factor, SchnorrVariableValue summand);

    SchnorrVariable getVariable();

    default VariableExpression getName() {
        return getVariable().getVariableExpr();
    }

    default SchnorrStatement getStatement() {
        return getVariable().getStatement();
    }

    Expression asExpression();
}
