package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.Substitution;
import de.upb.crypto.math.expressions.VariableExpression;

public interface SchnorrVariableAssignment extends Substitution {
    SchnorrVariableValue getValue(SchnorrVariable variable);

    default Expression getSubstitution(VariableExpression variable) {
        if (!(variable instanceof SchnorrVariable))
            return null;

        SchnorrVariableValue val = getValue((SchnorrVariable) variable);
        if (val == null)
            return null;
        return val.asExpression();
    }
}
