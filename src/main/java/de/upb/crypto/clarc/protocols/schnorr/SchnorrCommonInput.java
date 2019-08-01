package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.group.GroupElementExpression;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SchnorrCommonInput implements CommonInput {
    /**
     * Schnorr proves knowledge of x s.t. Ψ(x) = y for a public y.
     * The homomorphicPart is x (as an expression that we interpret as a homomorphism through expr.evaluate(substitutionMap))
     */
    protected List<GroupElementExpression> additionalHomomorphicPart;

    /**
     * Schnorr proves knowledge of x s.t. Ψ(x) = y for a public y.
     * The constantPart is y.
     */
    protected List<GroupElementExpression> additionalConstantPart;

    /**
     * Substitutions that will be applied to expressions stored within SchnorrProtocol (excluding additionalStatements as seen above).
     */
    protected Map<String, Expression> substitutionMap;

    public List<GroupElementExpression> getAdditionalHomomorphicPart() {
        return Collections.unmodifiableList(additionalHomomorphicPart);
    }

    public List<GroupElementExpression> getAdditionalConstantPart() {
        return Collections.unmodifiableList(additionalConstantPart);
    }

    public Map<String, Expression> getSubstitutionMap() {
        return Collections.unmodifiableMap(substitutionMap);
    }
}
