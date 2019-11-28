package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.base.AlgebraicVariableContext;
import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.group.GroupElementExpression;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

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
    protected Function<String, Expression> substitutionMap;

    public SchnorrCommonInput(List<GroupElementExpression> additionalHomomorphicPart, List<GroupElementExpression> additionalConstantPart, Function<String, Expression> substitutionMap) {
        this.additionalHomomorphicPart = additionalHomomorphicPart;
        this.additionalConstantPart = additionalConstantPart;
        this.substitutionMap = substitutionMap;
    }

    public SchnorrCommonInput(Function<String, Expression> substitutionMap) {
        this.substitutionMap = substitutionMap;
    }

    public SchnorrCommonInput(AlgebraicVariableContext ctxt) {
        this.substitutionMap = ctxt::varContextGetExpr;
    }


    public List<GroupElementExpression> getAdditionalHomomorphicPart() {
        return Collections.unmodifiableList(additionalHomomorphicPart);
    }

    public List<GroupElementExpression> getAdditionalConstantPart() {
        return Collections.unmodifiableList(additionalConstantPart);
    }

    public Function<String, Expression> getSubstitutionFunction() {
        if (substitutionMap == null)
            return s -> null;
        return substitutionMap;
    }

    public boolean hasSubstitutions() {
        return substitutionMap != null;
    }
}
