package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.clarc.protocols.schnorr.expr.InternalSchnorrExponentVariableExpr;
import de.upb.crypto.clarc.protocols.schnorr.expr.InternalSchnorrGroupVariableExpr;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrGroupElemVariable;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariableValue;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrZnVariable;
import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.Substitutions;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.expressions.group.GroupVariableExpr;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.*;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class SchnorrPreimage implements Response, Substitutions {
    @UniqueByteRepresented
    private HashMap<SchnorrVariable, SchnorrVariableValue> variableValues = new HashMap<>();

    public SchnorrPreimage(Map<SchnorrVariable, SchnorrVariableValue> variableValues) {
        this.variableValues.putAll(variableValues);
    }

    public SchnorrPreimage(Collection<SchnorrVariable> variables, Representation repr) {
        for (SchnorrVariable var : variables)
            variableValues.put(var, var.recreateValue(repr.obj().get(var.getName())));
    }

    public SchnorrVariableValue getValue(SchnorrVariable variable) {
        return variableValues.get(variable);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation(); //format: scope -> (variableName -> representationOfValue)
        for (Map.Entry<SchnorrVariable, SchnorrVariableValue> entry : variableValues.entrySet()) {
            String scope = entry.getKey().getScopeString();
            ObjectRepresentation reprOfScope = repr.obj().putIfMissing(scope, ObjectRepresentation::new).obj();
            reprOfScope.put(entry.getKey().getName(), entry.getValue().getRepresentation());
        }
        return repr;
    }

    @Override
    public Expression getSubstitution(VariableExpression variable) {
        if (variable instanceof InternalSchnorrExponentVariableExpr)
            return variableValues.get(((InternalSchnorrExponentVariableExpr) variable).getVariable()).asExpression();
        if (variable instanceof InternalSchnorrGroupVariableExpr)
            return variableValues.get(((InternalSchnorrGroupVariableExpr) variable).getVariable()).asExpression();

        if (variable instanceof ExponentVariableExpr) {
            for (SchnorrVariable knownVar : variableValues.keySet())
                if (knownVar instanceof SchnorrZnVariable && !knownVar.isInternalVariable() && knownVar.getName().equals(variable.getName()))
                    return variableValues.get(knownVar).asExpression();
        }

        if (variable instanceof GroupVariableExpr) {
            for (SchnorrVariable knownVar : variableValues.keySet())
                if (knownVar instanceof SchnorrGroupElemVariable && !knownVar.isInternalVariable() && knownVar.getName().equals(variable.getName()))
                    return variableValues.get(knownVar).asExpression();
        }

        return null;
    }
}
