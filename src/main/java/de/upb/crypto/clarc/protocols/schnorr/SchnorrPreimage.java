package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariableValue;
import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.Substitution;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.*;
import java.util.stream.Collectors;

public class SchnorrPreimage implements Response, Substitution {
    @UniqueByteRepresented
    private final HashMap<SchnorrVariable, SchnorrVariableValue> variableValues = new HashMap<>();

    public SchnorrPreimage(Map<SchnorrVariable, SchnorrVariableValue> variableValues) {
        this.variableValues.putAll(variableValues);
    }

    public SchnorrPreimage(Collection<SchnorrVariable> variables, Representation repr) {
        int i=0;
        for (SchnorrVariable variable : variables.stream().sorted().collect(Collectors.toList()))
            variableValues.put(variable, variable.recreateValue(repr.list().get(i++)));
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
        ListRepresentation repr = new ListRepresentation(); //format: the SchnorrVariableValues lexicographically ordered by their SchnorrVariables
        variableValues.keySet().stream()
                .sorted()
                .map(variable -> variableValues.get(variable).getRepresentation())
                .forEachOrdered(repr::add);

        return repr;
    }

    @Override
    public Expression getSubstitution(VariableExpression variable) {
        for (SchnorrVariable knownVar : variableValues.keySet()) //TODO get rid of iteration by introducing new set of varExprs?
            if (knownVar.getVariableExpr().equals(variable))
                return variableValues.get(knownVar).asExpression();

        return null;
    }
}
