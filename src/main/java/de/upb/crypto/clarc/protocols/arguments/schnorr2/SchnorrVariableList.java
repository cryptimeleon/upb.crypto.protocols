package de.upb.crypto.clarc.protocols.arguments.schnorr2;

import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

import java.util.LinkedHashMap;
import java.util.List;

/**
 * Holds an ordered list of SchnorrVariableValues.
 */
public class SchnorrVariableList implements SchnorrVariableAssignment, AnnouncementSecret, Response, SecretInput {
    private final LinkedHashMap<SchnorrVariable, SchnorrVariableValue> variableValues;

    public SchnorrVariableList(List<? extends SchnorrVariableValue> variableValues) {
        this.variableValues = new LinkedHashMap<>();
        for (SchnorrVariableValue val : variableValues)
            this.variableValues.put(val.getVariable(), val);
    }

    public SchnorrVariableList(List<? extends SchnorrVariable> variables, Representation repr) {
        int i=0;
        variableValues = new LinkedHashMap<>();
        for (SchnorrVariable variable : variables) {
            SchnorrVariableValue val = variable.recreateValue(repr.list().get(i++));
            variableValues.put(val.getVariable(), val);
        }
    }

    @Override
    public SchnorrVariableValue getValue(SchnorrVariable variable) {
        return variableValues.get(variable);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        variableValues.forEach((k,v) -> accumulator.append(v));
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation repr = new ListRepresentation();
        variableValues.values().stream()
                .map(Representable::getRepresentation)
                .forEachOrdered(repr::add);

        return repr;
    }
}
