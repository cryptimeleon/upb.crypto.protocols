package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.Objects;

public class SchnorrZnVariable extends SchnorrVariable {
    public final Zn zn;

    public SchnorrZnVariable(String name, Zn zn, SchnorrStatement privateToStatement) {
        super(name, privateToStatement);
        this.zn = zn;
    }

    public SchnorrZnVariable(String name, Zn zn) {
        this(name, zn, null);
    }

    @Override
    public SchnorrZnVariableValue getRandomValue() {
        return new SchnorrZnVariableValue(zn.getUniformlyRandomElement(), this);
    }

    @Override
    public SchnorrZnVariableValue recreateValue(Representation repr) {
        return new SchnorrZnVariableValue(zn.getElement(repr), this);
    }

    @Override
    public SchnorrZnVariableValue instantiateFromInput(SchnorrInput input) {
        return new SchnorrZnVariableValue(zn.valueOf(input.getInteger(name)), this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SchnorrZnVariable that = (SchnorrZnVariable) o;
        return zn.equals(that.zn);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), zn);
    }
}
