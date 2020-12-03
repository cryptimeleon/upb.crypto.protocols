package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.RepresentationRestorer;

import java.lang.reflect.Type;
import java.util.Objects;

/**
 * A variable in the Schnorr protocol.
 * Each SchnorrStatement is a homomorphism over these variables.
 * This is only the (static) variable. SchnorrVariableValue represents a concrete value.
 */
public abstract class SchnorrVariable implements RepresentationRestorer, Comparable<SchnorrVariable>, UniqueByteRepresentable {
    protected final VariableExpression name;
    protected final SchnorrStatement privateToStatement; //null if public variable.

    public SchnorrVariable(VariableExpression name, SchnorrStatement privateToStatement) {
        this.name = name;
        this.privateToStatement = privateToStatement;
    }

    public SchnorrVariable(VariableExpression name) {
        this(name, null);
    }

    public abstract SchnorrVariableValue getRandomValue();
    public abstract SchnorrVariableValue recreateValue(Representation repr);
    public abstract SchnorrVariableValue instantiateFromInput(SchnorrInput input);

    public VariableExpression getVariableExpr() {
        return name;
    }

    public SchnorrStatement getStatement() {
        return privateToStatement;
    }

    public boolean isInternalVariable() {
        return privateToStatement != null;
    }

    @Override
    public Object recreateFromRepresentation(Type type, Representation repr) {
        if (!(type instanceof Class))
            throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());

        if (Announcement.class.isAssignableFrom((Class) type))
            return recreateValue(repr);

        throw new IllegalArgumentException("Cannot recreate "+type.getTypeName());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SchnorrVariable that = (SchnorrVariable) o;
        return name.equals(that.name) &&
                Objects.equals(privateToStatement, that.privateToStatement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, privateToStatement);
    }

    @Override
    public int compareTo(SchnorrVariable other) {
        ByteArrayAccumulator thisAcc = new ByteArrayAccumulator();
        this.updateAccumulator(thisAcc);
        ByteArrayAccumulator otherAcc = new ByteArrayAccumulator();
        other.updateAccumulator(otherAcc);

        return thisAcc.compareTo(otherAcc);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator acc) {
        acc.escapeAndSeparate(acc.getClass().getName());
        acc.escapeAndSeparate(privateToStatement.getName());
        acc.append(name);

        return acc;
    }
}
