package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.RepresentationRestorer;

import java.lang.reflect.Type;
import java.util.Objects;

/**
 * A variable in the Schnorr protocol.
 * Each SchnorrStatement is a homomorphism over these variables.
 * This is only the (static) variable. SchnorrVariableValue represents a concrete value.
 */
public abstract class SchnorrVariable implements RepresentationRestorer {
    protected final String name;
    protected final SchnorrStatement privateToStatement; //null if public variable.

    public SchnorrVariable(String name, SchnorrStatement privateToStatement) {
        if (name == null || name.isEmpty())
            throw new IllegalArgumentException("Name must not be empty");
        this.name = name;
        this.privateToStatement = privateToStatement;
    }

    public SchnorrVariable(String name) {
        this(name, null);
    }

    public abstract SchnorrVariableValue getRandomValue();
    public abstract SchnorrVariableValue recreateValue(Representation repr);
    public abstract SchnorrVariableValue instantiateFromInput(SchnorrInput input);

    public String getName() {
        return name;
    }

    public SchnorrStatement getStatement() {
        return privateToStatement;
    }

    public String getScopeString() {
        return isInternalVariable() ? getStatement().getName() : "";
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
}
