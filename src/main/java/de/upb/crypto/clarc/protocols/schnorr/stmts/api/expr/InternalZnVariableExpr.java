package de.upb.crypto.clarc.protocols.schnorr.stmts.api.expr;

import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Objects;

public class InternalZnVariableExpr implements ExponentVariableExpr {
    @Represented
    protected String name;
    @Represented
    protected String statement;

    public InternalZnVariableExpr(String statement, String name) {
        this.name = name;
        this.statement = statement;
    }

    public InternalZnVariableExpr(Representation repr) {
        ReprUtil.deserialize(this, repr);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(statement);
        accumulator.append(name);

        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public String getName() {
        return name;
    }

    public String getStatement() {
        return statement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InternalZnVariableExpr that = (InternalZnVariableExpr) o;
        return name.equals(that.name) &&
                statement.equals(that.statement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, statement);
    }

}
