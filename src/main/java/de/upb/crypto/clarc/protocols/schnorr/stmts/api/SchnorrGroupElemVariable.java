package de.upb.crypto.clarc.protocols.schnorr.stmts.api;

import de.upb.crypto.clarc.protocols.schnorr.SchnorrInput;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.group.GroupVariableExpr;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.Representation;

public class SchnorrGroupElemVariable extends SchnorrVariable {
    protected Group group;

    public SchnorrGroupElemVariable(VariableExpression name, Group group, SchnorrStatement privateToStatement) {
        super(name, privateToStatement);
        this.group = group;
    }

    public SchnorrGroupElemVariable(VariableExpression name, Group group) {
        this(name, group, null);
    }

    @Override
    public SchnorrVariableValue getRandomValue() {
        return new SchnorrGroupElemVariableValue(group.getUniformlyRandomElement(), this);
    }

    @Override
    public GroupVariableExpr getVariableExpr() {
        return (GroupVariableExpr) super.getVariableExpr();
    }

    @Override
    public SchnorrVariableValue recreateValue(Representation repr) {
        return new SchnorrGroupElemVariableValue(group.getElement(repr), this);
    }

    @Override
    public SchnorrVariableValue instantiateFromInput(SchnorrInput input) {
        return new SchnorrGroupElemVariableValue(input.getGroupElement(getVariableExpr()), this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SchnorrGroupElemVariable that = (SchnorrGroupElemVariable) o;
        return group.equals(that.group);
    }
}
