package de.upb.crypto.clarc.protocols.schnorr.expr;

import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrStatement;
import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.math.expressions.group.GroupVariableExpr;

/**
 * In the Schnorr context, GroupVariableExpr are user-given.
 * Statements shall use InternalGroupVariableExpr for Schnorr witnesses/variables that are private to that statement.
 */
public class InternalGroupVariableExpr extends GroupVariableExpr { //TODO get rid of those and just make SchnorrVariable a VariableExpression?!
    protected SchnorrVariable var;
    public InternalGroupVariableExpr(SchnorrVariable var) {
        super(var.getName());
        this.var = var;
    }

    public SchnorrVariable getVariable() {
        return var;
    }

}
