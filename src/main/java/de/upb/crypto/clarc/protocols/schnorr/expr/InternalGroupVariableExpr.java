package de.upb.crypto.clarc.protocols.schnorr.expr;

import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.math.expressions.group.GroupVariableExpr;

/**
 * In the Schnorr context, GroupVariableExpr are user-given.
 * Statements shall use InternalGroupVariableExpr for Schnorr witnesses/variables that are private to that statement.
 */
public class InternalGroupVariableExpr extends GroupVariableExpr {
    protected String statement;
    protected SchnorrVariable var;
    public InternalGroupVariableExpr(SchnorrVariable var, String statement) {
        super(var.getName());
        this.statement = statement;
        this.var = var;
    }

    public String getStatement() {
        return statement;
    }

    public SchnorrVariable getVariable() {
        return var;
    }

}
