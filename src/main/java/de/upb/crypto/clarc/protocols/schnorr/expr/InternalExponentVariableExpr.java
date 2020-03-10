package de.upb.crypto.clarc.protocols.schnorr.expr;

import de.upb.crypto.clarc.protocols.schnorr.stmts.api.SchnorrVariable;
import de.upb.crypto.math.expressions.exponent.ExponentVariableExpr;

/**
 * In the Schnorr context, ExponentVariableExpr are user-given.
 * Statements shall use InternalExponentVariableExpr for Schnorr witnesses/variables that are private to that statement.
 */
public class InternalExponentVariableExpr extends ExponentVariableExpr {
    protected String statement;
    protected SchnorrVariable var;

    public InternalExponentVariableExpr(SchnorrVariable var, String statement) {
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
