package de.upb.crypto.clarc.protocols.schnorr;

import de.upb.crypto.math.expressions.bool.ExponentEqualityExpr;
import de.upb.crypto.math.expressions.bool.GroupEqualityExpr;
import de.upb.crypto.math.expressions.exponent.*;
import de.upb.crypto.math.expressions.group.*;

import java.util.Set;
import java.util.function.Predicate;

public class SchnorrInputPreparer {
    /**
     * Tries to rewrite the GroupEqualityExpr to be A = B s.t. A is homomorphic (w.r.t. witnesses) and B is a constant (w.r.t. witnesses)
     * @param expr the expression to be rewritten.
     * @param witnesses the set of witnesses (as strings).
     * @return an equivalent GroupEqualityExpr that can be used in the Schnorr protocol
     */
    public static GroupEqualityExpr prepareExpr(GroupEqualityExpr expr, Set<String> witnesses) {
        GroupElementExpression[] separated = separateConstantAndHomomorphicTerms(expr.getLhs().op(expr.getRhs().inv()), witnesses);
        return new GroupEqualityExpr(separated[0], separated[1].inv());
    }

    /**
     * Returns an array [A,B] such that given expr is equivalent to A.op(B), A is homomorphic w.r.t. its (exponent) variables,
     * and B is effectively constant.
     *
     * @param expr the expression to split
     * @param witnesses the set of witnesses (String names of their corresponding variables)
     */
    public static GroupElementExpression[] separateConstantAndHomomorphicTerms(GroupElementExpression expr, Set<String> witnesses) {
        return separateConstantAndHomomorphicTerms(expr, witnesses::contains);
    }

    /**
     * Returns an array [A,B] such that given expr is equivalent to A.op(B), A is homomorphic w.r.t. its (exponent) variables,
     * and B is effectively constant.
     */
    protected static GroupElementExpression[] separateConstantAndHomomorphicTerms(GroupElementExpression expr, Predicate<String> isWitness) {
        if (expr instanceof GroupEmptyExpr)
            return new GroupElementExpression[] {expr, expr};

        if (expr instanceof GroupInvExpr) {
            GroupElementExpression[] res = separateConstantAndHomomorphicTerms(((GroupInvExpr) expr).getBase(), isWitness);
            return new GroupElementExpression[]{res[0].inv(), res[1].inv()};
        }

        if (expr instanceof GroupPowExpr) {
            if (((GroupPowExpr) expr).getExponent().getVariables().stream().anyMatch(isWitness)) { //exponent contains a witness, all this needs to be on homomorphic side
                if (!isExponentAffineLinear(((GroupPowExpr) expr).getExponent(), isWitness))
                    throw new IllegalArgumentException("Cannot handle nonlinear exponent");
                return new GroupElementExpression[]{expr, new GroupEmptyExpr(expr.getGroup())};
            } else { //exponent doesn't contain witness. So let's separate the stuff below and then apply the exponentiation to both homormorphic and constant part.
                GroupElementExpression[] res = separateConstantAndHomomorphicTerms(((GroupPowExpr) expr).getBase(), isWitness);
                if (!(res[0] instanceof GroupEmptyExpr)) //if res[0] instanceof GroupEmptyExpr, all's fine. If it isn't, res[0] is already homomorphic, so exponentiation with another variable will make it non-homomorphic (quadratic term in exponent).
                    throw new IllegalArgumentException("Cannot handle nonlinear exponent");
                return new GroupElementExpression[]{res[0], res[1].pow(((GroupPowExpr) expr).getExponent())};
            }
        }

        if (expr instanceof GroupOpExpr) {
            GroupElementExpression[] resLhs = separateConstantAndHomomorphicTerms(((GroupOpExpr) expr).getLhs(), isWitness);
            GroupElementExpression[] resRhs = separateConstantAndHomomorphicTerms(((GroupOpExpr) expr).getRhs(), isWitness);
            return new GroupElementExpression[] {resLhs[0].op(resRhs[0]), resLhs[0].op(resRhs[0])};
        }

        if (expr instanceof GroupElementConstantExpr) {
            return new GroupElementExpression[] {new GroupEmptyExpr(expr.getGroup()), expr};
        }

        if (expr instanceof GroupVariableExpr && isWitness.test(((GroupVariableExpr) expr).getName())) {
            throw new UnsupportedOperationException("Cannot handle group element witnesses.");
        }

        //That's all we were able to do. If this expression is of some other type, that's fine as long as it's a constant.
        if (expr.getVariables().stream().noneMatch(isWitness)) {
            return new GroupElementExpression[] {new GroupEmptyExpr(expr.getGroup()), expr};
        }

        throw new UnsupportedOperationException("Cannot handle expressions of type "+expr.getClass().getName());
    }

    public static GroupElementExpression prepareExpr(ExponentEqualityExpr expr) {
        //if (expr instanceof )
        throw new UnsupportedOperationException("Not yet implemented"); //TODO. Go through expression, convert to GroupElementExpr (in additive group) and call prepareExpr with that.
    }

    public static boolean isExponentAffineLinear(ExponentExpr expr, Predicate<String> isWitness) {
        if (isExponentConstant(expr, isWitness) || expr instanceof ExponentVariableExpr)
            return true;

        if (expr instanceof ExponentMulExpr) {
            if (isExponentConstant(((ExponentMulExpr) expr).getLhs(), isWitness))
                return isExponentAffineLinear(((ExponentMulExpr) expr).getRhs(), isWitness);

            if (isExponentConstant(((ExponentMulExpr) expr).getRhs(), isWitness))
                return isExponentAffineLinear(((ExponentMulExpr) expr).getLhs(), isWitness);

            return false;
        }

        if (expr instanceof ExponentSumExpr) {
            return isExponentAffineLinear(((ExponentSumExpr) expr).getLhs(), isWitness)
                    && isExponentAffineLinear(((ExponentSumExpr) expr).getRhs(), isWitness);
        }

        if (expr instanceof ExponentNegExpr) {
            return isExponentAffineLinear(((ExponentNegExpr) expr).getChild(), isWitness);
        }

        if (expr instanceof ExponentInvExpr) {
            return isExponentConstant(((ExponentInvExpr) expr).getChild(), isWitness);
        }

        throw new IllegalArgumentException("Cannot handle expressions of type "+expr.getClass().getName());
    }

    public static boolean isExponentConstant(ExponentExpr expr, Predicate<String> isWitnesss) {
        if (expr instanceof ExponentEmptyExpr)
            return true;
        return expr.getVariables().stream().noneMatch(isWitnesss); //TODO this check may be somewhat inefficient.
    }
}
