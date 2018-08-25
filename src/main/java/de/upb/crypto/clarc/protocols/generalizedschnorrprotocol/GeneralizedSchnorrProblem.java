package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.expressions.SuperGroupElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.SuperZnElementPolicyFacts;
import de.upb.crypto.clarc.protocols.expressions.arith.*;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.math.interfaces.structures.GroupElementMixedExpression;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Set;

/**
 * A generalized Schnorr Problem consists of an {@link GroupElementEqualityExpression}. The LHS of the Equation is a
 * fixed value (a constant or a variable with fixed value).
 * The Equation has the form A_j = prod_{i} (g_j,i ^ x_i)
 */
public class GeneralizedSchnorrProblem implements Problem {


    private GroupElementEqualityExpression problemEquation;

    public GeneralizedSchnorrProblem(GroupElementEqualityExpression problemEquation) {
        this.problemEquation = problemEquation;
        checkExpressionForm();
    }

    public GeneralizedSchnorrProblem(Representation representation) {
        this.problemEquation = (GroupElementEqualityExpression) representation.repr().recreateRepresentable();
        checkExpressionForm();
    }

    public GroupElementEqualityExpression getProblemEquation() {
        return problemEquation;
    }

    public void setProblemEquation(GroupElementEqualityExpression problemEquation) {
        this.problemEquation = problemEquation;
        checkExpressionForm();
    }

    /**
     * Get the value for A, if
     * 1. A is the LHS of the equation and a {@link NumberGroupElementLiteral} or
     * 2. A is the LHS of the equation and a {@link GroupElementVariable} with a fixed value
     *
     * @return the value of A
     * @throws IllegalStateException if A has an invalid form
     */
    public GroupElementMixedExpression getValueOfA() {
        return this.problemEquation.getLHS().resultAsEfficientExpression(new SuperGroupElementPolicyFacts(), new SuperZnElementPolicyFacts());
    }

    /**
     * Returns the right hand side of the Problem's equation. It is of the form
     * \prod g_i^x_i, where x_i are ZnVariables
     *
     * @return
     */
    public ProductGroupElementExpression getRHS() {
        return (ProductGroupElementExpression) getProblemEquation().getRHS();
    }

    /**
     * Returns the variables within the RHS expression.
     *
     * @param result
     */
    public void getVariables(Set<Variable> result) {
        //LHS dos not contain variables by definition.
        getRHS().getVariables(result);
    }

    /**
     * Internally ensures that the object is a valid problem for Schnorr, i.e.
     * the left hand side of the equation is a constant A
     * and the right hand side is of the form \prod_{i} a_i ^ w_i, where A is fixed, a_i can be computed, and w_i is the witness
     * <p>
     * Throws an exception if the form doesn't match.
     */
    protected void checkExpressionForm() {
        GeneralizedSchnorrProblem genSchnorrProblem = this;
        if (!genSchnorrProblem.getProblemEquation().getLHS().isDetermined())
            throw new IllegalArgumentException("lhs must be a constant/computable without variables");
        if (!(genSchnorrProblem.getProblemEquation().getRHS() instanceof ProductExpression)) {
            throw new IllegalArgumentException("rhs must be a ProductExpression");
        }
        for (ArithExpression expr : ((ProductGroupElementExpression) genSchnorrProblem.getProblemEquation().getRHS())
                .getElements()) {
            if (!(expr instanceof PowerGroupElementExpression)) {
                throw new IllegalArgumentException("rhs factors must be PowerGroupElementExpressions");
            }
            if (!(((PowerGroupElementExpression) expr).getRHS() instanceof ZnVariable))
                throw new IllegalArgumentException("exponents on the right hand side must be variables");
            if (!((PowerGroupElementExpression) expr).getLHS().isDetermined())
                throw new IllegalArgumentException("factors must be fully determined (not depend on variables)");
        }
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return new RepresentableRepresentation(this.problemEquation);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GeneralizedSchnorrProblem that = (GeneralizedSchnorrProblem) o;

        return getProblemEquation() != null ? getProblemEquation().equals(that.getProblemEquation()) : that
                .getProblemEquation() == null;
    }

    @Override
    public int hashCode() {
        return getProblemEquation() != null ? getProblemEquation().hashCode() : 0;
    }

    @Override
    public String toString() {
        return this.problemEquation.getLHS().toString() + " = " + this.problemEquation.getRHS().toString();
    }
}
