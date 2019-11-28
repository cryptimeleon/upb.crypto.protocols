package de.upb.crypto.clarc.protocols.base;

import de.upb.crypto.math.expressions.Expression;
import de.upb.crypto.math.expressions.exponent.ExponentConstantExpr;
import de.upb.crypto.math.expressions.exponent.ExponentExpression;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zn;

import java.lang.reflect.Field;
import java.math.BigInteger;

public interface AlgebraicVariableContext {
    /**
     * Returns an Expression that evaluates to a concrete value corresponding to the name variable.
     */
    default GroupElementExpression varContextGetGroupElemExpr(String name) {
        Field field = getFieldByName(this, name);
        if (field == null || (!GroupElementExpression.class.isAssignableFrom(field.getType()) && !GroupElement.class.isAssignableFrom(field.getType()) ) )
            throw new IllegalArgumentException("Variable "+name+" is not an accessible group element field of this class (should be typed GroupElementExpression or GroupElement)");

        try {
            Object val = field.get(this);
            if (val instanceof GroupElementExpression)
                return (GroupElementExpression) val;
            else
                return ((GroupElement) val).expr();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return null;
        }
    }

    default GroupElement varContextGetGroupElem(String name) {
        return varContextGetGroupElemExpr(name).evaluate();
    }

    default ExponentExpression varContextGetExponentExpr(String name) {
        Field field = getFieldByName(this, name);
        if (field == null || (!ExponentExpression.class.isAssignableFrom(field.getType())
                && !BigInteger.class.isAssignableFrom(field.getType())
                && !Zn.ZnElement.class.isAssignableFrom(field.getType())) )
            throw new IllegalArgumentException("Variable "+name+" is not an accessible exponent field of this class (should be typed ExponentExpression, BigInteger, or ZnElement)");

        try {
            Object val = field.get(this);
            if (val instanceof ExponentExpression)
                return (ExponentExpression) val;
            else if (val instanceof BigInteger)
                return new ExponentConstantExpr((BigInteger) val);
            else
                return new ExponentConstantExpr((Zn.ZnElement) val);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return null;
        }
    }

    default Expression varContextGetExpr(String name) {
        Field field = getFieldByName(this, name);
        if (field == null || (
                !Expression.class.isAssignableFrom(field.getType())
                && !GroupElement.class.isAssignableFrom(field.getType())
                && !BigInteger.class.isAssignableFrom(field.getType())
                && !Zn.ZnElement.class.isAssignableFrom(field.getType())
                ) )
            throw new IllegalArgumentException("Variable "+name+" is not an accessible expression field of this class (should be typed Expression (GroupElementExpression or ExponentExpression) or GroupElement)");

        try {
            Object val = field.get(this);
            if (val instanceof Expression)
                return (Expression) val;
            else if (val instanceof GroupElement)
                return ((GroupElement) val).expr();
            else if (val instanceof BigInteger)
                return new ExponentConstantExpr((BigInteger) val);
            else if (val instanceof Zn.ZnElement)
                return new ExponentConstantExpr((Zn.ZnElement) val);
            else
                throw new IllegalArgumentException("Cannot handle type "+field.getType().getName()); //this should never happen
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            return null;
        }
    }

    default BigInteger varContextGetExponent(String name) {
        return varContextGetExponentExpr(name).evaluate();
    }

    static Field getFieldByName(AlgebraicVariableContext ctx, String name) { //TODO starting with Java 9, mark this private.
        Class<?> clazz = ctx.getClass();
        while (!clazz.equals(Object.class)) {
            try {
                Field field = clazz.getField(name); //TODO change to getDeclaredFields if we don't get access to the private field from here.
                //TODO filter by annotation @PartOfAlgebraicVariableContext? Or keep it like it is: any class member is fair game to be used as a variable.
                return field;
            } catch (SecurityException | IllegalArgumentException e) {
                throw new RuntimeException(e);
            } catch (NoSuchFieldException e) {
                //That's expected. Just use the superclass then
            } finally {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }
}
