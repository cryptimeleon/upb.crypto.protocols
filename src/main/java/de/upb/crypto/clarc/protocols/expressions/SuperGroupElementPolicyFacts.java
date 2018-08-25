package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SuperGroupElementPolicyFacts extends GroupElementPolicyFacts {

    @RepresentedList(elementRestorer = @Represented)
    private
    List<SimpleGroupElementPolicyFacts> facts;

    /**
     * Initializes an empty list of facts
     */
    public SuperGroupElementPolicyFacts() {
        this.facts = new ArrayList<>();
    }

    public SuperGroupElementPolicyFacts(List<SimpleGroupElementPolicyFacts> facts) {
        this.facts = facts;
    }

    public SuperGroupElementPolicyFacts(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }


    @Override
    public Map<String, GroupElement> getFacts() {
        Map<String, GroupElement> factList = new HashMap<>();
        facts.forEach(f -> factList.putAll(f.getFacts()));
        return factList;
    }

    public boolean addElement(SimpleGroupElementPolicyFacts fact) {
        return this.facts.add(fact);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SuperGroupElementPolicyFacts that = (SuperGroupElementPolicyFacts) o;

        return getFacts() != null ? getFacts().equals(that.getFacts()) : that.getFacts() == null;
    }

    @Override
    public int hashCode() {
        int result = getFacts() != null ? getFacts().hashCode() : 0;
        return 31 * result + this.getClass().getCanonicalName().hashCode();
    }
}
