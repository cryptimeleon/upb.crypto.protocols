package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SuperZnElementPolicyFacts extends ZnElementPolicyFacts {

    @RepresentedList(elementRestorer = @Represented)
    private
    List<SimpleZnElementPolicyFacts> facts;

    /**
     * Instantiates an empty fact list
     */
    public SuperZnElementPolicyFacts() {
        this.facts = new ArrayList<>();
    }

    public SuperZnElementPolicyFacts(List<SimpleZnElementPolicyFacts> facts) {
        this.facts = facts;
    }

    public SuperZnElementPolicyFacts(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }


    @Override
    public Map<String, Zn.ZnElement> getFacts() {
        Map<String, Zn.ZnElement> factList = new HashMap<>();
        facts.forEach(f -> factList.putAll(f.getFacts()));
        return factList;
    }

    public boolean addElement(SimpleZnElementPolicyFacts fact) {
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

        SuperZnElementPolicyFacts that = (SuperZnElementPolicyFacts) o;

        return getFacts() != null ? getFacts().equals(that.getFacts()) : that.getFacts() == null;
    }

    @Override
    public int hashCode() {
        int result = getFacts() != null ? getFacts().hashCode() : 0;
        return 31 * result + this.getClass().getCanonicalName().hashCode();
    }
}
