package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.*;

import java.util.HashMap;
import java.util.Map;

/**
 * A policy fact containing facts for a single group
 */
public class SimpleGroupElementPolicyFacts extends GroupElementPolicyFacts {


    private final Map<String, GroupElement> facts;
    private final MapRepresentation factsRepr;
    private final Group group;

    /**
     * Construcotr when having a list of policy facts for one group
     *
     * @param elements map containing the mapping form fact name to a value
     */
    public SimpleGroupElementPolicyFacts(Map<String, GroupElement> elements) {
        facts = elements;
        factsRepr = new MapRepresentation();

        group = elements.entrySet().iterator().next().getValue().getStructure();

        for (GroupElement g : elements.values()) {
            if (!g.getStructure().equals(group)) {
                throw new IllegalArgumentException("The elements in a GroupElementPolicyFact must be elements from " +
                        "the same group");
            }
        }
        elements.forEach((key, value) -> factsRepr.put(new StringRepresentation(key), value.getRepresentation()));


    }

    public SimpleGroupElementPolicyFacts(Representation representation) {
        group = (Group) representation.obj().get("group").repr().recreateRepresentable();
        factsRepr = new MapRepresentation();
        representation.obj().get("factsRepr").map().getMap().forEach((key1, value1) -> factsRepr.put(key1.str(),
                group.getElement(value1).getRepresentation()));
        facts = new HashMap<>();
        representation.obj().get("factsRepr").map().getMap().forEach((key, value) -> facts.put(key.str().get(), group
                .getElement(value)));
    }

    /**
     * Updates or adds element as value for the key name.
     *
     * @param name    the name of the element
     * @param element the new value for the element
     * @return the added value;
     */
    public GroupElement addElement(String name, GroupElement element) {
        factsRepr.put(new StringRepresentation(name), element.getRepresentation());
        return facts.put(name, element);

    }

    public Map<String, GroupElement> getFacts() {
        return new HashMap<>(facts);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("factsRepr", factsRepr);
        repr.put("group", new RepresentableRepresentation(group));
        return repr;
    }

    public void addElements(Map<String, GroupElement> facts) {
        this.facts.putAll(facts);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SimpleGroupElementPolicyFacts that = (SimpleGroupElementPolicyFacts) o;

        if (getFacts() != null ? !getFacts().equals(that.getFacts()) : that.getFacts() != null) return false;
        if (factsRepr != null ? !factsRepr.equals(that.factsRepr) : that.factsRepr != null) return false;
        return group != null ? group.equals(that.group) : that.group == null;
    }

    @Override
    public int hashCode() {
        int result = getFacts() != null ? getFacts().hashCode() : 0;
        result = 31 * result + (factsRepr != null ? factsRepr.hashCode() : 0);
        result = 31 * result + (group != null ? group.hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }
}
