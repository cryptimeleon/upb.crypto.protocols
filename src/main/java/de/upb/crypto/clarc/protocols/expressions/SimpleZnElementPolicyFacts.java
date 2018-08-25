package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.HashMap;
import java.util.Map;

public class SimpleZnElementPolicyFacts extends ZnElementPolicyFacts {

    private final Map<String, Zn.ZnElement> facts;
    private final MapRepresentation factsRepr;
    private final Zn zn;

    public SimpleZnElementPolicyFacts(Map<String, ? extends Zn.ZnElement> elements) {
        facts = new HashMap<>();
        facts.putAll(elements);
        factsRepr = new MapRepresentation();

        if (elements.isEmpty())
            throw new IllegalArgumentException("Given facts are empty");
        zn = elements.entrySet().iterator().next().getValue().getStructure();

        for (Zn.ZnElement e : elements.values()) {
            if (!e.getStructure().equals(zn)) {
                throw new IllegalArgumentException("The elements in a ZnElementPolicyFact must be elements from the  " +
                        "same Zn-Ring");
            }
        }
        elements.forEach((key, value) -> factsRepr.put(new StringRepresentation(key), value.getRepresentation()));


    }

    public SimpleZnElementPolicyFacts(Representation representation) {
        zn = (Zn) representation.obj().get("zn").repr().recreateRepresentable();
        factsRepr = new MapRepresentation();
        representation.obj().get("factsRepr").map().getMap().forEach((key1, value1) -> factsRepr.put(key1.str(), zn
                .getElement(value1).getRepresentation()));
        facts = new HashMap<>();
        representation.obj().get("factsRepr").map().getMap().forEach((key, value) -> facts.put(key.str().get(), zn
                .getElement(value)));
    }

    /**
     * Updates or adds element as value for the key name.
     *
     * @param name    name of the element
     * @param element the value for the key
     * @return the added value;
     */
    public Zn.ZnElement addElement(String name, Zn.ZnElement element) {
        factsRepr.put(new StringRepresentation(name), element.getRepresentation());
        return facts.put(name, element);

    }

    public Map<String, Zn.ZnElement> getFacts() {
        return new HashMap<>(facts);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("factsRepr", factsRepr);
        repr.put("zn", new RepresentableRepresentation(zn));
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SimpleZnElementPolicyFacts that = (SimpleZnElementPolicyFacts) o;

        if (getFacts() != null ? !getFacts().equals(that.getFacts()) : that.getFacts() != null) return false;
        if (factsRepr != null ? !factsRepr.equals(that.factsRepr) : that.factsRepr != null) return false;
        return zn != null ? zn.equals(that.zn) : that.zn == null;
    }

    @Override
    public int hashCode() {
        int result = getFacts() != null ? getFacts().hashCode() : 0;
        result = 31 * result + (factsRepr != null ? factsRepr.hashCode() : 0);
        result = 31 * result + (zn != null ? zn.hashCode() : 0);
        result = 31 * result + this.getClass().getCanonicalName().hashCode();
        return result;
    }
}
