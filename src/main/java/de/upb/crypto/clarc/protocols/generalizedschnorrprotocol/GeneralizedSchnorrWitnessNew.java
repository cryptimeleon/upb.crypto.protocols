package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.expressions.ZnElementPolicyFacts;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A witness for a generalized schnorr protocol, consisting of Zp values x_1,...,x_n
 */
public class GeneralizedSchnorrWitnessNew extends ZnElementPolicyFacts implements Witness {
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "zp", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    Map<String, Zp.ZpElement> witnesses;
    @Represented
    Zp zp = null;

    public GeneralizedSchnorrWitnessNew(Map<String, Zp.ZpElement> witnesses) {
        this.witnesses = new HashMap<>();
        this.witnesses.putAll(witnesses);
        if (!witnesses.isEmpty())
            this.zp = witnesses.values().stream().findAny().get().getStructure();
    }

    public GeneralizedSchnorrWitnessNew(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public Zp.ZpElement getWitnessValue(String variableName) {
        return witnesses.get(variableName);
    }

    public int getNumberOfWitnesses() {
        return witnesses.size();
    }

    protected Map<String, Zp.ZpElement> getMap() {
        return witnesses;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GeneralizedSchnorrWitnessNew that = (GeneralizedSchnorrWitnessNew) o;
        return Objects.equals(witnesses, that.witnesses);
    }

    @Override
    public int hashCode() {
        return Objects.hash(witnesses);
    }

    @Override
    public String getName() {
        return "TODO remove getName() from Witness interface";
    }

    @Override
    public Map<String, Zn.ZnElement> getFacts() {
        return Collections.unmodifiableMap(witnesses);
    }
}
