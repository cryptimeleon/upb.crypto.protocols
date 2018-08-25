package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.util.Map;

public abstract class GroupElementPolicyFacts implements PolicyFact {

    public abstract Map<String, GroupElement> getFacts();


}
