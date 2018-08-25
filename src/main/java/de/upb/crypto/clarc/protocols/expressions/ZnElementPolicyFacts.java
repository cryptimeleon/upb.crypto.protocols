package de.upb.crypto.clarc.protocols.expressions;

import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.structures.zn.Zn;

import java.util.Map;

public abstract class ZnElementPolicyFacts implements PolicyFact {

    public abstract Map<String, Zn.ZnElement> getFacts();
}
