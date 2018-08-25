package de.upb.crypto.clarc.protocols.arguments;

import de.upb.crypto.clarc.protocols.simulator.ZeroKnowledgeSimulator;

public interface ZeroKnowledgeArgument extends InteractiveArgument {
    @Override
    default ZeroKnowledgeSimulator getSimulator() {
        return new ZeroKnowledgeSimulator(this);
    }
}
