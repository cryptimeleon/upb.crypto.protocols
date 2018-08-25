package de.upb.crypto.clarc.protocols.parameters;

import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * The problem is the description of the problem, the knowledge of the solution is proven by the correct execution of
 * the
 * protocol.
 * The problem may have a special required form. In general, the problem is represented by an equation, where some
 * values are unknown. Computing theses values is as hard as solving a theoretical problem, that is believed to be
 * computational hard.
 */
public interface Problem extends StandaloneRepresentable {
}
