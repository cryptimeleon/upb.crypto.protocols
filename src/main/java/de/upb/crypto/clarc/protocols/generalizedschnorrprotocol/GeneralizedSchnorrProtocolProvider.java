package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.expressions.comparison.GroupElementEqualityExpression;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.ProtocolProvider;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.clarc.protocols.protocolfactory.GeneralizedSchnorrProtocolFactory;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class GeneralizedSchnorrProtocolProvider implements ProtocolProvider {

    @Represented
    Zp zp;

    public GeneralizedSchnorrProtocolProvider(Zp zp) {
        this.zp = zp;
    }

    public GeneralizedSchnorrProtocolProvider(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public InteractiveThreeWayAoK getProtocolInstance(Problem[] instances, Witness[] witnesses) {
        if (Arrays.stream(instances).anyMatch(p -> !(p instanceof GeneralizedSchnorrProblem))) {
            throw new IllegalArgumentException("The given instances are not valid");
        }
        GroupElementEqualityExpression[] problem =
                Arrays.stream(instances).map(p -> ((GeneralizedSchnorrProblem) p).getProblemEquation())
                        .toArray(GroupElementEqualityExpression[]::new);
        GeneralizedSchnorrProtocolFactory factory =
                new GeneralizedSchnorrProtocolFactory(problem, zp);
        if (Arrays.stream(witnesses).anyMatch(w -> w instanceof EmptyWitness)) {
            return factory.createVerifierGeneralizedSchnorrProtocol();
        } else {
            if (witnesses[0] instanceof GeneralizedSchnorrWitness) { //TODO get rid of this. Factory doesn't need to be called anyway
                GeneralizedSchnorrWitness[] generalizedSchnorrWitnesses =
                        Arrays.stream(witnesses).map(w -> (GeneralizedSchnorrWitness) w)
                                .toArray(GeneralizedSchnorrWitness[]::new);
                Map<String, Zp.ZpElement> witnessMap = new HashMap<>();
                for (GeneralizedSchnorrWitness witness : generalizedSchnorrWitnesses) {
                    witnessMap.put(witness.getName(), witness.getWitnessValue());
                }
                return factory.createProverGeneralizedSchnorrProtocol(witnessMap);
            } else if (witnesses[0] instanceof GeneralizedSchnorrWitnessNew) {
                return factory.createProverGeneralizedSchnorrProtocol(((GeneralizedSchnorrWitnessNew) witnesses[0]).getMap());
            } else
                throw new IllegalArgumentException("Cannot handle witness type " + witnesses[0].getClass().getName());
        }
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GeneralizedSchnorrProtocolProvider that = (GeneralizedSchnorrProtocolProvider) o;
        return Objects.equals(zp, that.zp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zp);
    }
}
