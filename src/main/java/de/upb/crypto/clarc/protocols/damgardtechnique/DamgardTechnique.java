package de.upb.crypto.clarc.protocols.damgardtechnique;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgument;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgumentInstance;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Challenge;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocol;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.CommitmentSchemePublicParameters;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * This class provides Damgard's Technique. Damgard's Technique is a construction to improve Sigma-Protocols in order to
 * provide security against concurrent adversaries. The resulting protocol is a 'Concurrent black-box zero knowledge
 * three-way interactive argument of knowledge'.
 * Damgard's Technique is applied on a given Sigma-Protocol. A given commitment scheme is used to achieve the security
 * improvement by changing the original given Sigma-Protocol in the following way:
 * <p>
 * 1.) Instead of sending the announcement the protocol sends the commitment of the announcement.
 * 2.) The last message additionally contains the original announcement and the verify-value of the commitment of the
 * announcement. These information are then used in the verify to check validity of the commitment as well as the
 * original verification from the Sigma-Protocol.
 * <p>
 * The result of Damgard's Technique is a 'Concurrent black-box zero knowledge three-way interactive argument of
 * knowledge'.
 */
public class DamgardTechnique implements InteractiveArgument {

    protected SigmaProtocol protocol;
    protected CommitmentScheme commitmentScheme;

    /**
     * Constructor for a Sigma Protocol using Damgard's Technique
     *
     * @param protocol         {@link SigmaProtocol} used in Damgard`s Technique
     * @param commitmentScheme {@link CommitmentScheme} for a single message used in Damgard's Technique; Prover and
     *                         Verifier need to use the
     *                         same {@link CommitmentScheme} and {@link CommitmentSchemePublicParameters}
     */
    public DamgardTechnique(SigmaProtocol protocol, CommitmentScheme commitmentScheme) {
        super();
        this.protocol = protocol;
        this.commitmentScheme = commitmentScheme;
    }

    @Override
    public DamgardInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        return new DamgardInstance(role, this, commonInput, secretInput);
    }

    public SigmaProtocol getInnerProtocol() {
        return protocol;
    }

    @Override
    public String getFirstMessageRole() {
        return null;
    }
}
