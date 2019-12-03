package de.upb.crypto.clarc.protocols.fiatshamir;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GenSchnorrTestdataProvider;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.clarc.protocols.arguments.sigma.Announcement;
import de.upb.crypto.clarc.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FiatShamirHeuristicTest {
    private BigInteger small_prime;
    private int lamda = 260;
    private int n = 3;
    private int m = 2;
    private Zp zp;
    private Group[] groups;

    private SigmaProtocol protocolForProver;
    private SigmaProtocol protocolForVerifier;
    private SigmaProtocol secondProtocolProver;

    private FiatShamirHeuristic fiatShamirForProver;
    private FiatShamirHeuristic fiatShamirForVerifier;
    private FiatShamirHeuristic fiatShamirForSecondProver;

    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        groups = provider.generateGenSchnorrGroups();
        zp = provider.generateGenSchnorrZPGroup(groups[0]);
        protocolForProver = provider.getGenSchorrProtocol(m, n, groups);
        // Since the generation of getGenSchnorrProtocol is not fixed, this will generate a new protocol
        secondProtocolProver = provider.getGenSchorrProtocol(m, n, groups);
        protocolForVerifier = new GeneralizedSchnorrProtocol(protocolForProver.getProblems(),
                null, (GeneralizedSchnorrPublicParameter) protocolForProver.getPublicParameters());
        fiatShamirForProver = new FiatShamirHeuristic(protocolForProver, new SHA256HashFunction());
        fiatShamirForVerifier = new FiatShamirHeuristic(protocolForVerifier, new SHA256HashFunction());
        fiatShamirForSecondProver = new FiatShamirHeuristic(secondProtocolProver, new SHA256HashFunction());
    }

    @Test
    public void testFiatShamirNonInteractiveProofOfKnowledge() {
        Proof fiatShamirProofFromProver = fiatShamirForProver.prove();
        assertTrue(fiatShamirForVerifier.verify(fiatShamirProofFromProver));
    }

    @Test
    public void testFiatShamirProofRepresentation() {
        Proof fiatShamirProofFromProver = fiatShamirForProver.prove();
        Proof recreatedProof = new FiatShamirProof(fiatShamirProofFromProver.getRepresentation());
        assertEquals(recreatedProof, fiatShamirProofFromProver);
    }

    /**
     * A test taking a FSA proof, adding a string to the auxData to obtain a different value and then asserting, that
     * this is not a valid proof using the verifier
     */
    @Test
    public void testNegativeFiatShamirNonInteractiveProofOfKnowledge() {

        if (this.fiatShamirForSecondProver.getProtocol().equals(this.fiatShamirForProver.getProtocol())) {
            throw new IllegalArgumentException("The two protocols are equal");
        }
        FiatShamirProof proofFirstProver = fiatShamirForProver.prove();
        FiatShamirProof proofSecondProver =
                fiatShamirForSecondProver.prove(new ByteArrayImplementation("Test".getBytes()));


        InteractiveThreeWayAoK protocol = fiatShamirForProver.getProtocol();
        Announcement[] announcementsFirstProver =
                Arrays.stream(proofFirstProver.getAnnouncementRepresentations())
                        .map(protocol::recreateAnnouncement)
                        .toArray(Announcement[]::new);
        Response[] responsesFirstProver = Arrays.stream(proofFirstProver.getResponseRepresentations())
                .map(protocol::recreateResponse)
                .toArray(Response[]::new);

        InteractiveThreeWayAoK protocol2ndProver = fiatShamirForSecondProver.getProtocol();
        Announcement[] announcementsSecondProver =
                Arrays.stream(proofSecondProver.getAnnouncementRepresentations())
                        .map(protocol2ndProver::recreateAnnouncement)
                        .toArray(Announcement[]::new);
        Response[] responsesSecondProver = Arrays.stream(proofSecondProver.getResponseRepresentations())
                .map(protocol2ndProver::recreateResponse)
                .toArray(Response[]::new);

        // Wrong announcement from different protocol
        FiatShamirProof wrongProof =
                new FiatShamirProof(announcementsSecondProver, proofFirstProver.getAuxData(), responsesFirstProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));

        // Wrong challenge by additional hashes
        wrongProof =
                new FiatShamirProof(announcementsFirstProver, proofSecondProver.getAuxData(), responsesFirstProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));

        // Wrong response from different protocol
        wrongProof =
                new FiatShamirProof(announcementsFirstProver, proofFirstProver.getAuxData(), responsesSecondProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));

        // Wrong announcement and aux data from different protocol
        wrongProof =
                new FiatShamirProof(announcementsSecondProver, proofSecondProver.getAuxData(), responsesFirstProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));

        // Wrong aux data and response from different protocol
        wrongProof =
                new FiatShamirProof(announcementsFirstProver, proofSecondProver.getAuxData(), responsesSecondProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));

        // Wrong announcement and response from different protocol
        wrongProof =
                new FiatShamirProof(announcementsSecondProver, proofFirstProver.getAuxData(), responsesSecondProver);
        assertFalse(fiatShamirForVerifier.verify(wrongProof));
    }
}