package de.upb.crypto.clarc.protocols.generalizedschnorrprotocol;

import de.upb.crypto.clarc.protocols.arguments.sigma.SigmaProtocolTranscript;
import de.upb.crypto.math.interfaces.structures.Group;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class GeneralizedSchnorrSimulatorTest {

    private GeneralizedSchnorrProtocol schnorr;


    @BeforeAll
    public void setUp() {
        GenSchnorrTestdataProvider provider = new GenSchnorrTestdataProvider();
        Group[] groups = provider.generateGenSchnorrGroups();
        int m = 1;
        int n = 1;
        schnorr = provider.getGenSchorrProtocol(m, n, groups);

    }

    @Test
    public void testGenSchnorrTranscript() {
        GeneralizedSchnorrChallenge challenge = (GeneralizedSchnorrChallenge) schnorr.chooseChallenge();
        if (schnorr.verify(schnorr.generateAnnouncements(), challenge, schnorr.generateResponses(challenge))) {
            GeneralizedSchnorrSimulator simulator = new GeneralizedSchnorrSimulator(schnorr);
            SigmaProtocolTranscript transcript = simulator.simulate(challenge);
            assertTrue(schnorr.verify(transcript.getAnnouncements(), transcript.getChallenge(), transcript
                    .getResponses()));
        }
    }
}
