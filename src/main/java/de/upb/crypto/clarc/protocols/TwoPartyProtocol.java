package de.upb.crypto.clarc.protocols;

import java.util.List;

/**
 * An interactive protocol between two parties.
 */
public interface TwoPartyProtocol {
    TwoPartyProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
