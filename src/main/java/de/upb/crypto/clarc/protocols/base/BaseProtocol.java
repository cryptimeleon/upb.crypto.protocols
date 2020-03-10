package de.upb.crypto.clarc.protocols.base;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.TwoPartyProtocol;
import de.upb.crypto.clarc.protocols.TwoPartyProtocolInstance;

public abstract class BaseProtocol implements TwoPartyProtocol {
    protected String firstMessageRole;
    protected String otherRole;

    public BaseProtocol(String firstMessageRole, String otherRole) {
        this.firstMessageRole = firstMessageRole;
        this.otherRole = otherRole;
    }

    @Override
    public String getFirstMessageRole() {
        return firstMessageRole;
    }

    @Override
    public String[] getRoleNames() {
        return new String[] {firstMessageRole, otherRole};
    }
}
