package de.upb.crypto.clarc.protocols.arguments.sigma;

import de.upb.crypto.clarc.protocols.CommonInput;
import de.upb.crypto.clarc.protocols.SecretInput;
import de.upb.crypto.clarc.protocols.arguments.InteractiveArgumentInstance;

public abstract class SigmaProtocolInstance implements InteractiveArgumentInstance {
    protected SigmaProtocol protocol;
    protected CommonInput commonInput;
    protected SecretInput secretInput;
    protected AnnouncementSecret announcementSecret;
    protected Announcement announcement;
    protected Challenge challenge;
    protected Response response;

    protected SigmaProtocolInstance(SigmaProtocol protocol, CommonInput commonInput, SecretInput secretInput) {
        this.protocol = protocol;
        this.commonInput = commonInput;
        this.secretInput = secretInput;
    }

    protected SigmaProtocolInstance(SigmaProtocol protocol, CommonInput commonInput) {
        this.protocol = protocol;
        this.commonInput = commonInput;
    }


    @Override
    public SigmaProtocol getProtocol() {
        return protocol;
    }
}
