package de.upb.crypto.clarc.protocols;

public interface SecretInput {
    SecretInput EMPTY = new EmptySecretInput();

    class EmptySecretInput implements SecretInput {
    }
}
