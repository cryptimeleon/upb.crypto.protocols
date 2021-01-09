package de.upb.crypto.clarc.protocols;


public interface CommonInput {
    CommonInput EMPTY = new EmptyCommonInput();
    class EmptyCommonInput implements CommonInput {

    }
}
