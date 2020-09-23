package com.reedelk.jwt.internal.exception;

import com.reedelk.runtime.api.exception.PlatformException;

public class TokenSignException extends PlatformException {

    public TokenSignException(String message, Throwable exception) {
        super(message, exception);
    }
}