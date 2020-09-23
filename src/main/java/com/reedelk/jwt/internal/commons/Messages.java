package com.reedelk.jwt.internal.commons;

import com.reedelk.runtime.api.commons.FormattedMessage;

public class Messages {

    private Messages() {
    }

    public enum SignToken implements FormattedMessage {

        ERROR_SIGN("An error occurred while signing the JTW token, cause=[%s].");

        private final String message;

        SignToken(String message) {
            this.message = message;
        }

        @Override
        public String template() {
            return message;
        }
    }
}
