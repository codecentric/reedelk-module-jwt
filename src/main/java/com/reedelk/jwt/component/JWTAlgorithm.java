package com.reedelk.jwt.component;

import com.auth0.jwt.algorithms.Algorithm;

public enum JWTAlgorithm {

    HMAC256 {
        @Override
        Algorithm create(JWTConfiguration configuration) {
            String secret = configuration.getSecret();
            return Algorithm.HMAC256(secret);
        }
    },

    HMAC384 {
        @Override
        Algorithm create(JWTConfiguration configuration) {
            String secret = configuration.getSecret();
            return Algorithm.HMAC384(secret);
        }
    },

    HMAC512 {
        @Override
        Algorithm create(JWTConfiguration configuration) {
            String secret = configuration.getSecret();
            return Algorithm.HMAC512(secret);
        }
    };

    abstract Algorithm create(JWTConfiguration configuration);

}
