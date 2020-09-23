package com.reedelk.jwt.component;

import com.reedelk.runtime.api.annotation.*;
import com.reedelk.runtime.api.component.Implementor;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ServiceScope;

@Shared
@Component(service = JWTConfiguration.class, scope = ServiceScope.PROTOTYPE)
public class JWTConfiguration implements Implementor {

    @Property("JWT Issuer")
    @Hint("Issuer name")
    @Mandatory
    @Description("The name of the issuer of the JWT token.")
    private String issuer;

    @Property("JWT Algorithm")
    @DefaultValue("HMAC256")
    @InitValue("HMAC256")
    @Mandatory
    @Description("The algorithm to be used to sign and verify the JWT token.")
    private JWTAlgorithm algorithm;

    @Property("Secret")
    @Hint("my-secret-key")
    @Password
    @Description("The secret key to be used to sign and verify the JWT token.")
    @When(propertyName = "algorithm", propertyValue = "HMAC256")
    @When(propertyName = "algorithm", propertyValue = "HMAC384")
    @When(propertyName = "algorithm", propertyValue = "HMAC512")
    private String secret;

    public JWTAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(JWTAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
