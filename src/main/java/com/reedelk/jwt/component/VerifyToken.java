package com.reedelk.jwt.component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.reedelk.runtime.api.annotation.*;
import com.reedelk.runtime.api.component.ProcessorSync;
import com.reedelk.runtime.api.exception.PlatformException;
import com.reedelk.runtime.api.flow.FlowContext;
import com.reedelk.runtime.api.message.Message;
import com.reedelk.runtime.api.message.MessageAttributes;
import com.reedelk.runtime.api.message.MessageBuilder;
import com.reedelk.runtime.api.script.ScriptEngineService;
import com.reedelk.runtime.api.script.dynamicvalue.DynamicString;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import static com.reedelk.runtime.api.commons.ComponentPrecondition.Configuration.requireNotBlank;
import static com.reedelk.runtime.api.commons.ComponentPrecondition.Configuration.requireNotNull;
import static org.osgi.service.component.annotations.ServiceScope.PROTOTYPE;

@ModuleComponent("Verify Token")
@ComponentOutput(
        attributes = MessageAttributes.class,
        payload = boolean.class,
        description = "False if the algorithm stated in the token's header it's not equal to the one defined in the JWT configuration " +
                "or the signature is invalid or the token has expired " +
                "or a the claim contained a different value than the expected one " +
                "otherwise true.")
@ComponentInput(
        payload = Object.class,
        description = "The component input is used to evaluate the dynamic " +
                "value provided for the JWT token property.")
@Description("The Verify Token component verifies that the input token is correctly signed. The component returns " +
        "false if the algorithm stated in the token's header it's not equal to the one defined in the JWT configuration " +
        "or the signature is invalid or the token has expired " +
        "or a the claim contained a different value than the expected one " +
        "otherwise true.")
@Component(service = VerifyToken.class, scope = PROTOTYPE)
public class VerifyToken implements ProcessorSync {

    @Property("JWT Configuration")
    @Description("The configuration for the JWT token.")
    private JWTConfiguration configuration;

    @Property("JTW Token")
    @InitValue("#[message.payload()]")
    @Description("The JWT token to be verified.")
    private DynamicString token;

    @Reference
    ScriptEngineService scriptEngine;

    private JWTVerifier verifier;

    @Override
    public void initialize() {
        requireNotBlank(SignToken.class, configuration.getIssuer(), "The name of the JWT issuer.");
        requireNotNull(SignToken.class, configuration.getAlgorithm(), "The algorithm to be used to sign and verify the token");
        Algorithm algorithm = configuration.getAlgorithm().create(configuration);
        verifier = JWT.require(algorithm)
                .withIssuer(configuration.getIssuer())
                .build();
    }

    @Override
    public Message apply(FlowContext flowContext, Message message) {
        String evaluatedToken = scriptEngine.evaluate(token, flowContext, message)
                .orElseThrow(() -> new PlatformException("Token expression could not be evaluated."));
        boolean isValid;
        try {
            verifier.verify(evaluatedToken);
            isValid = true;
        } catch (Exception exception) {
            isValid = false;
        }
        return MessageBuilder.get(VerifyToken.class)
                .withJavaObject(isValid)
                .build();
    }

    public void setConfiguration(JWTConfiguration configuration) {
        this.configuration = configuration;
    }

    public void setToken(DynamicString token) {
        this.token = token;
    }
}
