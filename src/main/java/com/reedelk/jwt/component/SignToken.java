package com.reedelk.jwt.component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.reedelk.jwt.internal.commons.Messages;
import com.reedelk.jwt.internal.exception.TokenSignException;
import com.reedelk.runtime.api.annotation.*;
import com.reedelk.runtime.api.component.ProcessorSync;
import com.reedelk.runtime.api.flow.FlowContext;
import com.reedelk.runtime.api.message.Message;
import com.reedelk.runtime.api.message.MessageAttributes;
import com.reedelk.runtime.api.message.MessageBuilder;
import com.reedelk.runtime.api.message.content.MimeType;
import com.reedelk.runtime.api.script.ScriptEngineService;
import com.reedelk.runtime.api.script.dynamicmap.DynamicObjectMap;
import com.reedelk.runtime.api.script.dynamicvalue.DynamicLong;
import com.reedelk.runtime.api.script.dynamicvalue.DynamicString;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;

import static com.reedelk.runtime.api.commons.ComponentPrecondition.Configuration.requireNotBlank;
import static com.reedelk.runtime.api.commons.ComponentPrecondition.Configuration.requireNotNull;
import static org.osgi.service.component.annotations.ServiceScope.PROTOTYPE;

@ModuleComponent("Sign Token")
@ComponentOutput(
        attributes = MessageAttributes.class,
        payload = String.class,
        description = "A new signed token containing issued date, configured subject, audience, expiration and claims.")
@ComponentInput(
        payload = Object.class,
        description = "The component input is used to evaluate the dynamic " +
                "values provided for the token claims.")
@Description("Creates a new signed token containing issued date, subject, audience, expiration and claims." +
        "The supported value types for claims are: String, Date, Long, Double, Boolean and Integer.")
@Component(service = SignToken.class, scope = PROTOTYPE)
public class SignToken implements ProcessorSync {

    @Property("JWT Configuration")
    @Description("The configuration for the JWT token.")
    private JWTConfiguration configuration;

    @Property("JWT Subject")
    @Example("Token subject")
    @Hint("Token subject")
    @Description("The optional value to be assigned to the subject claim.")
    private DynamicString subject;

    @Property("JWT Audience")
    @Example("Login")
    @Hint("Login")
    @Description("The optional value to be assigned to the audience claim.")
    private DynamicString audience;

    @Property("JWT Expiration")
    @Example("15")
    @Hint("15")
    @Description("Token expiration time in minutes.")
    private DynamicLong expiration;

    @Property("JWT Claims")
    @TabGroup("JWT Claims")
    @Description("The JWT claims to be associated with the token.")
    private DynamicObjectMap claims;

    @Reference
    ScriptEngineService scriptEngine;

    private Algorithm algorithm;

    @Override
    public void initialize() {
        requireNotBlank(SignToken.class, configuration.getIssuer(), "The name of the JWT issuer.");
        requireNotNull(SignToken.class, configuration.getAlgorithm(), "The algorithm to be used to sign and verify the token");
        algorithm = configuration.getAlgorithm().create(configuration);
    }

    @Override
    public Message apply(FlowContext flowContext, Message message) {

        LocalDateTime actualDateTime = LocalDateTime.now();
        Date issuedAtDate = Date.from(actualDateTime.atZone(ZoneId.systemDefault()).toInstant());

        JWTCreator.Builder builder = JWT.create()
                .withIssuer(configuration.getIssuer())
                .withIssuedAt(issuedAtDate);

        scriptEngine.evaluate(expiration, flowContext, message).ifPresent(expiresInMinutes -> {
            LocalDateTime exp = actualDateTime.plusMinutes(expiresInMinutes);
            Date expiresAtDate = Date.from(exp.atZone(ZoneId.systemDefault()).toInstant());
            builder.withExpiresAt(expiresAtDate);
        });

        scriptEngine.evaluate(subject, flowContext, message).ifPresent(builder::withSubject);
        scriptEngine.evaluate(audience, flowContext, message).ifPresent(builder::withAudience);

        Map<String, Object> evaluatedClaims = scriptEngine.evaluate(claims, flowContext, message);

        fillClaims(evaluatedClaims, builder);

        String token;
        try {
            token = builder.sign(algorithm);
        } catch (JWTCreationException exception) {
            String error = Messages.SignToken.ERROR_SIGN.format(exception.getMessage());
            throw new TokenSignException(error, exception);
        }

        return MessageBuilder.get(SignToken.class)
                .withString(token, MimeType.TEXT_PLAIN)
                .build();
    }

    public void setConfiguration(JWTConfiguration configuration) {
        this.configuration = configuration;
    }

    public void setClaims(DynamicObjectMap claims) {
        this.claims = claims;
    }

    public void setSubject(DynamicString subject) {
        this.subject = subject;
    }

    public void setAudience(DynamicString audience) {
        this.audience = audience;
    }

    public void setExpiration(DynamicLong expiration) {
        this.expiration = expiration;
    }

    private void fillClaims(Map<String, Object> evaluatedClaims, JWTCreator.Builder builder) {
        if (evaluatedClaims != null && !evaluatedClaims.isEmpty()) {
            evaluatedClaims.forEach((claimKey, claimValue) -> {
                // String/Date/Long/Double/Boolean/Integer
                if (claimValue instanceof String) builder.withClaim(claimKey, (String) claimValue);
                if (claimValue instanceof Date) builder.withClaim(claimKey, (Date) claimValue);
                if (claimValue instanceof Long) builder.withClaim(claimKey, (Long) claimValue);
                if (claimValue instanceof Double) builder.withClaim(claimKey, (Double) claimValue);
                if (claimValue instanceof Boolean) builder.withClaim(claimKey, (Boolean) claimValue);
                if (claimValue instanceof Integer) builder.withClaim(claimKey, (Integer) claimValue);
            });
        }
    }
}
