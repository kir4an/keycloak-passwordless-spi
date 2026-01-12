package com.mizanwise.keycloak_passwordless_spi.email;

import com.mizanwise.keycloak_passwordless_spi.otp.OtpRequest;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpSenderProvider;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpSendingException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.RealmModel;

import java.util.Map;

import static com.mizanwise.keycloak_passwordless_spi.OtpAuthenticatorFactory.PROP_SMS_TPL;

public class EmailOtpSender implements OtpSenderProvider {
    private static final String ARG_CODE = "{code}";
    private static final String DEFAULT_TEMPLATE = "Your code is {code}";
    private static final String SUBJECT = "Your verification code";

    private final String template;

    public EmailOtpSender(Map<String, String> cfg) {
        this.template = cfg.getOrDefault(PROP_SMS_TPL, DEFAULT_TEMPLATE);
    }

    @Override
    public void sendOtp(AuthenticationFlowContext ctx, OtpRequest request) throws OtpSendingException {
        String message = template.replace(ARG_CODE, request.getCode());

        EmailSenderProvider sender = ctx.getSession().getProvider(EmailSenderProvider.class);
        if (sender == null) {
            throw new OtpSendingException("EmailSenderProvider not available");
        }

        RealmModel realm = ctx.getRealm();
        String address = request.getDestination();

        try {
            // Keycloak 26: config берём из realm SMTP settings
            sender.send(realm.getSmtpConfig(), address, SUBJECT, message, message);
        } catch (EmailException e) {
            throw new OtpSendingException("Failed to send email OTP to " + address + ": " + e.getMessage(), e);
        }
    }
}
