package com.mizanwise.keycloak_passwordless_spi.email;

import com.mizanwise.keycloak_passwordless_spi.otp.OtpRequest;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpSenderProvider;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpSendingException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.RealmModel;

import java.lang.reflect.Method;
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

        EmailTemplateProvider emailTemplate = ctx.getSession().getProvider(EmailTemplateProvider.class);
        if (emailTemplate != null) {
            emailTemplate.setRealm(ctx.getRealm());
        }

        EmailSenderProvider sender = ctx.getSession().getProvider(EmailSenderProvider.class);
        if (sender == null) {
            throw new OtpSendingException("EmailSenderProvider not available");
        }

        try {
            sendToAddress(sender, ctx.getRealm(), request.getDestination(), SUBJECT, message);
        } catch (Exception e) {
            throw new OtpSendingException("Failed to send email OTP", e);
        }
    }

    private void sendToAddress(EmailSenderProvider sender,
                               RealmModel realm,
                               String address,
                               String subject,
                               String textBody) throws Exception {
        Method method = sender.getClass()
                .getMethod("send", RealmModel.class, String.class, String.class, String.class, String.class);
        method.invoke(sender, realm, address, subject, textBody, textBody);
    }
}
