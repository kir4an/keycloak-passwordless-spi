package com.mizanwise.keycloak_passwordless_spi.otp;

import org.keycloak.authentication.AuthenticationFlowContext;

public interface OtpSenderProvider {
    void sendOtp(AuthenticationFlowContext ctx, OtpRequest request) throws OtpSendingException;
}
