package com.mizanwise.keycloak_passwordless_spi;

import com.mizanwise.keycloak_passwordless_spi.otp.OtpChannel;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpRequest;
import com.mizanwise.keycloak_passwordless_spi.otp.OtpSenderProviderFactory;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mizanwise.keycloak_passwordless_spi.OtpAuthenticatorFactory.*;

public class OtpAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(OtpAuthenticator.class.getName());
    private static final String FAKE_OTP = "929903"; // A fake OTP for testing purposes

    private static final String PARAM_USERNAME = "username";
    private static final String PARAM_OTP = "otp";
    private static final String PARAM_CHANNEL = "channel";

    private static final SecureRandom RND = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext ctx) {
        process(ctx);
    }

    @Override
    public void action(AuthenticationFlowContext ctx) {
        process(ctx);
    }

    private void process(AuthenticationFlowContext ctx) {
        LOG.infof("=== OTP PROCESS START ===");
        LOG.infof("Session ID: %s", ctx.getAuthenticationSession().getParentSession().getId());
        LOG.infof("Tab ID: %s", ctx.getAuthenticationSession().getTabId());
        LOG.infof("Execution ID: %s", ctx.getExecution().getId());

        MultivaluedMap<String, String> form = ctx.getHttpRequest().getDecodedFormParameters();
        String phone = val(form, PARAM_USERNAME);
        String otp = val(form, PARAM_OTP);
        String channel = val(form, PARAM_CHANNEL);

        LOG.infof("Form params - username: %s, otp: %s, channel: %s",
                phone != null ? phone : "NULL",
                otp != null ? "***" : "NULL",
                channel != null ? channel : "NULL");

        // Если phone не в форме, извлечь из сессии
        if (phone == null) {
            phone = ctx.getAuthenticationSession().getAuthNote("username");
            LOG.infof("Retrieved username from session: %s", phone != null ? phone : "NULL");
        }

        Map<String, String> cfg =
                Optional.ofNullable(ctx.getAuthenticatorConfig())
                        .map(AuthenticatorConfigModel::getConfig)
                        .orElseGet(Map::of);

        boolean developmentMode = Boolean.parseBoolean(cfg.getOrDefault(PROP_DEVELOPMENT_MODE, "false"));
        int otpLen = parseInt(cfg.getOrDefault(PROP_LEN, "6"), 6);
        int otpExp = parseInt(cfg.getOrDefault(PROP_EXPIRATION_TIME, "5"), 5);
        boolean allowReg = Boolean.parseBoolean(cfg.getOrDefault(PROP_ALLOW_REG, "true"));
        String errUnknown = cfg.getOrDefault(PROP_ERR_UNK, "unknown_user");
        String defaultChannel = cfg.getOrDefault(PROP_DEFAULT_CHANNEL, OtpChannel.SMS.toString());

        LOG.infof("Config - developmentMode: %s, otpLen: %d, otpExp: %d, allowReg: %s",
                developmentMode, otpLen, otpExp, allowReg);

        // Показать форму ввода email, если email не введен
        if (phone == null || phone.trim().isEmpty()) {
            LOG.info("No username provided, showing phone.ftl");
            Response page = ctx.form().createForm("phone.ftl");
            ctx.challenge(page);
            return;
        }

        // Сохранить username в сессии для последующих запросов
        ctx.getAuthenticationSession().setAuthNote("username", phone);
        LOG.infof("Saved username to session: %s", phone);

        // Отправить OTP, если код еще не введен
        if (otp == null || otp.trim().isEmpty()) {
            LOG.info("No OTP provided, generating and sending code");

            String code = generateCode(otpLen);
            ctx.getAuthenticationSession().setAuthNote("otp", code);
            ctx.getAuthenticationSession().setAuthNote("otp_issuing_time", Instant.now().toEpochMilli() + "");

            LOG.infof("Generated OTP code: %s (saved to session)", code);

            try {
                if (channel == null || channel.isEmpty()) {
                    channel = defaultChannel;
                }

                OtpChannel otpChannel = OtpChannel.fromString(channel);
                if (otpChannel == null) {
                    LOG.errorf("Unknown OTP channel: %s", channel);
                    Response page = ctx.form()
                            .setError("Invalid channel: " + channel)
                            .createForm("phone.ftl");
                    ctx.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, page);
                    return;
                }

                LOG.infof("Sending OTP via channel: %s to: %s", otpChannel, phone);

                OtpSenderProviderFactory.getInstance(cfg).get(otpChannel)
                        .sendOtp(
                                ctx,
                                OtpRequest.builder()
                                        .destination(phone)
                                        .code(code)
                                        .build()
                        );

                LOG.infof("OTP sent successfully to %s", phone);

            } catch (Exception e) {
                LOG.errorf(e, "Failed to send OTP to %s", phone);
                Response page = ctx.form()
                        .setError("Failed to send verification code. Please try again.")
                        .createForm("phone.ftl");
                ctx.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, page);
                return;
            }

            Response page = ctx.form()
                    .setAttribute("phone", phone)
                    .setAttribute("channel", channel)
                    .createForm("otp.ftl");
            ctx.challenge(page);
            LOG.info("Showing otp.ftl form");
            return;
        }

        // Проверить OTP
        LOG.info("Verifying OTP code");

        String expected = ctx.getAuthenticationSession().getAuthNote("otp");
        String issuingTime = ctx.getAuthenticationSession().getAuthNote("otp_issuing_time");

        LOG.infof("Expected OTP: %s, Provided OTP: %s", expected, otp);
        LOG.infof("Issuing time from session: %s", issuingTime);

        if (expected == null || issuingTime == null) {
            LOG.error("OTP or issuing time not found in session - session may have been lost");
            Response page = ctx.form()
                    .setAttribute("phone", phone)
                    .setError("Session expired. Please start over.")
                    .createForm("phone.ftl");
            ctx.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, page);
            return;
        }

        Instant issuedAt = Instant.ofEpochMilli(Long.parseLong(issuingTime));
        Instant expiresAt = issuedAt.plus(otpExp, ChronoUnit.MINUTES);
        Instant now = Instant.now();

        boolean isExpired = now.isAfter(expiresAt);
        boolean valid = otp.equals(expected) || (developmentMode && FAKE_OTP.equals(otp));

        LOG.infof("OTP validation - valid: %s, isExpired: %s (issued: %s, expires: %s, now: %s)",
                valid, isExpired, issuedAt, expiresAt, now);

        if (!valid) {
            LOG.warn("OTP code mismatch");
            Response page = ctx.form()
                    .setAttribute("phone", phone)
                    .setError("Invalid verification code")
                    .createForm("otp.ftl");
            ctx.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
            return;
        }

        if (isExpired) {
            LOG.warn("OTP code expired");
            Response page = ctx.form()
                    .setAttribute("phone", phone)
                    .setError("Verification code expired. Please request a new one.")
                    .createForm("phone.ftl");
            ctx.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, page);
            return;
        }

        // Найти или создать пользователя
        LOG.infof("Looking up user by email: %s", phone);

        UserProvider users = ctx.getSession().users();
        RealmModel realm = ctx.getRealm();

        // Сначала ищем по email
        UserModel user = users.getUserByEmail(realm, phone);

        // Если не найден, пробуем по username
        if (user == null) {
            LOG.infof("User not found by email, trying username");
            user = users.getUserByUsername(realm, phone);
        }

        if (user == null) {
            LOG.infof("User not found, allowReg=%s", allowReg);

            if (!allowReg) {
                LOG.warn("User registration not allowed");
                ctx.failureChallenge(AuthenticationFlowError.UNKNOWN_USER,
                        json(ctx, 401, "UNKNOWN_USER", errUnknown));
                return;
            }

            LOG.infof("Creating new user with username/email: %s", phone);

            user = users.addUser(realm, phone);
            user.setEnabled(true);
            user.setUsername(phone);
            user.setEmail(phone);
            user.setEmailVerified(true);

            LOG.infof("User created successfully: ID=%s, username=%s, email=%s",
                    user.getId(), user.getUsername(), user.getEmail());
        } else {
            LOG.infof("User found: ID=%s, username=%s, email=%s",
                    user.getId(), user.getUsername(), user.getEmail());
        }

        // Устанавливаем пользователя в контекст
        ctx.setUser(user);
        LOG.infof("User set in context: %s", user.getUsername());

        // Завершаем аутентификацию успешно
        ctx.success();
        LOG.infof("=== OTP PROCESS SUCCESS ===");
    }

    private static Response json(AuthenticationFlowContext ctx, int status, String action, String code) {
        return Response.status(status)
                .entity(Map.of("action", action, "error", code,
                        "execution", ctxExecution(ctx),
                        "tab_id", ctxTab(ctx)))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private static String ctxExecution(AuthenticationFlowContext ctx) {
        return ctx.getExecution().getId();
    }

    private static String ctxTab(AuthenticationFlowContext ctx) {
        return ctx.getAuthenticationSession().getTabId();
    }

    private static String val(MultivaluedMap<String, String> m, String key) {
        return m != null ? m.getFirst(key) : null;
    }

    private static String generateCode(int digits) {
        int max = (int) Math.pow(10, digits);
        return String.format("%0" + digits + 'd', RND.nextInt(max));
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return def;
        }
    }

    @Override
    public boolean requiresUser() {
        LOG.info("requiresUser() called - returning false");
        return false;  // КРИТИЧНО: false, так как мы создаем пользователя внутри
    }

    @Override
    public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) {
        LOG.infof("configuredFor() called for user: %s", u != null ? u.getUsername() : "null");
        return true;  // КРИТИЧНО: всегда true
    }

    @Override
    public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {
        LOG.infof("setRequiredActions() called for user: %s", u != null ? u.getUsername() : "null");
        // Ничего не делаем - не добавляем required actions
    }

    @Override
    public void close() {
    }
}
