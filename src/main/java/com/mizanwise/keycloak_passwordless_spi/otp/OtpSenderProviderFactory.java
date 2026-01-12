package com.mizanwise.keycloak_passwordless_spi.otp;

import com.mizanwise.keycloak_passwordless_spi.email.EmailOtpSender;
import com.mizanwise.keycloak_passwordless_spi.sms.SmsOtpSender;

import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import static com.mizanwise.keycloak_passwordless_spi.OtpAuthenticatorFactory.*;

public class OtpSenderProviderFactory {
    // channel -> provider, immutable after construction for thread safety
    private final Map<OtpChannel, OtpSenderProvider> providers;
    private final Map<String, String> config;

    private OtpSenderProviderFactory(Map<String, String> cfg) {
        this.config = Collections.unmodifiableMap(new HashMap<>(cfg));
        EnumMap<OtpChannel, OtpSenderProvider> map = new EnumMap<>(OtpChannel.class);

        // Dynamically register OTP sender providers based on configuration
        map.put(OtpChannel.SMS, new SmsOtpSender(cfg));
        map.put(OtpChannel.EMAIL, new EmailOtpSender(cfg));

        // Future: register other channel providers here (EMAIL, PUSH, etc.)
        // e.g., map.put(OtpChannel.EMAIL, new EmailOtpSender(...));

        this.providers = Collections.unmodifiableMap(map);
    }

    /**
     * Build a new factory instance on demand using provided configuration.
     */
    public static OtpSenderProviderFactory getInstance(Map<String, String> cfg) {
        return new OtpSenderProviderFactory(cfg);
    }

    /**
     * Lookup provider by channel. Returns null if none registered.
     */
    public OtpSenderProvider get(OtpChannel channel) {
        OtpSenderProvider provider = providers.get(channel);
        if (provider == null) {
            throw new IllegalStateException(String.format(
                    "No OTP sender provider registered for channel %s. Available: %s. Config: %s",
                    channel, providers.keySet(), config));
        }
        return provider;
    }

    /**
     * Expose the configuration used to build this factory.
     */
    public Map<String, String> getConfig() {
        return config;
    }

    /**
     * Snapshot of registered providers.
     */
    public Map<OtpChannel, OtpSenderProvider> snapshotProviders() {
        return providers;
    }
}
