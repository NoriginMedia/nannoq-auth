package com.nannoq.tools.auth;

/**
 * Created by anders on 24/02/2017.
 */
public class AuthGlobals {
    public static final String VALID_JWT_REGISTRY_KEY = "_valid_jwt_registry";
    public static final String VALIDATION_REQUEST = "VALIDATION";

    // auth
    public static final String GLOBAL_AUTHORIZATION = "GLOBAL";

    // claims
    public static final String JWT_CLAIMS_USER_EMAIL = "email";
    public static final String JWT_CLAIMS_NAME = "name";
    public static final String JWT_CLAIMS_GIVEN_NAME = "givenName";
    public static final String JWT_CLAIMS_FAMILY_NAME = "familyName";
    public static final String JWT_CLAIMS_EMAIL_VERIFIED = "emailVerified";

    // timers
    public static final long SEVEN_DAYS = 7L * (3600L * 1000L * 24L);
}
