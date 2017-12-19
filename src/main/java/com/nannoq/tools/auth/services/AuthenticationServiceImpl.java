/*
 * MIT License
 *
 * Copyright (c) 2017 Anders Mikkelsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.nannoq.tools.auth.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.nannoq.tools.auth.models.AuthPackage;
import com.nannoq.tools.auth.models.TokenContainer;
import com.nannoq.tools.auth.models.UserProfile;
import com.nannoq.tools.auth.services.providers.FaceBookProvider;
import com.nannoq.tools.auth.services.providers.Google;
import com.nannoq.tools.auth.services.providers.InstaGram;
import com.nannoq.tools.auth.services.providers.utils.GoogleUser;
import com.nannoq.tools.auth.utils.PermissionPack;
import com.nannoq.tools.repository.models.ModelUtils;
import com.nannoq.tools.repository.repository.redis.RedisUtils;
import io.jsonwebtoken.*;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.redis.RedisClient;
import io.vertx.redis.RedisTransaction;
import io.vertx.serviceproxy.ServiceException;
import org.apache.commons.codec.digest.DigestUtils;

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

import static com.nannoq.tools.auth.AuthGlobals.*;
import static com.nannoq.tools.auth.utils.AuthFutures.authFail;
import static java.util.stream.Collectors.toConcurrentMap;

/**
 * This class defines an authenticator. The authenticator receives an external token and converts it into an internal
 * JWT.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class.getSimpleName());

    private static String KEY_ALGORITHM = "HmacSHA512";

    private final String CALLBACK_URL;

    private final String EMAIL_HASH_KEY_BASE;

    public static final String GOOGLE = "GOOGLE";
    public static final String FACEBOOK = "FACEBOOK";
    public static final String INSTAGRAM = "INSTAGRAM";

    static final String REFRESH_TOKEN_SPLITTER = "____";

    private final String ISSUER;
    private final String AUDIENCE;

    private final Vertx vertx;
    private final JsonObject appConfig;
    private final RedisClient redisClient;
    private final String domainIdentifier;
    private final SecretKey SIGNING_KEY;
    private final List<String> GOOGLE_CLIENT_IDS;

    private int notBeforeTimeInMinutes = -5;
    private int idTokenExpirationInDays = 5;
    private int refreshTokenExpirationInDays = 30;

    private Function<PermissionPack, Map<String, Object>> setPermissionOnClaims;

    public AuthenticationServiceImpl(@Nonnull Vertx vertx, @Nonnull JsonObject appConfig,
                                     @Nonnull Function<PermissionPack, Map<String, Object>> permissionFunction,
                                     @Nonnull String KEY_BASE)
            throws InvalidKeyException, NoSuchAlgorithmException {
        this.vertx = vertx;
        this.appConfig = appConfig;
        this.redisClient = RedisUtils.getRedisClient(vertx, appConfig);
        this.domainIdentifier = appConfig.getString("domainIdentifier");
        this.setPermissionOnClaims = permissionFunction;
        this.SIGNING_KEY = new SecretKeySpec(DatatypeConverter.parseHexBinary(KEY_BASE), KEY_ALGORITHM);
        //noinspection unchecked
        this.GOOGLE_CLIENT_IDS = appConfig.getJsonArray("gcmIds").getList();
        this.EMAIL_HASH_KEY_BASE = appConfig.getString("emailHashKeybase");
        String CALL_BACK_PROVIDER_URL = appConfig.getString("callbackProviderUrl");
        this.CALLBACK_URL = appConfig.getString("callBackRoot") + CALL_BACK_PROVIDER_URL;
        this.ISSUER = appConfig.getString("authJWTIssuer");
        this.AUDIENCE = appConfig.getString("authJWTAudience");

        initializeKey(KEY_ALGORITHM);
    }

    @Fluent
    private AuthenticationServiceImpl setNotBeforeTimeInMinutes(int notBeforeTimeInMinutes) {
        this.notBeforeTimeInMinutes = notBeforeTimeInMinutes;

        return this;
    }

    @Fluent
    private AuthenticationServiceImpl setIdTokenExpirationInDays(int idTokenExpirationInDays) {
        this.idTokenExpirationInDays = idTokenExpirationInDays;

        return this;
    }

    @Fluent
    private AuthenticationServiceImpl setRefreshTokenExpirationInDays(int refreshTokenExpirationInDays) {
        this.refreshTokenExpirationInDays = refreshTokenExpirationInDays;

        return this;
    }

    @Fluent
    private AuthenticationServiceImpl setKeyAlgorithm(String keyAlgorithm) {
        KEY_ALGORITHM = keyAlgorithm;

        return this;
    }

    @Fluent
    public AuthenticationServiceImpl withNotBeforeTimeInMinutes(int notBeforeTime) {
        return setNotBeforeTimeInMinutes(notBeforeTime);
    }

    @Fluent
    public AuthenticationServiceImpl withIdTokenExpirationInDays(int idTokenExpiration) {
        return setIdTokenExpirationInDays(idTokenExpiration);
    }

    @Fluent
    public AuthenticationServiceImpl withRefreshTokenExpirationInDays(int refreshTokenExpiration) {
        return setRefreshTokenExpirationInDays(refreshTokenExpiration);
    }

    @Fluent
    public AuthenticationServiceImpl withKeyAlgorithm(String keyAlgorithm) {
        return setKeyAlgorithm(keyAlgorithm);
    }

    private void initializeKey(String keyAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(keyAlgorithm);
        mac.init(SIGNING_KEY);
    }

    @Override
    @Fluent
    public AuthenticationService createJwtFromProvider(@Nonnull String token, @Nonnull String authProvider,
                                                       @Nonnull Handler<AsyncResult<AuthPackage>> resultHandler) {
        AsyncResult<AuthPackage> unableToParseException = ServiceException.fail(500, "Unable to parse Token: ");

        switch (authProvider.toUpperCase()) {
            case GOOGLE:
                new Google().withClientIds(GOOGLE_CLIENT_IDS).checkJWT(vertx, appConfig, token, result -> {
                    if (result.failed()) {
                        logger.error("Unable to process Google Token!", result.cause());

                        resultHandler.handle(unableToParseException);
                    } else {
                        buildAuthPackage(result.result(), authResult ->
                                resultHandler.handle(Future.succeededFuture(authResult.result())));
                    }
                });
                break;
            case FACEBOOK:
                new FaceBookProvider().checkJWT(vertx, appConfig, token, result -> {
                    if (result.failed()) {
                        logger.error("Unable to process Facebook Token!", result.cause());

                        resultHandler.handle(unableToParseException);
                    } else {
                        buildAuthPackage(result.result(), authResult ->
                                resultHandler.handle(Future.succeededFuture(authResult.result())));
                    }
                });
                break;
            case INSTAGRAM:
                new InstaGram(CALLBACK_URL).checkJWT(vertx, appConfig, token, result -> {
                    if (result.failed()) {
                        logger.error("Unable to process Instagram Token!", result.cause());

                        resultHandler.handle(unableToParseException);
                    } else {
                        buildAuthPackage(result.result(), authResult ->
                                resultHandler.handle(Future.succeededFuture(authResult.result())));
                    }
                });
                break;
            default:
                logger.error("ERROR JwtGenerator: Unknown AuthProvider: " + authProvider);
                resultHandler.handle(ServiceException.fail(400, "Unknown Provider..."));
                break;
        }

        return this;
    }

    private void buildAuthPackage(UserProfile userProfile, Handler<AsyncResult<AuthPackage>> resultHandler) {
        String userId;

        try {
            userId = ModelUtils.hashString(userProfile.getEmail() + EMAIL_HASH_KEY_BASE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            userId = userProfile.getEmail();
        }

        userProfile.setUserId(userId);

        Map<String, Object> claimsMap = createClaimsMap(userProfile);
        String email = userProfile.getEmail();

        doTokenCreation(userProfile, resultHandler, claimsMap, email);
    }

    private void buildAuthPackage(@Nonnull GoogleIdToken.Payload result,
                                  Handler<AsyncResult<AuthPackage>> resultHandler) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JWT_CLAIMS_USER_EMAIL, result.getEmail());
        claims.put(JWT_CLAIMS_NAME, result.get("name"));
        claims.put(JWT_CLAIMS_GIVEN_NAME, result.get("given_name"));
        claims.put(JWT_CLAIMS_FAMILY_NAME, result.get("family_name"));
        claims.put(JWT_CLAIMS_EMAIL_VERIFIED, result.get("email_verified"));

        UserProfile userProfile = new GoogleUser(result);
        String userId;

        try {
            userId = ModelUtils.hashString(userProfile.getEmail() + EMAIL_HASH_KEY_BASE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            userId = userProfile.getEmail();
        }

        userProfile.setUserId(userId);

        String email = result.getEmail();

        doTokenCreation(userProfile, resultHandler, claims, email);
    }

    private void doTokenCreation(UserProfile userProfile, Handler<AsyncResult<AuthPackage>> resultHandler,
                                 Map<String, Object> claimsMap, String email) {
        createTokenContainer(email, claimsMap, tokenContainerResult -> {
            if (tokenContainerResult.result() != null) {
                resultHandler.handle(Future.succeededFuture(new AuthPackage(
                        tokenContainerResult.result(), userProfile)));
            } else {
                logger.error("TokenContainer is null...", tokenContainerResult.cause());

                resultHandler.handle(
                        ServiceException.fail(500, "TokenContainer is null..."));
            }
        });
    }

    private Map<String, Object> createClaimsMap(UserProfile result) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(JWT_CLAIMS_USER_EMAIL, result.getEmail());
        claims.put(JWT_CLAIMS_NAME, result.getName());
        claims.put(JWT_CLAIMS_GIVEN_NAME, result.getGivenName());
        claims.put(JWT_CLAIMS_FAMILY_NAME, result.getFamilyName());
        claims.put(JWT_CLAIMS_EMAIL_VERIFIED, result.isEmailVerified());

        return claims;
    }

    private void createTokenContainer(String email, Map<String, Object> claims,
                                      Handler<AsyncResult<TokenContainer>> resultHandler) {
        try {
            final String id = ModelUtils.hashString(email + EMAIL_HASH_KEY_BASE);

            Calendar now = Calendar.getInstance();
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DAY_OF_MONTH, idTokenExpirationInDays);

            Calendar notBefore = Calendar.getInstance();
            notBefore.add(Calendar.MINUTE, notBeforeTimeInMinutes);

            String jwtId = UUID.randomUUID().toString();

            claims.put("id", jwtId);
            claims = generatePermissions(id, claims, GLOBAL_AUTHORIZATION);

            String jwt = createJwt(id, jwtId, claims, now.getTime(), notBefore.getTime(), calendar.getTime());

            calendar.add(Calendar.DAY_OF_MONTH, refreshTokenExpirationInDays);
            String newRefreshToken = DigestUtils.sha1Hex(id + UUID.randomUUID().toString());
            String refreshTokenWithExpireKey = newRefreshToken + REFRESH_TOKEN_SPLITTER + calendar.getTime().getTime();

            createTokenContainer(id, jwtId, email, newRefreshToken, claims,
                    jwt, refreshTokenWithExpireKey, resultHandler);
        } catch (JwtException | IllegalArgumentException | NoSuchAlgorithmException e) {
            logger.error("Failed Token Container Creation!", e);

            resultHandler.handle(ServiceException.fail(500, "" + e));
        }
    }

    private void createTokenContainer(String id, String jwtId, String email,
                                      String newRefreshToken, Map<String, Object> claims,
                                      String jwt, String expireToken,
                                      Handler<AsyncResult<TokenContainer>> resultHandler) {
        String mapId = id + VALID_JWT_REGISTRY_KEY;

        RedisUtils.performJedisWithRetry(redisClient, intRedis -> {
            RedisTransaction transaction = intRedis.transaction();

            transaction.multi(multiResult -> transaction.hset(mapId, jwtId, expireToken, result -> {
                if (result.failed()) {
                    logger.error("Could not set valid jwt for: " + email, result.cause());
                } else {
                    String encodedClaims = Json.encode(claims);

                    transaction.set(newRefreshToken, encodedClaims, setRefreshHandler -> {
                        if (setRefreshHandler.failed()) {
                            logger.error("Could not store refreshtoken for: " + email, setRefreshHandler.cause());
                        }
                    });
                }
            }));

            transaction.exec(execResult -> {
                if (execResult.failed()) {
                    resultHandler.handle(ServiceException.fail(
                            500, "Could not set valid jwt for: " + email));
                } else {
                    resultHandler.handle(Future.succeededFuture(new TokenContainer(jwt, newRefreshToken)));
                }
            });
        });
    }

    private String createJwt(String id, String jwtId, Map<String, Object> claims, Date now, Date notBefore, Date then)
            throws IllegalArgumentException {
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(ISSUER)
                .setSubject(id)
                .setAudience(AUDIENCE)
                .setExpiration(then)
                .setNotBefore(notBefore)
                .setIssuedAt(now)
                .setId(jwtId)
                .signWith(SignatureAlgorithm.HS512, SIGNING_KEY)
                .compressWith(CompressionCodecs.DEFLATE)
                .compact();
    }

    private String createJwt(String id, String jwtId, Jws<Claims> claims, Date now, Date notBefore, Date then)
            throws IllegalArgumentException {
        return Jwts.builder()
                .setClaims(claims.getBody())
                .setIssuer(ISSUER)
                .setSubject(id)
                .setAudience(AUDIENCE)
                .setExpiration(then)
                .setNotBefore(notBefore)
                .setIssuedAt(now)
                .setId(jwtId)
                .signWith(SignatureAlgorithm.HS512, SIGNING_KEY)
                .compressWith(CompressionCodecs.DEFLATE)
                .compact();
    }

    private Map<String, Object> generatePermissions(String userId, Map<String, Object> claims, String authOrigin) {
        claims.putIfAbsent(domainIdentifier, userId);

        return setPermissionOnClaims.apply(new PermissionPack(userId, claims, authOrigin));
    }

    @SuppressWarnings("unchecked")
    @Override
    @Fluent
    public AuthenticationService refresh(@Nonnull String refreshToken,
                                         @Nonnull Handler<AsyncResult<TokenContainer>> resultHandler) {
        getTokenCache(refreshToken).compose(tokenCache ->
        getClaims(tokenCache).compose(claims -> {
            String oldId = claims.get("id").toString();

            getTokenContainer(claims).compose(tokenContainer ->
            deleteOld(claims, refreshToken, oldId, tokenContainer).compose(container ->
                            resultHandler.handle(Future.succeededFuture(container)),
                            authFail(resultHandler)),
            authFail(resultHandler));
        }, authFail(resultHandler)),
        authFail(resultHandler));

        return this;
    }

    private Future<TokenContainer> deleteOld(Map<String, Object> claims, String refreshToken, String oldId,
                                             TokenContainer tokenContainer) {
        Future<TokenContainer> tokenContainerFuture = Future.future();
        final String email = claims.get(JWT_CLAIMS_USER_EMAIL).toString();
        String userId;

        try {
            userId = ModelUtils.hashString(email + EMAIL_HASH_KEY_BASE);
        } catch (NoSuchAlgorithmException e) {
            logger.error("No Algorithm!", e);
            userId = email;
        }

        final String finalUserId = userId;
        final String id = oldId;

        logger.debug("Purging: " + finalUserId + VALID_JWT_REGISTRY_KEY + " " + id);

        final String registry = finalUserId + VALID_JWT_REGISTRY_KEY;

        RedisUtils.performJedisWithRetry(redisClient, internalRedis -> {
            RedisTransaction transaction = internalRedis.transaction();

            transaction.multi(multiResult -> {
                transaction.del(refreshToken, delResult -> {
                    if (delResult.failed()) {
                        logger.debug("Del RefreshToken failed!");
                    }
                });

                transaction.hdel(registry, id, delValResult -> {
                    if (delValResult.failed()) {
                        logger.debug("Del JwtValidity failed!");
                    }
                });
            });

            transaction.exec(execResult -> {
                if (execResult.failed()) {
                    tokenContainerFuture.fail(new InternalError("Unable to purge old refresh..."));
                } else {
                    logger.debug("Purged all remnants of old refresh...");

                    tokenContainerFuture.complete(tokenContainer);
                }
            });
        });

        return tokenContainerFuture;
    }

    @SuppressWarnings("unchecked")
    private Future<Map<String, Object>> getClaims(String tokenCache) {
        Future<Map<String, Object>> claimsFuture = Future.future();

        if (tokenCache == null) {
            claimsFuture.fail(new ServiceException(500, "TokenCache cannot be null..."));
        } else {
            try {
                Map<String, Object> claims = Json.decodeValue(tokenCache, Map.class);

                claimsFuture.complete(claims);
            } catch (DecodeException e) {
                claimsFuture.fail(e);
            }
        }

        return claimsFuture;
    }

    private Future<TokenContainer> getTokenContainer(Map<String, Object> claims) {
        Future<TokenContainer> tokenContainerFuture = Future.future();
        String email = claims.get(JWT_CLAIMS_USER_EMAIL).toString();

        createTokenContainer(email, claims, tokenContainerResult -> {
            if (tokenContainerResult.failed()) {
                tokenContainerFuture.fail(tokenContainerResult.cause());
            } else {
                tokenContainerFuture.complete(tokenContainerResult.result());
            }
        });

        return tokenContainerFuture;
    }

    private Future<String> getTokenCache(String refreshToken) {
        Future<String> tokenCacheFuture = Future.future();

        RedisUtils.performJedisWithRetry(redisClient, intRedis -> intRedis.get(refreshToken, getResult -> {
            if (getResult.failed()) {
                tokenCacheFuture.fail(getResult.cause());
            } else {
                tokenCacheFuture.complete(getResult.result());
            }
        }));

        return tokenCacheFuture;
    }

    @Fluent
    @Override
    public AuthenticationService switchToAssociatedDomain(String domainId, Jws<Claims> verifyResult,
                                                          Handler<AsyncResult<TokenContainer>> resultHandler) {
        verifyResult.getBody().put(domainIdentifier, domainId);

        createTokenContainer(verifyResult, resultHandler);

        return this;
    }

    private void createTokenContainer(Jws<Claims> claims, Handler<AsyncResult<TokenContainer>> resultHandler) {
        try {
            String email = claims.getBody().get(JWT_CLAIMS_USER_EMAIL).toString();
            final String id = ModelUtils.hashString(email + EMAIL_HASH_KEY_BASE);

            Calendar now = Calendar.getInstance();
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DAY_OF_MONTH, idTokenExpirationInDays);

            Calendar notBefore = Calendar.getInstance();
            notBefore.add(Calendar.MINUTE, notBeforeTimeInMinutes);

            String jwtId = UUID.randomUUID().toString();

            claims.getBody().put("id", jwtId);

            String jwt = createJwt(id, jwtId, claims, now.getTime(), notBefore.getTime(), calendar.getTime());

            calendar.add(Calendar.DAY_OF_MONTH, refreshTokenExpirationInDays);
            String newRefreshToken = DigestUtils.sha1Hex(id + UUID.randomUUID().toString());
            String refreshTokenWithExpireKey = newRefreshToken + REFRESH_TOKEN_SPLITTER + calendar.getTime().getTime();

            Map<String, Object> mappedClaims = claims.getBody().entrySet().stream()
                    .map(e -> new AbstractMap.SimpleEntry<>(e.getKey(), e.getValue()))
                    .collect(toConcurrentMap(Map.Entry::getKey, Map.Entry::getValue));

            createTokenContainer(id, jwtId, email, newRefreshToken, mappedClaims,
                    jwt, refreshTokenWithExpireKey, resultHandler);
        } catch (JwtException | IllegalArgumentException | NoSuchAlgorithmException e) {
            logger.error("Failed Token Container Creation!", e);

            resultHandler.handle(ServiceException.fail(500, "" + e));
        }
    }

    @Override
    public void close() {
        redisClient.close(closerResult ->
                logger.debug("RedisClient closed for AuthenticationService: " + closerResult.succeeded()));
    }
}
