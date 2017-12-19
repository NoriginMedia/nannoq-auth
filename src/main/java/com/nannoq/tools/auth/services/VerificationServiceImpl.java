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

import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.utils.Authorization;
import com.nannoq.tools.auth.utils.Authorizer;
import com.nannoq.tools.repository.repository.redis.RedisUtils;
import io.jsonwebtoken.*;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.redis.RedisClient;
import io.vertx.redis.RedisTransaction;
import io.vertx.serviceproxy.ServiceException;

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.List;
import java.util.function.Supplier;

import static com.nannoq.tools.auth.AuthGlobals.VALIDATION_REQUEST;
import static com.nannoq.tools.auth.AuthGlobals.VALID_JWT_REGISTRY_KEY;
import static com.nannoq.tools.auth.services.AuthenticationServiceImpl.REFRESH_TOKEN_SPLITTER;

/**
 * This class defines an implementation of a VerificationService. It verifies both incoming JWTS, and also checks
 * whether a token has been revoked or not.
 *
 * Accepts HTTP and Eventbus.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class VerificationServiceImpl implements VerificationService {
    private static final Logger logger = LoggerFactory.getLogger(VerificationServiceImpl.class.getSimpleName());

    private static String KEY_ALGORITHM = "HmacSHA512";

    private final String ISSUER;
    private final String AUDIENCE;

    private final Vertx vertx;
    private final SecretKey SIGNING_KEY;
    private final String domainIdentifier;
    private final RedisClient redisClient;
    private final Authorizer authorizer;
    private final Supplier<Future<List<String>>> userIdsSupplier;
    private final boolean dev;

    public VerificationServiceImpl(Vertx vertx, @Nullable JsonObject appConfig, @Nonnull String KEY_BASE,
                                   Authorizer authorizer, Supplier<Future<List<String>>> userIdsSupplier)
            throws NoSuchAlgorithmException, InvalidKeyException {
        this(vertx, appConfig, KEY_BASE, authorizer, userIdsSupplier, false);
    }

    public VerificationServiceImpl(Vertx vertx, @Nullable JsonObject appConfig, @Nonnull String KEY_BASE,
                                   Authorizer authorizer, Supplier<Future<List<String>>> userIdsSupplier, boolean dev)
            throws InvalidKeyException, NoSuchAlgorithmException {
        this.vertx = vertx;
        this.SIGNING_KEY = new SecretKeySpec(DatatypeConverter.parseHexBinary(KEY_BASE), KEY_ALGORITHM);
        this.domainIdentifier = appConfig.getString("domainIdentifier");
        this.userIdsSupplier = userIdsSupplier;
        this.redisClient = RedisUtils.getRedisClient(vertx, appConfig);
        this.authorizer = authorizer;
        this.ISSUER = appConfig.getString("authJWTIssuer");
        this.AUDIENCE = appConfig.getString("authJWTAudience");
        this.dev = dev;

        initializeKey(KEY_ALGORITHM);
    }

    @Fluent
    private VerificationServiceImpl setKeyAlgorithm(String keyAlgorithm) {
        KEY_ALGORITHM = keyAlgorithm;

        return this;
    }

    @Fluent
    public VerificationServiceImpl withKeyAlgorithm(String keyAlgorithm) {
        return setKeyAlgorithm(keyAlgorithm);
    }

    private void initializeKey(String keyAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(keyAlgorithm);
        mac.init(SIGNING_KEY);
    }

    @Fluent
    @Override
    public VerificationService verifyJWT(@Nonnull String token, @Nonnull Authorization authorization,
                                         @Nonnull Handler<AsyncResult<VerifyResult>> resultHandler) {
        verifyToken(token, verifyResult -> {
            if (verifyResult.failed()) {
                logger.error("ERROR JWT: " + verifyResult.cause());

                resultHandler.handle(ServiceException.fail(
                        401, "ERROR: " + verifyResult.cause()));
            } else {
                Jws<Claims> claims = verifyResult.result();

                try {
                    if (authorization.validate()) {
                        if (authorization.getDomainIdentifier().equals(VALIDATION_REQUEST)) {
                            returnAuth(claims, resultHandler);
                        } else {
                            if (authorizer.isAsync()) {
                                verifyAuthorization(claims, authorization, res ->
                                        authResult(claims, resultHandler, res.succeeded()));
                            } else {
                                authResult(claims, resultHandler, verifyAuthorization(claims, authorization));
                            }
                        }
                    } else {
                        logger.error("Invalid Authorization Field: " + Json.encodePrettily(authorization));

                        notAuthorized(resultHandler);
                    }
                } catch (IllegalAccessException e) {
                    resultHandler.handle(ServiceException.fail(
                            401, "Not authorized for this resource, invalid AuthTypeToken!"));
                }
            }
        });

        return this;
    }

    private void authResult(Jws<Claims> claims, Handler<AsyncResult<VerifyResult>> resultHandler, boolean succeeded) {
        if (succeeded) {
            returnAuth(claims, resultHandler);
        } else {
            notAuthorized(resultHandler);
        }
    }

    private void notAuthorized(Handler<AsyncResult<VerifyResult>> resultHandler) {
        resultHandler.handle(ServiceException.fail(401, "Not authorized for this resource!"));
    }

    private void returnAuth(Jws<Claims> claims, @Nonnull Handler<AsyncResult<VerifyResult>> resultHandler) {
        VerifyResult vr = new VerifyResult(claims.getBody().getSubject());

        logger.debug("User Auth: " + Json.encodePrettily(vr));

        resultHandler.handle(Future.succeededFuture(vr));
    }

    @Fluent
    @Override
    public VerificationServiceImpl verifyToken(String token, Handler<AsyncResult<Jws<Claims>>> resultHandler) {
        vertx.executeBlocking(verificationFuture -> {
            try {
                logger.debug("Verifying Token...");

                Jws<Claims> claims = Jwts.parser()
                        .setSigningKey(SIGNING_KEY)
                        .requireIssuer(ISSUER)
                        .requireAudience(AUDIENCE)
                        .parseClaimsJws(token);

                logger.debug("Token parsed...");

                final String userId = claims.getBody().getSubject();
                final String id = claims.getBody().getId();
                final String registry = userId + VALID_JWT_REGISTRY_KEY;

                if (dev) {
                    logger.info("DEV ACCEPT");

                    resultHandler.handle(Future.succeededFuture(claims));
                    verificationFuture.complete(Future.succeededFuture());
                } else {
                    RedisUtils.performJedisWithRetry(redisClient, intRedis -> intRedis.hget(registry, id, jwts -> {
                        if (jwts.failed()) {
                            resultHandler.handle(ServiceException.fail(
                                    500, "Redis failure..."));
                            verificationFuture.fail(jwts.cause());

                            logger.error("Failed to fetch from redis store...");
                        } else {
                            final String result = jwts.result();

                            if (result != null && result.length() > 4 && result.contains("____")) {
                                resultHandler.handle(Future.succeededFuture(claims));
                                verificationFuture.complete(Future.succeededFuture());
                            } else {
                                failedVerify(verificationFuture, resultHandler, jwts, userId, id);
                            }
                        }
                    }));
                }
            } catch (MissingClaimException | IncorrectClaimException | SignatureException |
                    ExpiredJwtException | MalformedJwtException | PrematureJwtException |
                    UnsupportedJwtException e) {
                resultHandler.handle(ServiceException.fail(
                        500, "Unknown error: " + e.getMessage()));

                verificationFuture.fail(e);
            }
        }, false, result -> {
            logger.debug("Result: " + result.succeeded());

            if (result.failed()) {
                logger.error("Verification failed!", result.cause());
            }
        });

        return this;
    }

    private void failedVerify(Future<Object> verificationFuture,
                              Handler<AsyncResult<Jws<Claims>>> resultHandler,
                              AsyncResult<String> jwts, String userId, String id) {
        resultHandler.handle(ServiceException.fail(
                401, "Invalid JWT..."));
        verificationFuture.fail(jwts.cause());

        logger.error("Could not validate JWT! user: " + userId + ", id: " + id);
    }

    public boolean verifyAuthorization(Jws<Claims> claims, Authorization authorization) throws IllegalAccessException {
        return authorizer.authorize(claims, domainIdentifier, authorization);
    }

    @Fluent
    @Override
    public VerificationServiceImpl verifyAuthorization(Jws<Claims> claims, Authorization authorization,
                                                       Handler<AsyncResult<Boolean>> resultHandler)
            throws IllegalAccessException {
        if (authorizer.isAsync()) {
            authorizer.authorize(claims, domainIdentifier, authorization, resultHandler);
        } else {
            if (authorizer.authorize(claims, domainIdentifier, authorization)) {
                resultHandler.handle(Future.succeededFuture(Boolean.TRUE));
            } else {
                resultHandler.handle(Future.failedFuture(new SecurityException("You are not authorized!")));
            }
        }

        return this;
    }

    @Fluent
    @Override
    public VerificationService revokeToken(@Nonnull String token,
                                           @Nonnull Handler<AsyncResult<Boolean>> resultHandler) {
        verifyToken(token, verifyResult -> {
            if (verifyResult.failed()) {
                logger.error("Could not verify JWT for revoke...", verifyResult.cause());

                resultHandler.handle(ServiceException.fail(401, "Could not verify JWT..."));
            } else {
                Jws<Claims> claims = verifyResult.result();
                final String userId = claims.getBody().getSubject();
                final String id = claims.getBody().getId();
                final String registry = userId + VALID_JWT_REGISTRY_KEY;

                doGarbageCollectionAfterRevoke(registry, id, resultHandler);
            }
        });

        return this;
    }

    @SuppressWarnings("UnusedReturnValue")
    public VerificationService revokeUser(@Nonnull String userId,
                                          @Nonnull Handler<AsyncResult<Boolean>> resultHandler) {
        final String registry = userId + VALID_JWT_REGISTRY_KEY;

        purgeJWTsOnUser(registry, resultHandler);

        return this;
    }

    private void doGarbageCollectionAfterRevoke(String registry, String id,
                                                Handler<AsyncResult<Boolean>> resultHandler) {
        RedisUtils.performJedisWithRetry(redisClient, intRedis -> {
            RedisTransaction transaction = intRedis.transaction();

            transaction.multi(multiResult -> transaction.hget(registry, id, tokenResult -> {
                if (tokenResult.failed()) {
                    logger.error("Unable to delete refreshtoken for revoked JWT!");
                } else {
                    String[] refreshArray = tokenResult.result().split(REFRESH_TOKEN_SPLITTER);

                    transaction.del(refreshArray[0], delResult -> {
                        if (delResult.failed()) {
                            logger.error("Del RefreshToken failed!", delResult.cause());
                        }
                    });

                    transaction.hdel(registry, id, delJwtValidityResult -> {
                        if (delJwtValidityResult.failed()) {
                            logger.error("Del JwtValidity failed!", delJwtValidityResult.cause());
                        }
                    });
                }
            }));

            transaction.exec(execResult -> {
                if (execResult.failed()) {
                    logger.error("Failed Destroy transaction!", execResult.cause());

                    resultHandler.handle(ServiceException.fail(
                            500, "Failed revoking old token..."));
                } else {
                    resultHandler.handle(Future.succeededFuture(Boolean.TRUE));
                }
            });
        });
    }

    private void purgeJWTsOnUser(String registry, Handler<AsyncResult<Boolean>> resultHandler) {
        RedisUtils.performJedisWithRetry(redisClient, intRedis -> {
            RedisTransaction transaction = intRedis.transaction();

            transaction.multi(multiResult -> transaction.hgetall(registry, tokenResult -> {
                if (tokenResult.failed()) {
                    logger.error("Unable to delete refreshtoken for revoked JWT!");
                } else {
                    if (tokenResult.result() == null) {
                        logger.debug("Token List is empty!");
                    } else {
                        try {
                            final Object content = tokenResult.result();

                            if (content.toString().equalsIgnoreCase("{}")) {
                                logger.debug("Empty object!");
                            } else {
                                final JsonObject arrayOfStrings = new JsonObject(content.toString());
                                
                                arrayOfStrings.forEach(stringObjectEntry -> {
                                    String key = stringObjectEntry.getKey();
                                    Object value = stringObjectEntry.getValue();
                                    String[] refreshArray = value.toString().split(REFRESH_TOKEN_SPLITTER);

                                    transaction.del(refreshArray[0], delResult -> {
                                        if (delResult.failed()) {
                                            logger.error("Failed invalidating: " + value, delResult.cause());
                                        }
                                    });

                                    transaction.hdel(registry, key, delResult -> {
                                        if (delResult.failed()) {
                                            logger.error("Failed invalidating jwt: " + key, delResult.cause());
                                        }
                                    });
                                });
                            }
                        } catch (Exception e) {
                            logger.error("Error performing revocation!", e);
                        }
                    }
                }
            }));

            transaction.exec(execResult -> {
                if (execResult.failed()) {
                    logger.error("Failed Destroy transaction!", execResult.cause());

                    resultHandler.handle(ServiceException.fail(
                            500, "Failed revoking all tokens..."));
                } else {
                    resultHandler.handle(Future.succeededFuture(Boolean.TRUE));
                }
            });
        });
    }

    @Fluent
    @Override
    public VerificationService verifyJWTValidity(@Nonnull Handler<AsyncResult<Boolean>> resultHandler) {
        fetchUserIds(fetchRes -> {
            if (fetchRes.failed()) {
                logger.error("Could not read userids...", fetchRes.cause());
            } else {
                fetchRes.result().forEach(id -> RedisUtils.performJedisWithRetry(redisClient, intRedis -> {
                    String registryKey = id + VALID_JWT_REGISTRY_KEY;

                    intRedis.hgetall(registryKey, jwts -> {
                        if (jwts.failed()) {
                            logger.error("Could not read jwts for " + id, jwts.cause());
                        } else {
                            checkJwts(jwts.result(), id, registryKey, intRedis);
                        }
                    });
                }));
            }
        });

        return this;
    }

    private void fetchUserIds(Handler<AsyncResult<List<String>>> resultHandler) {
        userIdsSupplier.get().setHandler(idsRes -> {
            if (idsRes.failed()) {
                resultHandler.handle(Future.failedFuture(idsRes.cause()));
            } else {
                resultHandler.handle(Future.succeededFuture(idsRes.result()));
            }
        });
    }

    private void checkJwts(JsonObject jwtsObject, String userId, String registryKey, RedisClient intRedis) {
        if (jwtsObject != null) {
            jwtsObject.forEach(stringObjectEntry -> {
                String key = stringObjectEntry.getKey();
                Object value = stringObjectEntry.getValue();
                String[] refreshArray = value.toString().split(REFRESH_TOKEN_SPLITTER);

                long date = Long.parseLong(refreshArray[1]);
                Calendar tokenTime = Calendar.getInstance();
                tokenTime.setTimeInMillis(date);

                if (tokenTime.before(Calendar.getInstance())) {
                    logger.debug("Invalidating outdated token: " + value);

                    intRedis.del(refreshArray[0], delResult -> {
                        if (delResult.failed()) {
                            logger.error("Failed invalidating: " + value, delResult.cause());
                        }
                    });

                    intRedis.hdel(registryKey, key, delResult -> {
                        if (delResult.failed()) {
                            logger.error("Failed invalidating jwt: " + key, delResult.cause());
                        }
                    });
                }
            });
        } else {
            logger.error("JWT List for " + userId + " is null...",
                    new NullPointerException("UserId is Null!"));
        }
    }

    @Override
    public void close() {
        redisClient.close(closeResult -> logger.debug("Closed Redis for Service: " + closeResult.succeeded()));
    }
}
