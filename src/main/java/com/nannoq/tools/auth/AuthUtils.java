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
 *
 */

package com.nannoq.tools.auth;

import com.nannoq.tools.auth.models.AuthPackage;
import com.nannoq.tools.auth.models.TokenContainer;
import com.nannoq.tools.auth.models.UserProfile;
import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.services.AuthenticationService;
import com.nannoq.tools.auth.services.VerificationService;
import com.nannoq.tools.auth.utils.Authorization;
import com.nannoq.tools.cluster.CircuitBreakerUtils;
import com.nannoq.tools.cluster.apis.APIManager;
import com.nannoq.tools.cluster.services.ServiceManager;
import io.vertx.circuitbreaker.CircuitBreaker;
import io.vertx.circuitbreaker.CircuitBreakerOptions;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.serviceproxy.ServiceException;

import java.util.Base64;
import java.util.function.Consumer;

/**
 * This class is used for doing most auth options from a client perspective. It has evnetbus and http logic, with retry
 * backups by circuitbreaker.
 *
 * @author Anders Mikkelsen
 * @version 3/3/16
 */
public class AuthUtils {
    private static final Logger logger = LoggerFactory.getLogger(AuthUtils.class.getSimpleName());

    private static final String AUTH_AUTH_CIRCUTBREAKER_NAME = "com.auth.auth.circuitbreaker";
    private static final String AUTH_VERIFY_CIRCUTBREAKER_NAME = "com.auth.verify.circuitbreaker";

    public static final String USER_IDENTIFIER = "userId";

    private static final String USER_NOT_VERIFIED = "NOT_VERIFIED";

    private static final String AUTH_API_BASE = "AUTH";
    private final String AUTH_TOKEN_ENDPOINT;
    private final String AUTH_VERIFY_ENDPOINT;

    private CircuitBreaker authAuthCircuitBreaker;
    private CircuitBreaker authVerifyCircuitBreaker;

    private MessageConsumer<JsonObject> authCircuitBreakerEvents;
    private MessageConsumer<JsonObject> verifyCircuitBreakerEvents;

    private final Vertx vertx;
    private final APIManager apiManager;

    private static AuthUtils instance = null;


    private AuthUtils() {
        this(Vertx.currentContext().config());
    }

    private AuthUtils(JsonObject appConfig) {
        this(Vertx.currentContext().owner(), appConfig);
    }
    
    private AuthUtils(Vertx vertx, JsonObject appConfig) {
        this.vertx = vertx;

        logger.info("Initializing AuthUtils...");

        apiManager = new APIManager(vertx, appConfig);
        AUTH_TOKEN_ENDPOINT = appConfig.getString("authTokenEndpoint");
        AUTH_VERIFY_ENDPOINT = appConfig.getString("authVerifyEndpoint");

        prepareCircuitBreakers();
        prepareListeners();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            authCircuitBreakerEvents.unregister();
            verifyCircuitBreakerEvents.unregister();
        }));

        logger.info("AuthUtils initialized...");
    }

    public static AuthUtils getInstance() {
        if (instance == null) {
            instance = new AuthUtils();
        }

        return instance;
    }

    private void prepareCircuitBreakers() {
        authAuthCircuitBreaker = CircuitBreaker.create(AUTH_AUTH_CIRCUTBREAKER_NAME, vertx,
                new CircuitBreakerOptions()
                        .setMaxFailures(3)
                        .setTimeout(3000)
                        .setFallbackOnFailure(true)
                        .setResetTimeout(10000)
                        .setNotificationAddress(AUTH_AUTH_CIRCUTBREAKER_NAME)
                        .setNotificationPeriod(60000L * 60 * 6))
                .openHandler(v -> logger.info(AUTH_AUTH_CIRCUTBREAKER_NAME + " OPEN"))
                .halfOpenHandler(v -> logger.info(AUTH_AUTH_CIRCUTBREAKER_NAME + " HALF-OPEN"))
                .closeHandler(v -> logger.info(AUTH_AUTH_CIRCUTBREAKER_NAME + " CLOSED"));
        authAuthCircuitBreaker.close();

        authVerifyCircuitBreaker = CircuitBreaker.create(AUTH_VERIFY_CIRCUTBREAKER_NAME, vertx,
                new CircuitBreakerOptions()
                        .setMaxFailures(3)
                        .setTimeout(1000)
                        .setFallbackOnFailure(true)
                        .setResetTimeout(10000)
                        .setNotificationAddress(AUTH_VERIFY_CIRCUTBREAKER_NAME)
                        .setNotificationPeriod(60000L * 60 * 6))
                .openHandler(v -> logger.info(AUTH_VERIFY_CIRCUTBREAKER_NAME + " OPEN"))
                .halfOpenHandler(v -> logger.info(AUTH_AUTH_CIRCUTBREAKER_NAME + " HALF-OPEN"))
                .closeHandler(v -> logger.info(AUTH_VERIFY_CIRCUTBREAKER_NAME + " CLOSED"));
        authVerifyCircuitBreaker.close();
    }

    private void prepareListeners() {
        authCircuitBreakerEvents = vertx.eventBus().consumer(AUTH_AUTH_CIRCUTBREAKER_NAME, message ->
                CircuitBreakerUtils.handleCircuitBreakerEvent(authAuthCircuitBreaker, message));

        verifyCircuitBreakerEvents = vertx.eventBus().consumer(AUTH_VERIFY_CIRCUTBREAKER_NAME, message ->
                CircuitBreakerUtils.handleCircuitBreakerEvent(authVerifyCircuitBreaker, message));
    }

    @Fluent
    public AuthUtils convertExternalToken(String token, String provider, Handler<AsyncResult<AuthPackage>> resultHandler) {
        logger.debug("Auth request ready for: " + provider);

        if (token == null) {
            logger.error("Token cannot be null!");

            resultHandler.handle(Future.failedFuture("Token cannot be null!"));
        } else {
            Consumer<Throwable> backup = v -> httpAuthBackUp(token, provider, httpResult -> {
                logger.debug("Launching http backup...");

                if (httpResult.failed()) {
                    resultHandler.handle(Future.failedFuture(httpResult.cause()));
                } else {
                    resultHandler.handle(Future.succeededFuture(httpResult.result()));
                }
            });

            getAuthenticationService().compose(service -> {
                logger.debug("Running Eventbus Auth...");

                CircuitBreakerUtils.performRequestWithCircuitBreaker(authAuthCircuitBreaker, resultHandler, fut ->
                        attemptAuthConversionOnEventBus(fut, service, token, provider),
                        backup);
            }, Future.future().setHandler(failure -> backup.accept(failure.cause())));
        }

        return this;
    }

    private Future<AuthenticationService> getAuthenticationService() {
        Future<AuthenticationService> authenticationServiceFuture = Future.future();

        ServiceManager.getInstance().consumeService(AuthenticationService.class, fetchResult -> {
            if (fetchResult.failed()) {
                logger.error("Failed Auth Service fetch...");

                authenticationServiceFuture.fail(fetchResult.cause());
            } else {
                authenticationServiceFuture.complete(fetchResult.result());
            }
        });

        return authenticationServiceFuture;
    }

    private void attemptAuthConversionOnEventBus(Future<AuthPackage> authFuture,
                                                 AuthenticationService authenticationService,
                                                 String token, String provider) {
        authenticationService.createJwtFromProvider(token, provider, conversionResult -> {
            if (authFuture.isComplete()) {
                logger.error("Ignoring result, authFuture already completed: " + conversionResult.cause());
            } else {
                if (conversionResult.failed()) {
                    logger.error("Conversion failed!");

                    if (conversionResult.cause() instanceof ServiceException) {
                        ServiceManager.handleResultFailed(conversionResult.cause());
                        authFuture.complete(null);
                    } else {
                        authFuture.fail(conversionResult.cause());
                    }
                } else {
                    logger.debug("Conversion ok, returning result...");

                    authFuture.complete(conversionResult.result());
                }
            }
        });
    }

    private void httpAuthBackUp(String token, String provider,
                                Handler<AsyncResult<AuthPackage>> resultHandler) {
        logger.debug("Running HTTP Auth Backup...");

        ServiceManager.getInstance().consumeApi(AUTH_API_BASE, apiResult -> {
            if (apiResult.failed()) {
                logger.error("HTTP Backup unavailable...");

                resultHandler.handle(ServiceException.fail(502, "Service not available..."));
            } else {
                apiManager.performRequestWithCircuitBreaker(AUTH_API_BASE, resultHandler, authFuture -> {
                    HttpClientRequest req = apiResult.result().get(AUTH_TOKEN_ENDPOINT, httpClientResponse -> {
                        if (httpClientResponse.statusCode() == 401) {
                            logger.error("UNAUTHORIZED IN HTTP AUTH");

                            authFuture.fail("Unauthorized...");
                        } else {
                            httpClientResponse.bodyHandler(responseData -> {
                                logger.debug("Received: " + responseData.toString() + " from auth.");

                                JsonObject jsonObjectBody = responseData.toJsonObject();

                                logger.debug("AUTH FROM HTTP IS: " + Json.encodePrettily(jsonObjectBody));

                                TokenContainer tokenContainer = Json.decodeValue(
                                        jsonObjectBody.getJsonObject("tokenContainer")
                                                .toString(), TokenContainer.class);
                                UserProfile userProfile = Json.decodeValue(
                                        jsonObjectBody.getJsonObject("userProfile").toString(), UserProfile.class);

                                AuthPackage authPackage = new AuthPackage(tokenContainer, userProfile);

                                authFuture.complete(authPackage);

                                logger.debug("Auth result returned...");
                            });
                        }
                    }).exceptionHandler(message -> {
                        logger.error("HTTP Auth ERROR: " + message);

                        authFuture.fail(message);
                    });

                    req.putHeader("Authorization", "Bearer " + token);
                    req.putHeader("X-Authorization-Provider", provider);
                    req.setTimeout(5000L);
                    req.end();
                }, e -> resultHandler.handle(Future.failedFuture(USER_NOT_VERIFIED)));
            }
        });
    }

    @Fluent
    @SuppressWarnings({"ThrowableResultOfMethodCallIgnored", "unchecked"})
    public AuthUtils authenticateAndAuthorize(String jwt, Authorization authorization,
                                              Handler<AsyncResult<VerifyResult>> resultHandler) {
        logger.debug("Auth request ready: " + authorization.toJson().encodePrettily());

        if (jwt == null) {
            logger.error("JWT cannot be null!");

            resultHandler.handle(Future.failedFuture("JWT cannot be null!"));
        } else {
            Consumer<Throwable> backup = v -> httpVerifyBackUp(jwt, authorization, httpResult -> {
                logger.debug("Received HTTP Verify Result: " + httpResult.succeeded());

                if (httpResult.failed()) {
                    resultHandler.handle(Future.failedFuture(httpResult.cause()));
                } else {
                    resultHandler.handle(Future.succeededFuture(httpResult.result()));
                }
            });

            getVerificationService().compose(service -> {
                logger.debug("Running Eventbus Auth...");

                CircuitBreakerUtils.<VerifyResult>performRequestWithCircuitBreaker(authAuthCircuitBreaker, authRes -> {
                            if (authRes.failed()) {
                                resultHandler.handle(ServiceException.fail(500, "Unknown error..."));
                            } else {
                                if (authRes.result() == null) {
                                    resultHandler.handle(ServiceException.fail(401, "Not authorized!"));
                                } else {
                                    resultHandler.handle(Future.succeededFuture(authRes.result()));
                                }
                            }
                        }, fut -> attemptAuthOnEventBus(fut, service, jwt, authorization),
                        backup);
            }, Future.future().setHandler(failure -> backup.accept(failure.cause())));
        }

        return this;
    }

    private Future<VerificationService> getVerificationService() {
        Future<VerificationService> verificationServiceFuture = Future.future();

        ServiceManager.getInstance().consumeService(VerificationService.class, fetchResult -> {
            if (fetchResult.failed()) {
                logger.error("Failed Verification Service fetch...");

                verificationServiceFuture.fail(fetchResult.cause());
            } else {
                verificationServiceFuture.complete(fetchResult.result());
            }
        });

        return verificationServiceFuture;
    }

    private void attemptAuthOnEventBus(Future<VerifyResult> authFuture, VerificationService verificationService,
                                       String jwt, Authorization authorization) {
        logger.debug("Running Auth on Eventbus, attempt: " + authVerifyCircuitBreaker.failureCount());

        verificationService.verifyJWT(jwt, authorization, verificationResult -> {
            if (authFuture.isComplete()) {
                logger.error("Ignoring result, authFuture already completed:" + verificationResult.cause());
            } else {
                if (verificationResult.failed()) {
                    logger.error("Failed verification service...");

                    if (verificationResult.cause() instanceof ServiceException) {
                        ServiceManager.handleResultFailed(verificationResult.cause());
                        ServiceException se = (ServiceException) verificationResult.cause();

                        if (se.failureCode() == 401) {
                            authFuture.complete(null);
                        } else {
                            authFuture.fail(verificationResult.cause());
                        }
                    } else {
                        logger.error(verificationResult.cause());

                        authFuture.fail(verificationResult.cause());
                    }
                } else {
                    VerifyResult verifyResult = verificationResult.result();

                    if (verifyResult != null) {
                        logger.debug("Authenticated!");
                        logger.debug(Json.encodePrettily(verifyResult));

                        authFuture.complete(verifyResult);
                    } else {
                        logger.error("Access Denied!");

                        authFuture.fail(verificationResult.cause());
                    }
                }
            }
        });
    }

    private void httpVerifyBackUp(String jwt, Authorization authorization,
                                  Handler<AsyncResult<VerifyResult>> resultHandler) {
        logger.debug("Running HTTP Verify Backup...");

        ServiceManager.getInstance().consumeApi(AUTH_API_BASE, apiResult -> {
            if (apiResult.failed()) {
                logger.error("HTTP Backup unavailable...");

                resultHandler.handle(ServiceException.fail(502, "Service not available..."));
            } else {
                apiManager.performRequestWithCircuitBreaker(AUTH_API_BASE, resultHandler, authFuture -> {
                    HttpClientRequest req = apiResult.result().get(AUTH_VERIFY_ENDPOINT, httpClientResponse -> {
                        if (httpClientResponse.statusCode() == 200) {
                            httpClientResponse.bodyHandler(bodyResult -> {
                                logger.debug("Auth Success!");

                                JsonObject bodyAsJson = bodyResult.toJsonObject();

                                logger.debug("Auth body: " + Json.encodePrettily(bodyAsJson));

                                VerifyResult verifyResult = Json.decodeValue(bodyAsJson.encode(), VerifyResult.class);

                                authFuture.complete(verifyResult);
                            });
                        } else {
                            authFuture.fail("User not authenticated!");
                        }
                    }).exceptionHandler(message -> {
                        logger.error("HTTP Auth ERROR: " + message);

                        authFuture.fail(message);
                    });

                    req.putHeader("Authorization", "Bearer " + jwt);
                    req.putHeader("X-Authorization-Type",
                            new String(Base64.getEncoder().encode(authorization.toJson().encode().getBytes())));
                    req.setTimeout(5000L);
                    req.end();
                }, e -> resultHandler.handle(Future.failedFuture(USER_NOT_VERIFIED)));
            }
        });
    }
}
