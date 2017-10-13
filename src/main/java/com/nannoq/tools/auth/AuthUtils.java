package com.nannoq.tools.auth;

import com.nannoq.tools.auth.models.AuthPackage;
import com.nannoq.tools.auth.models.TokenContainer;
import com.nannoq.tools.auth.models.UserProfile;
import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.services.AuthenticationService;
import com.nannoq.tools.auth.services.VerificationService;
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

import java.util.function.Consumer;

/**
 * File: AuthUtils
 * Project: data-api
 * Package: com.noriginmedia.norigintube.api.service
 * <p>
 * This class
 *
 * @author anders
 * @version 3/3/16
 */
public class AuthUtils {
    private static final Logger logger = LoggerFactory.getLogger(AuthUtils.class.getSimpleName());

    private static final String AUTH_AUTH_CIRCUTBREAKER_NAME = "com.auth.auth.circuitbreaker";
    private static final String AUTH_VERIFY_CIRCUTBREAKER_NAME = "com.auth.verify.circuitbreaker";

    public static final String USER_IDENTIFIER = "userId";
    public static final String USER_TYPE = "userType";

    private static final String USER_NOT_VERIFIED = "NOT_VERIFIED";

    private static final String AUTH_API_BASE = "/auth";
    private static final String AUTH_TOKEN_ENDPOINT = "/auth/api/oauth2/auth/convert";
    private static final String AUTH_VERIFY_ENDPOINT = "/auth/api/oauth2/verify";

    private CircuitBreaker authAuthCircuitBreaker;
    private CircuitBreaker authVerifyCircuitBreaker;

    private MessageConsumer<JsonObject> authCircuitBreakerEvents;
    private MessageConsumer<JsonObject> verifyCircuitBreakerEvents;

    private final Vertx vertx;
    private final boolean external;
    private final APIManager apiManager;

    private static AuthUtils instance = null;

    private AuthUtils(boolean external) {
        this.external = external;
        vertx = Vertx.currentContext().owner();

        logger.info("Initializing AuthUtils...");

        JsonObject appConfig = vertx.getOrCreateContext().config();
        apiManager = new APIManager(vertx, appConfig);

        prepareCircuitBreakers();
        prepareListeners();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            authCircuitBreakerEvents.unregister();
            verifyCircuitBreakerEvents.unregister();
        }));

        logger.info("AuthUtils initialized...");
    }

    public static AuthUtils getInstance(boolean external) {
        if (instance == null) {
            instance = new AuthUtils(external);
        }

        return instance;
    }

    public static AuthUtils getInstance() {
        return getInstance(false);
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
    public AuthUtils convertExternalToken(String token, String provider, String feedIdentifier, String authOrigin,
                                          Handler<AsyncResult<AuthPackage>> resultHandler) {
        logger.debug("Auth request ready for: " + provider);

        if (token == null) {
            logger.error("Token cannot be null!");

            resultHandler.handle(Future.failedFuture("Token cannot be null!"));
        } else {
            Consumer<Throwable> backup = v -> httpAuthBackUp(token, provider, feedIdentifier, httpResult -> {
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
                        attemptAuthConversionOnEventBus(fut, service, token, provider, feedIdentifier, authOrigin),
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
                                                 String token, String provider, String feedIdentifier,
                                                 String authOrigin) {
        authenticationService.createJwtFromProvider(token, provider, feedIdentifier, authOrigin, conversionResult -> {
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

    private void httpAuthBackUp(String token, String provider, String feedIdentifier,
                                Handler<AsyncResult<AuthPackage>> resultHandler) {
        logger.debug("Running HTTP Auth Backup...");

        ServiceManager.getInstance().consumeApi(AUTH_API_BASE, apiResult -> {
            if (apiResult.failed()) {
                logger.error("HTTP Backup unavailable...");

                resultHandler.handle(ServiceException.fail(502, "Service not available..."));
            } else {
                String endpoint = AUTH_TOKEN_ENDPOINT + "/" + feedIdentifier;

                apiManager.performRequestWithCircuitBreaker(AUTH_API_BASE, resultHandler, authFuture -> {
                    HttpClientRequest req = apiResult.result().get(endpoint, httpClientResponse -> {
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

                                AuthPackage authPackage = new AuthPackage(
                                        jsonObjectBody.getString("feedId"), jsonObjectBody.getString("userType"),
                                        tokenContainer, userProfile);

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
    public AuthUtils authenticateAndAuthorize(String jwt, String authTypeToken,
                                              Handler<AsyncResult<VerifyResult>> resultHandler) {
        logger.debug("Auth request ready: " + authTypeToken);

        if (jwt == null) {
            logger.error("JWT cannot be null!");

            resultHandler.handle(Future.failedFuture("JWT cannot be null!"));
        } else {
            Consumer<Throwable> backup = v -> httpVerifyBackUp(jwt, authTypeToken, httpResult -> {
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
                        }, fut -> attemptAuthOnEventBus(fut, service, jwt, authTypeToken),
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
                                       String jwt, String authTypeToken) {
        logger.debug("Running Auth on Eventbus, attempt: " + authVerifyCircuitBreaker.failureCount());

        verificationService.verifyJWT(jwt, authTypeToken, verificationResult -> {
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

    private void httpVerifyBackUp(String jwt, String authTypeToken, Handler<AsyncResult<VerifyResult>> resultHandler) {
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
                    req.putHeader("X-Authorization-Type", authTypeToken);
                    req.setTimeout(5000L);
                    req.end();
                }, e -> resultHandler.handle(Future.failedFuture(USER_NOT_VERIFIED)));
            }
        });
    }
}
