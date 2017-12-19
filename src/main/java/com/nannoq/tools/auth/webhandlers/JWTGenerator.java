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

package com.nannoq.tools.auth.webhandlers;

import com.nannoq.tools.auth.models.AuthPackage;
import com.nannoq.tools.auth.models.TokenContainer;
import com.nannoq.tools.auth.services.AuthenticationService;
import com.nannoq.tools.auth.services.AuthenticationServiceImpl;
import com.nannoq.tools.auth.utils.AuthPackageHandler;
import com.nannoq.tools.cluster.apis.APIManager;
import com.nannoq.tools.cluster.services.ServiceManager;
import com.nannoq.tools.repository.repository.redis.RedisUtils;
import facebook4j.Facebook;
import facebook4j.FacebookException;
import facebook4j.FacebookFactory;
import facebook4j.auth.AccessToken;
import facebook4j.conf.ConfigurationBuilder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;
import io.vertx.redis.RedisClient;
import org.jinstagram.auth.InstagramAuthService;
import org.jinstagram.auth.oauth.InstagramService;
import org.jsoup.Jsoup;
import org.jsoup.safety.Whitelist;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

import static com.nannoq.tools.auth.services.AuthenticationServiceImpl.*;
import static com.nannoq.tools.auth.utils.AuthFutures.*;
import static com.nannoq.tools.web.requestHandlers.RequestLogHandler.REQUEST_LOG_TAG;
import static com.nannoq.tools.web.requestHandlers.RequestLogHandler.addLogMessageToRequestLog;
import static com.nannoq.tools.web.responsehandlers.ResponseLogHandler.BODY_CONTENT_TAG;

/**
 * This class defines a Handler implementation that receives all traffic for endpoints that handle JWT generator, e.g.
 * authentication.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class JWTGenerator implements Handler<RoutingContext> {
    private final Logger logger = LoggerFactory.getLogger(JWTGenerator.class.getSimpleName());

    private final String CMS_ROOT;
    private final String GOOGLE_AUTH_URL;
    private final String YOUTUBE_AUTH_URL;

    private final Vertx vertx;
    private final JsonObject appConfig;
    private final String domainIdentifier;
    private final RedisClient redisClient;
    private final AuthenticationServiceImpl authenticator;
    private final AuthPackageHandler authPackageHandler;
    private final String callbackUrl;

    public JWTGenerator(@Nonnull Vertx vertx, @Nonnull JsonObject appConfig,
                        @Nonnull AuthenticationServiceImpl authenticator,
                        @Nonnull AuthPackageHandler authPackageHandler,
                        @Nonnull String domainIdentifier) {
        this.vertx = vertx;
        this.appConfig = appConfig;
        this.domainIdentifier = domainIdentifier;
        this.redisClient = RedisUtils.getRedisClient(vertx, appConfig);
        this.authenticator = authenticator;
        this.authPackageHandler = authPackageHandler;

        String googleClientId = appConfig.getString("googleClientId");
        String CALL_BACK_PROVIDER_URL = appConfig.getString("callbackProviderUrl");
        this.callbackUrl = appConfig.getString("callBackRoot") + CALL_BACK_PROVIDER_URL;

        CMS_ROOT = appConfig.getString("callBackRoot");
        GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth?" +
                "scope=openid%20email%20profile&" +
                "state=:stateToken&" +
                "redirect_uri=" + CMS_ROOT + "/auth/api/oauth2/auth/google&" +
                "response_type=code&" +
                "client_id=" + googleClientId + "&" +
                "prompt=consent&" +
                "include_granted_scopes=true&" +
                "access_type=offline";

        YOUTUBE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth?" +
                "scope=https://www.googleapis.com/auth/youtube.readonly&" +
                "state=:stateToken&" +
                "redirect_uri=" + CMS_ROOT + "/auth/api/oauth2/auth/verification/providers/youtube&" +
                "response_type=code&" +
                "client_id=" + googleClientId + "&" +
                "prompt=consent&" +
                "include_granted_scopes=true&" +
                "access_type=online";
    }

    @Override
    public void handle(RoutingContext routingContext) {
        HttpServerRequest request = routingContext.request();

        String authToken = request.getParam("code");
        String authProvider = request.getParam("provider");

        if (authProvider != null && authToken != null) {
            switch (authProvider.toUpperCase()) {
                case INSTAGRAM:
                    handleAccessToken(authProvider, "Bearer " + authToken, routingContext);

                    break;
                case FACEBOOK:
                    handleFacebookAuth(routingContext, authToken, authProvider);

                    break;
                case GOOGLE:
                    handleGoogleAuth(routingContext, authToken, authProvider);

                    break;
                default:
                    unAuthorized(routingContext);

                    logger.error("Unknown auth provider for Auth Flow...");
                    break;
            }
        } else {
            unAuthorized(routingContext);

            logger.error("Unknown request...");
        }
    }

    private void handleGoogleAuth(RoutingContext routingContext, String authToken, String authProvider) {
        logger.info("Authing for google...");

        Handler<AsyncResult<String>> resultHandler = authResult -> {
            if (authResult.succeeded()) {
                if (authResult.result() != null) {
                    logger.info("Completed Google Auth...");

                    handleAccessToken(authProvider, "Bearer " + authResult.result(), routingContext);
                } else {
                    logger.error("Failed Google Auth...", authResult.cause());

                    unAuthorized(routingContext);
                }
            } else {
                logger.error("Failed Google Auth...", authResult.cause());

                unAuthorized(routingContext);
            }
        };

        HttpClientOptions opts = new HttpClientOptions().setSsl(true);
        HttpClientRequest req = vertx.createHttpClient(opts)
                .post(443, "www.googleapis.com", "/oauth2/v4/token")
                .putHeader("Content-Type", "application/x-www-form-urlencoded");

        Handler<Future<String>> authHandler = authFuture -> req.handler(response -> {
            if (response.statusCode() >= 200 && response.statusCode() < 400) {
                logger.info("Google Status is: " + response.statusCode());

                response.bodyHandler(body -> {
                    JsonObject res = body.toJsonObject();

                    authFuture.complete(res.getString("id_token"));
                });
            } else {
                logger.error(response.statusCode());
                logger.error(response.statusMessage());
                logger.error(response.bodyHandler(body -> {
                    logger.error("UNAUTHORIZED!");

                    logger.error(Json.encodePrettily(body.toJsonObject()));

                    authFuture.fail(new UnknownError(response.statusMessage()));
                }));
            }
        }).end("code=" + authToken + "&" +
                "client_id=" + appConfig.getString("googleClientId") + "&" +
                "client_secret=" + appConfig.getString("googleClientSecret") + "&" +
                "redirect_uri=" + callbackUrl.replace(":provider", "google") +
                "&" + "grant_type=authorization_code");


        APIManager.performRequestWithCircuitBreaker(resultHandler, authHandler, fallBack -> {
            logger.error("Failed Google Auth...");

            unAuthorized(routingContext);
        });
    }

    private void handleFacebookAuth(RoutingContext routingContext, String authToken, String authProvider) {
        String appId = vertx.getOrCreateContext().config().getString("faceBookAppId");
        String appSecret = vertx.getOrCreateContext().config().getString("faceBookAppSecret");

        vertx.executeBlocking(future -> {
            ConfigurationBuilder cb = new ConfigurationBuilder();
            cb.setAppSecretProofEnabled(true);
            cb.setOAuthAppId(appId);
            cb.setOAuthAppSecret(appSecret);
            Facebook facebook = new FacebookFactory(cb.build()).getInstance();
            facebook.setOAuthCallbackURL(callbackUrl.replace(":provider", "facebook"));

            logger.info("Authing for facebook...");

            try {
                AccessToken token = facebook.getOAuthAccessToken(authToken);

                logger.info("Token is: " + token.getToken());

                handleAccessToken(authProvider, "Bearer " + token.getToken(), routingContext);
            } catch (FacebookException e) {
                logger.error("Failed Facebook Operation", e);

                unAuthorized(routingContext);
            }
        }, false, null);
    }

    public void directAuth(RoutingContext routingContext) {
        HttpServerRequest request = routingContext.request();

        StringBuffer sb = routingContext.get(REQUEST_LOG_TAG);
        String authToken = request.getHeader("Authorization");
        String authProvider = request.getHeader("X-Authorization-Provider");

        if (authToken != null && authProvider != null && authToken.startsWith("Bearer")) {
            String token = Jsoup.clean(authToken, Whitelist.none()).substring("Bearer".length()).trim();
            String upperedAuthProvider = Jsoup.clean(authProvider, Whitelist.none()).toUpperCase();

            authenticator.createJwtFromProvider(token, upperedAuthProvider, result -> {
                if (result.failed()) {
                    logger.error("AUTH Failed: " + sb.toString(), result.cause());

                    routingContext.response().setStatusCode(401);
                    routingContext.next();
                } else {
                    AuthPackage authPackage = result.result();

                    try {
                        String userId = authenticator.buildUserId(authPackage);

                        authPackageHandler.processDirectAuth(authPackage, userId, authPackageProcessResult -> {
                            if (authPackageProcessResult.failed()) {
                                logger.error("Failed processing Direct Auth!",
                                        authPackageProcessResult.cause());

                                routingContext.response().setStatusCode(422);
                                routingContext.next();
                            } else {
                                routingContext.response().setStatusCode(200);
                                routingContext.put(BODY_CONTENT_TAG, authPackageProcessResult.result().encode());
                                routingContext.next();
                            }
                        });
                    } catch (Exception e) {
                        logger.error("AUTH Failed: " + sb.toString(), e);

                        routingContext.response().setStatusCode(500);
                        routingContext.next();
                    }
                }
            });
        } else {
            logger.error("Invalid parameters!");

            JsonObject errorObject = new JsonObject();
            if (authToken == null) errorObject.put("header_error", "Authorization Header cannot be null!");
            if (authProvider == null) errorObject.put("header_error", "X-Authorization-Provider Header cannot be null!");
            if (domainIdentifier == null) errorObject.put("path_error", "FeedId cannot be null!");

            routingContext.put(BODY_CONTENT_TAG, errorObject.encodePrettily());
            routingContext.response().setStatusCode(401);
            routingContext.next();
        }
    }

    private void handleAccessToken(String authProvider, String authToken, RoutingContext routingContext) {
        getReceivedUserState(routingContext).compose(state ->
        getLocation(state).compose(location ->
        handleToken(authToken, state, location, authProvider).compose(authPackage ->
                finalizeResponse(location, state, authPackage, routingContext), authFailRedirect(routingContext)),
            authFailRedirect(routingContext)),
             authFailRedirect(routingContext));
    }

    @SuppressWarnings("ConstantConditions")
    private Future<AuthPackage> handleToken(String authToken, String state, String location, String authProvider) {
        Future<AuthPackage> authFuture = Future.future();

        if (authToken != null && authProvider != null && location != null) {
            if (authToken.startsWith("Bearer ")) {
                String token = authToken.substring("Bearer".length()).trim();
                authenticator.createJwtFromProvider(token, authProvider.toUpperCase(), result -> {
                    if (result.failed()) {
                        ServiceManager.handleResultFailed(result.cause());

                        authFuture.fail(CMS_ROOT + "#code=401&error=Unauthorized");
                    } else {
                        AuthPackage authPackage = result.result();
                        logger.info("Result is: " + Json.encodePrettily(authPackage));

                        purgeState(authProvider, state);

                        authFuture.complete(authPackage);
                    }
                });
            } else {
                authFuture.fail(CMS_ROOT + "#code=400&error=Invalid Auth headers");
            }
        } else {
            authFuture.fail(CMS_ROOT + "#code=401&error=Unauthorized");
        }

        return authFuture;
    }

    private void purgeState(String authProvider, String state) {
        RedisUtils.performJedisWithRetry(redisClient, intRedis -> intRedis.del(state, delResult ->
                        logger.info("Deleted state for " + state + " is " + delResult.result())));

        if (authProvider.toUpperCase().equals(INSTAGRAM)) {
            RedisUtils.performJedisWithRetry(redisClient, internalDeleteRedisClient -> internalDeleteRedisClient.del(
                    state + "_forUser", delResult ->
                            logger.info("Deleted state_forUser for " + state + " is " + delResult.result())));
        }
    }

    private Future<String> getLocation(String state) {
        Future<String> stateFuture = Future.future();

        RedisUtils.performJedisWithRetry(redisClient, intRedis -> intRedis.get(state, getResult -> {
            if (getResult.failed()) {
                stateFuture.fail(new InternalError(CMS_ROOT +
                        "#code=422&error=Unable to verify user state..."));
            } else {
                stateFuture.complete(getResult.result());
            }
        }));

        return stateFuture;
    }

    private Future<String> getReceivedUserState(RoutingContext routingContext) {
        Future<String> stateFuture = Future.future();
        String stateParam = routingContext.request().getParam("state");

        if (stateParam != null) {
            stateFuture.complete(stateParam);
        } else {
            stateFuture.fail(new IllegalArgumentException(CMS_ROOT +
                    "#code=400&error=State cannot be null from external"));
        }

        return stateFuture;
    }

    private void finalizeResponse(String url, String state, AuthPackage authPackage, RoutingContext routingContext) {
        logger.info("Building url for redirect...");

        final String finalUrl = url + "#state=" +
                state + "&jwt=" + authPackage.getTokenContainer().getAccessToken() +
                "&refresh_token=" + authPackage.getTokenContainer().getRefreshToken() +
                "&id=" + authPackage.getUserProfile().getUserId();

        logger.debug("Url is: " + finalUrl);

        String userId = authenticator.buildUserId(authPackage);

        authPackageHandler.processOAuthFlow(authPackage, userId, finalUrl, authPackageProcessResult -> {
            if (authPackageProcessResult.failed()) {
                routingContext.response()
                        .setStatusCode(302)
                        .putHeader(HttpHeaders.LOCATION, "#code=500&error=UNKNOWN")
                        .end();
            } else {
                JsonObject res = authPackageProcessResult.result();
                String location = res.getString("Location");

                routingContext.response()
                        .setStatusCode(302)
                        .putHeader(HttpHeaders.LOCATION, location)
                        .end();
            }
        });
    }

    public void returnAuthUrl(RoutingContext routingContext) {
        Consumer<String> success = location -> routingContext.response()
                .setStatusCode(302)
                .putHeader(HttpHeaders.LOCATION, location)
                .end();

        getProvider(routingContext).compose(provider ->
        getUserState(routingContext).compose(state ->
        getLocation(routingContext, state).compose(location ->
        setState(state, location).compose(v ->
        constructAuthUrl(routingContext, state, location, provider).compose(success::accept,
                authFailRedirect(routingContext)),
                authFailRedirect(routingContext)),
                authFailRedirect(routingContext)),
                denyRequest(routingContext)),
                denyRequest(routingContext));
    }

    public void returnProviderVerificationUrl(RoutingContext routingContext) {
        String feedId = routingContext.request().getParam("feedId");

        Consumer<String> success = location -> routingContext.response()
                .setStatusCode(302)
                .putHeader(HttpHeaders.LOCATION, location)
                .end();

        getProvider(routingContext).compose(provider ->
        getProviderId(routingContext).compose(providerId ->
        getUserState(routingContext).compose(state ->
        getLocation(routingContext, state).compose(location ->
        setState(state, location).compose(v ->
        constructVerificationUrl(state, location, feedId, provider, providerId).compose(success::accept,
                authFailRedirect(routingContext)),
                authFailRedirect(routingContext)),
                authFailRedirect(routingContext)),
                denyRequest(routingContext)),
                denyRequest(routingContext)),
                denyRequest(routingContext));
    }

    private Future<String> constructAuthUrl(RoutingContext routingContext, String state,
                                            String location, String provider) {
        Future<String> locationFuture = Future.future();

        switch (provider.toUpperCase()) {
            case INSTAGRAM:
                String forUserReference = routingContext.request().getParam("forUser");

                if (forUserReference != null) {
                    getInstagramUrl(state, forUserReference, location, urlResult -> {
                        if (urlResult.failed()) {
                            locationFuture.fail(new InternalError(urlResult.cause().getMessage()));
                        } else {
                            locationFuture.complete(urlResult.result());
                        }
                    });
                } else {
                    locationFuture.fail(new SecurityException(location +
                            "#code=400&error=" + "InstaGram does not support emails from API, " +
                            "and can only be federated into an established user. " +
                            "Please add id as email of the user to federate into as a " +
                            "query param with name \"forUser\"."));
                }
                break;
            case FACEBOOK:
                vertx.<String>executeBlocking(urlFuture -> {
                    JsonObject config = vertx.getOrCreateContext().config();
                    String appId = config.getString("faceBookAppId");
                    String appSecret = config.getString("faceBookAppSecret");

                    Facebook facebook = new FacebookFactory().getInstance();
                    facebook.setOAuthAppId(appId, appSecret);
                    facebook.setOAuthPermissions("public_profile,email,user_friends");

                    urlFuture.complete(facebook.getOAuthAuthorizationURL(
                            callbackUrl.replace(":provider", "facebook"), state));
                }, false, urlResult -> {
                    String url = urlResult.result();

                    if (url != null && !url.isEmpty()) {
                        locationFuture.complete(urlResult.result());
                    } else {
                        locationFuture.fail(new InternalError(location + "#code=500&error=Unknown"));
                    }
                });
                break;
            case GOOGLE:
                String authUrl = GOOGLE_AUTH_URL.replace(":stateToken", state);
                locationFuture.complete(authUrl);

                break;
            default:
                locationFuture.fail(location + "#code=400&error=Unknown");

                break;
        }

        return locationFuture;
    }

    private Future<String> constructVerificationUrl(String state, String location, String feedId,
                                                    String provider, String providerId) {
        Future<String> locationFuture = Future.future();

        switch (provider.toUpperCase()) {
            case INSTAGRAM:
                String clientId = appConfig.getString("instaClientId");
                String clientSecret = appConfig.getString("instaClientSecret");

                InstagramService instagram = new InstagramAuthService()
                        .apiKey(clientId)
                        .apiSecret(clientSecret)
                        .callback(callbackUrl.replace(":provider", "verification/providers/instagram"))
                        .scope("basic")
                        .build();

                locationFuture.complete(instagram.getAuthorizationUrl() + "&state=" + state +
                        "_PROVIDER_VERIFY_" + providerId + "_FEED_" + feedId);

                break;
            case FACEBOOK:
                vertx.<String>executeBlocking(urlFuture -> {
                    JsonObject config = vertx.getOrCreateContext().config();
                    String appId = config.getString("faceBookAppId");
                    String appSecret = config.getString("faceBookAppSecret");

                    Facebook facebook = new FacebookFactory().getInstance();
                    facebook.setOAuthAppId(appId, appSecret);
                    facebook.setOAuthPermissions("manage_pages");

                    urlFuture.complete(facebook.getOAuthAuthorizationURL(
                            callbackUrl.replace(":provider", "verification/providers/facebook"), state +
                                    "_PROVIDER_VERIFY_" + providerId + "_FEED_" + feedId));
                }, false, urlResult -> {
                    String url = urlResult.result();

                    if (url != null && !url.isEmpty()) {
                        locationFuture.complete(urlResult.result());
                    } else {
                        locationFuture.fail(new InternalError(location + "#code=500&error=Unknown"));
                    }
                });

                break;
            case YOUTUBE:
                String authUrl = YOUTUBE_AUTH_URL.replace(":stateToken", state + "_PROVIDER_VERIFY_" +
                        providerId + "_FEED_" + feedId);
                locationFuture.complete(authUrl);

                break;
            default:
                locationFuture.fail(location + "#code=400&error=Unknown");

                break;
        }

        return locationFuture;
    }

    private void getInstagramUrl(String state, String userRef, String location,
                                 Handler<AsyncResult<String>> resultHandler) {
        String finalState = state + "_forUser";

        RedisUtils.performJedisWithRetry(redisClient, internalRedis -> internalRedis.set(finalState, userRef, res -> {
            if (res.failed()) {
                logger.error("Cannot set forUser, aborting instagram...", res.cause());

                RedisUtils.performJedisWithRetry(redisClient, intRedis -> intRedis.del(state, delStateResult ->
                        logger.info("Deleted state for " + state + " is " + delStateResult.result()))
                );

                resultHandler.handle(Future.failedFuture(
                        location + "#code=500&error=Internal Server Error, Retry."));
            } else {
                String clientId = appConfig.getString("instaClientId");
                String clientSecret = appConfig.getString("instaClientSecret");

                InstagramService instagram = new InstagramAuthService()
                        .apiKey(clientId)
                        .apiSecret(clientSecret)
                        .callback(callbackUrl.replace(":provider", "instagram"))
                        .scope("basic public_content follower_list likes comments relationships")
                        .build();

                resultHandler.handle(Future.succeededFuture(
                        instagram.getAuthorizationUrl() + "&state=" + state));
            }
        }));
    }

    private Future<Void> setState(String state, String location) {
        Future<Void> voidFuture = Future.future();

        RedisUtils.performJedisWithRetry(redisClient, redis -> redis.set(state, location, setResults -> {
            if (setResults.failed()) {
                voidFuture.fail(new InternalError(location + "#code=500&error=Internal Server Error, Retry."));
            } else {
                voidFuture.complete();
            }
        }));

        return voidFuture;
    }

    private Future<String> getLocation(RoutingContext routingContext, String state) {
        Future<String> locationFuture = Future.future();

        String location = routingContext.request().getParam("location");
        if (location == null) location = CMS_ROOT;

        if (state == null || state.length() < 30) {
            locationFuture.fail(new IllegalArgumentException(location + "#code=400&error=" +
                    "Must have a state query param, containing a random or " +
                    "pseudo-random string of at least 30 characters."));
        } else {
            locationFuture.complete(location);
        }

        return locationFuture;
    }

    private Future<String> getProvider(RoutingContext routingContext) {
        Future<String> providerFuture = Future.future();
        String provider = routingContext.request().getParam("provider");

        if (provider == null) {
            providerFuture.fail(new IllegalArgumentException());
        } else {
            providerFuture.complete(provider);
        }

        return providerFuture;
    }

    private Future<String> getProviderId(RoutingContext routingContext) {
        Future<String> providerIdFuture = Future.future();
        String providerId = routingContext.request().getParam("providerId");

        if (providerId == null) {
            providerIdFuture.fail(new IllegalArgumentException());
        } else {
            providerIdFuture.complete(providerId);
        }

        return providerIdFuture;
    }

    private Future<String> getUserState(RoutingContext routingContext) {
        Future<String> stateFuture = Future.future();
        String stateParam = routingContext.request().getParam("state");

        if (stateParam != null) {
            stateFuture.complete(stateParam);
        } else {
            stateFuture.fail(new IllegalArgumentException("State cannot be null..."));
        }

        return stateFuture;
    }

    public void refreshFromHttp(RoutingContext routingContext) {
        Consumer<TokenContainer> success = tokenContainer -> {
            routingContext.response().setStatusCode(200);
            routingContext.put(BODY_CONTENT_TAG, tokenContainer);
            routingContext.next();
        };

        getToken(routingContext).compose(refreshToken ->
                refreshToken(refreshToken).compose(success::accept,
                        authFail(routingContext)),
                authFail(routingContext));
    }

    private Future<TokenContainer> refreshToken(String refreshToken) {
        Future<TokenContainer> tokenContainerFuture = Future.future();

        authenticator.refresh(refreshToken, refreshResult -> {
            if (refreshResult.failed()) {
                tokenContainerFuture.fail(new RuntimeException("Unable to refresh for: " + refreshToken));
            } else {
                tokenContainerFuture.complete(refreshResult.result());
            }
        });

        return tokenContainerFuture;
    }

    private void unAuthorized(RoutingContext routingContext) {
        addLogMessageToRequestLog(routingContext, "Unauthorized!");

        routingContext.response().setStatusCode(302).putHeader("Location", CMS_ROOT +
                "#code=401&error=Unauthorized").end();
    }
}
