package com.nannoq.tools.auth.webhandlers;

import com.nannoq.tools.auth.AuthUtils;
import com.nannoq.tools.auth.models.VerifyResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.util.concurrent.TimeUnit;

import static com.nannoq.tools.web.requestHandlers.RequestLogHandler.addLogMessageToRequestLog;

/**
 * Created by anders on 02/08/16.
 */
public class AuthHandler implements Handler<RoutingContext> {
    private static final Logger logger = LoggerFactory.getLogger(AuthHandler.class.getSimpleName());

    public static final String AUTH_PROCESS_TIME = "X-Auth-Time-To-Process";

    private final Vertx vertx;
    private final Class TYPE;
    private final AuthUtils authUtils;
    private final String apiKey;
    private final boolean external;

    public AuthHandler(Class type, Vertx vertx, String apiKey) {
        this(type, vertx, apiKey, false);
    }

    public AuthHandler(Class type, Vertx vertx, String apiKey, boolean external) {
        this.TYPE = type;
        this.vertx = vertx;
        this.apiKey = apiKey;
        this.external = external;
        authUtils = AuthUtils.getInstance(external);
    }

    @Override
    public void handle(RoutingContext routingContext) {
        long processStartTime = System.nanoTime();
        String auth = routingContext.request().getHeader("Authorization");

        if (logger.isDebugEnabled()) {
            addLogMessageToRequestLog(routingContext, "Starting auth for: " + auth);
        }

        if (auth != null) {
            if (auth.startsWith("APIKEY ")) {
                String key = auth.substring("APIKEY".length()).trim();

                if (key.equals(apiKey)) {
                    addLogMessageToRequestLog(routingContext, "INFO: Google AUTH overriden by API KEY!");

                    setAuthProcessTime(routingContext, processStartTime);
                    routingContext.next();
                } else {
                    unAuthorized(routingContext, processStartTime);
                }
            } else if (auth.startsWith("Bearer")) {
                String token = auth.substring("Bearer".length()).trim();

                if (logger.isInfoEnabled()) {
                    addLogMessageToRequestLog(routingContext, "Preparing request to auth backend...");
                }

                HttpServerRequest request = routingContext.request();
                String feedId = request.getParam("feedId");
                if (feedId == null) feedId = request.getParam("hash");
                String authTypeToken = request.rawMethod() + " " + TYPE.getSimpleName() + " " + feedId;

                authUtils.<VerifyResult>authenticateAndAuthorize(token, authTypeToken, result -> {
                    if (result.failed()) {
                        addLogMessageToRequestLog(routingContext, "Unauthorized!", result.cause());

                        unAuthorized(routingContext, processStartTime);
                    } else {
                        setAuthProcessTime(routingContext, processStartTime);
                        routingContext.put(AuthUtils.USER_IDENTIFIER, result.result().getId());
                        routingContext.put(AuthUtils.USER_TYPE, result.result().getUserType());
                        routingContext.next();
                    }
                });
            } else {
                unAuthorized(routingContext, processStartTime);
            }
        } else {
            unAuthorized(routingContext, processStartTime);
        }
    }

    private void setAuthProcessTime(RoutingContext routingContext, long initialTime) {
        long processTimeInNano = System.nanoTime() - initialTime;
        routingContext.response().putHeader(AUTH_PROCESS_TIME,
                String.valueOf(TimeUnit.NANOSECONDS.toMillis(processTimeInNano)));
    }

    private void unAuthorized(RoutingContext routingContext, long processStartTime) {
        setAuthProcessTime(routingContext, processStartTime);

        routingContext.fail(401);
    }
}
