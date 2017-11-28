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

package com.nannoq.tools.auth.webhandlers;

import com.nannoq.tools.auth.AuthUtils;
import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.utils.Authorization;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;

import java.util.concurrent.TimeUnit;

import static com.nannoq.tools.auth.AuthGlobals.GLOBAL_AUTHORIZATION;
import static com.nannoq.tools.web.requestHandlers.RequestLogHandler.addLogMessageToRequestLog;

/**
 * This class defines an auth handler for verifying jwts. It builds a request based on the method of the original client
 * request, and the model it is instantiated with. It accepts an optional domainIdentifier value.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
public class AuthHandler implements Handler<RoutingContext> {
    private static final Logger logger = LoggerFactory.getLogger(AuthHandler.class.getSimpleName());

    public static final String AUTH_PROCESS_TIME = "X-Auth-Time-To-Process";

    private final Class TYPE;
    private final AuthUtils authUtils;
    private final String apiKey;
    private final String domainIdentifier;

    public AuthHandler(Class type, String domainIdentifier, String apiKey) {
        this.TYPE = type;
        this.domainIdentifier = domainIdentifier;
        this.apiKey = apiKey;
        authUtils = AuthUtils.getInstance();
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
                String feedId = routingContext.pathParam(domainIdentifier);
                if (feedId == null) feedId = request.getParam("hash");
                Authorization authorization = new Authorization();
                authorization.setMethod(request.rawMethod());
                authorization.setModel(TYPE.getSimpleName());
                authorization.setDomainIdentifier(feedId == null ? GLOBAL_AUTHORIZATION : feedId);

                authUtils.<VerifyResult>authenticateAndAuthorize(token, authorization, result -> {
                    if (result.failed()) {
                        addLogMessageToRequestLog(routingContext, "Unauthorized!", result.cause());

                        unAuthorized(routingContext, processStartTime);
                    } else {
                        setAuthProcessTime(routingContext, processStartTime);
                        routingContext.put(AuthUtils.USER_IDENTIFIER, result.result().getId());
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
