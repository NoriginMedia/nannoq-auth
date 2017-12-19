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

package com.nannoq.tools.auth.utils;

import com.nannoq.tools.auth.services.VerificationService;
import com.nannoq.tools.auth.services.VerificationServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;
import io.vertx.serviceproxy.ServiceException;

import static com.nannoq.tools.web.requestHandlers.RequestLogHandler.addLogMessageToRequestLog;
import static com.nannoq.tools.web.responsehandlers.ResponseLogHandler.BODY_CONTENT_TAG;

/**
 * This class defines a set of static methods for performing various auth related futures.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class AuthFutures {
    private static final Logger logger = LoggerFactory.getLogger(AuthFutures.class.getSimpleName());

    public static Future<String> getToken(RoutingContext routingContext) {
        Future<String> tokenFuture = Future.future();
        String authentication = routingContext.request().getHeader(HttpHeaders.AUTHORIZATION);

        if (authentication != null) {
            if (authentication.startsWith("Bearer ")) {
                tokenFuture.complete(authentication.substring("Bearer".length()).trim());
            } else {
                tokenFuture.fail(new IllegalArgumentException("Auth does not start with Bearer!"));
            }
        } else {
            tokenFuture.fail(new IllegalArgumentException("Auth is null!"));
        }

        return tokenFuture;
    }

    public static Future<Jws<Claims>> verifyToken(VerificationServiceImpl verifier, String token) {
        Future<Jws<Claims>> claimsFuture = Future.future();

        verifier.verifyToken(token, resultHandler -> {
            if (resultHandler.failed()) {
                if (resultHandler.cause() instanceof ServiceException) {
                    claimsFuture.fail(resultHandler.cause());
                } else {
                    claimsFuture.fail(new SecurityException("Could not verify JWT..."));
                }
            } else {
                claimsFuture.complete(resultHandler.result());
            }
        });

        return claimsFuture;
    }

    public static <U> Future<U> denyRequest(RoutingContext routingContext) {
        return Future.<U>future().setHandler(handler -> routingContext.response().setStatusCode(400).end());
    }

    public static <U> Future<U> authFail(RoutingContext routingContext) {
        return Future.<U>future().setHandler(handler -> doAuthFailure(routingContext, handler));
    }

    public static <U> void doAuthFailure(RoutingContext routingContext, AsyncResult<U> handler) {
        String errorMessage;

        if (handler.cause() instanceof ServiceException) {
            ServiceException se = (ServiceException) handler.cause();

            errorMessage = "AUTH ERROR: Authorization Cause is: " +
                    se.getMessage() + " : " + se.getDebugInfo().encodePrettily();
        } else {
            errorMessage = "AUTH ERROR: Authorization Cause is: " + handler.cause().getMessage();
        }

        addLogMessageToRequestLog(routingContext, errorMessage);

        routingContext.put(BODY_CONTENT_TAG, new JsonObject().put("auth_error", errorMessage));

        unAuthorized(routingContext);
    }

    public static  <U> Future<U> authFailRedirect(RoutingContext routingContext) {
        return authFailRedirect(routingContext, null);
    }

    public static <U> Future<U> authFailRedirect(RoutingContext routingContext, String location) {
        return Future.<U>future().setHandler(handler -> doAuthFailureRedirect(routingContext, handler, location));
    }

    public static <U> void doAuthFailureRedirect(RoutingContext routingContext, AsyncResult<U> handler) {
        doAuthFailureRedirect(routingContext, handler, null);
    }

    public static <U> void doAuthFailureRedirect(RoutingContext routingContext, AsyncResult<U> handler, String location) {
        String errorMessage;

        if (handler.cause() instanceof ServiceException) {
            ServiceException se = (ServiceException) handler.cause();

            errorMessage = "AUTH ERROR: Authorization Cause is: " +
                    se.getMessage() + " : " + se.getDebugInfo().encodePrettily();
        } else {
            errorMessage = "AUTH ERROR: Authorization Cause is: " + handler.cause().getMessage();
        }

        addLogMessageToRequestLog(routingContext, errorMessage);

        routingContext.put(BODY_CONTENT_TAG, new JsonObject().put("auth_error", errorMessage));

        if (location == null) {
            unAuthorizedRedirect(routingContext, handler.cause().getMessage());
        } else {
            unAuthorizedRedirect(routingContext, location);
        }
    }

    private static void unAuthorized(RoutingContext routingContext) {
        routingContext.response().setStatusCode(401);
        routingContext.next();
    }

    private static void unAuthorizedRedirect(RoutingContext routingContext, String location) {
        addLogMessageToRequestLog(routingContext, "Unauthorized!");

        routingContext.response().setStatusCode(302).putHeader("Location", location).end();
    }

    public static <U, T> Future<U> authFail(Handler<AsyncResult<T>> resultHandler) {
        return Future.<U>future().setHandler(handler -> doAuthFailure(handler, resultHandler));
    }

    public static <U, T> void doAuthFailure(AsyncResult<U> handler, Handler<AsyncResult<T>> resultHandler) {
        String errorMessage = "AUTH ERROR: Authentication Cause is: " + handler.cause().getMessage();

        if (handler.cause() instanceof ServiceException) {
            resultHandler.handle(Future.failedFuture(handler.cause()));
        } else {
            resultHandler.handle(ServiceException.fail(500, errorMessage));
        }
    }
}
