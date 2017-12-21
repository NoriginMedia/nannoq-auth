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

import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.services.VerificationService;
import com.nannoq.tools.auth.utils.Authorization;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.RoutingContext;
import io.vertx.serviceproxy.ServiceException;

import java.util.Base64;
import java.util.function.Consumer;

import static com.nannoq.tools.auth.AuthGlobals.VALIDATION_REQUEST;
import static com.nannoq.tools.auth.utils.AuthFutures.*;
import static com.nannoq.tools.web.responsehandlers.ResponseLogHandler.BODY_CONTENT_TAG;

/**
 * This class defines a Handler implementation that receives all traffic for endpoints that handle JWT reception, e.g.
 * verification and authorization.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class JWTReceiver implements Handler<RoutingContext> {
    private static final Logger logger = LoggerFactory.getLogger(JWTReceiver.class.getSimpleName());

    private final VerificationService verifier;
    private final String AUTHORIZATION_TYPE_HEADER;

    public JWTReceiver(VerificationService verifier) {
        this(verifier, null);
    }

    public JWTReceiver(VerificationService verifier, String AUTHORIZATION_TYPE_HEADER) {
        this.verifier = verifier;

        if (AUTHORIZATION_TYPE_HEADER == null) {
            this.AUTHORIZATION_TYPE_HEADER = "X-Authorization-Type";
        } else {
            this.AUTHORIZATION_TYPE_HEADER = AUTHORIZATION_TYPE_HEADER;
        }
    }

    @Override
    public void handle(RoutingContext routingContext) {
        Handler<VerifyResult> success = result -> {
            routingContext.put(BODY_CONTENT_TAG, Json.encode(result));
            routingContext.response().setStatusCode(200);
            routingContext.next();
        };

        getToken(routingContext).compose(token ->
        verifyToken(verifier, token).compose(claims ->
        authorizeRequest(claims, routingContext).compose(success,
                authFail(routingContext)),
                authFail(routingContext)),
                authFail(routingContext));
    }

    private Future<VerifyResult> authorizeRequest(Jws<Claims> claims, RoutingContext routingContext) {
        Future<VerifyResult> idFuture = Future.future();
        String authorization = routingContext.request().getHeader(AUTHORIZATION_TYPE_HEADER);

        logger.info("Incoming Auth Json Base64 is: " + authorization);

        try {
            Authorization authorizationPOJO;

            if (authorization == null) {
                authorizationPOJO = new Authorization();
                authorizationPOJO.setDomainIdentifier(VALIDATION_REQUEST);
            } else {
                String json = new String(Base64.getDecoder().decode(authorization));

                logger.info("Incoming Auth Json is: " + json);

                authorizationPOJO = Json.decodeValue(json, Authorization.class);
            }

            if (authorizationPOJO.getDomainIdentifier().equals(VALIDATION_REQUEST)) {
                idFuture.complete(new VerifyResult(claims.getBody().getSubject()));
            } else {
                try {
                    checkAuthorization(authorizationPOJO, claims, res -> {
                        if (res.failed()) {
                            idFuture.fail(new SecurityException("You are not authorized for this action!"));
                        } else {
                            idFuture.complete(new VerifyResult(claims.getBody().getSubject()));
                        }
                    });
                } catch (IllegalAccessException e) {
                    idFuture.fail(e);
                }
            }
        } catch (DecodeException e) {
            idFuture.fail(new SecurityException("You are not authorized for this action, illegal AuthTypeToken!"));
        }

        return idFuture;
    }

    private void checkAuthorization(Authorization authorization, Jws<Claims> claims,
                                    Handler<AsyncResult<Boolean>> completer) throws IllegalAccessException {
        verifier.verifyAuthorization(claims, authorization, completer);
    }

    public void revoke(RoutingContext routingContext) {
        Consumer<Void> success = v -> {
            routingContext.response().setStatusCode(204);
            routingContext.next();
        };

        getToken(routingContext).compose(token ->
                        revokeToken(token).compose(success::accept,
                                authFail(routingContext)),
                authFail(routingContext));
    }

    private Future<Void> revokeToken(String token) {
        Future<Void> revokeFuture = Future.future();

        verifier.revokeToken(token, revokeResult -> {
            if (revokeResult.failed()) {
                if (revokeResult.cause() instanceof ServiceException) {
                    revokeFuture.fail(revokeResult.cause());
                } else {
                    revokeFuture.fail(new SecurityException("Unable to revoke token..."));
                }
            } else {
                revokeFuture.complete();
            }
        });

        return revokeFuture;
    }
}
