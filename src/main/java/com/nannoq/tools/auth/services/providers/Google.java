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

package com.nannoq.tools.auth.services.providers;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import static com.nannoq.tools.auth.services.AuthenticationServiceImpl.GOOGLE;

/**
 * This class defines a google provider which will check an incoming token and verify its authenticity towards
 * google and return a GoogleUser object.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class Google implements Provider<GoogleIdToken.Payload> {
    private static final Logger logger = LoggerFactory.getLogger(Google.class.getSimpleName());
    private List<String> CLIENT_IDS;

    private final Vertx vertx;
    private final JsonObject appConfig;
    private GoogleIdTokenVerifier verifier;

    public Google(Vertx vertx, JsonObject appConfig) {
        this.vertx = vertx;
        this.appConfig = appConfig;
        JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
        HttpTransport transport;

        try {
            transport = GoogleNetHttpTransport.newTrustedTransport();
            verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(CLIENT_IDS)
                    .setIssuer("https://accounts.google.com")
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            logger.error(e);
        }
    }

    @Fluent
    public Google withClientIds(List<String> ids) {
        CLIENT_IDS = ids;
        JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
        HttpTransport transport;

        try {
            transport = GoogleNetHttpTransport.newTrustedTransport();
            verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(CLIENT_IDS)
                    .setIssuer("https://accounts.google.com")
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            logger.error(e);
        }

        return this;
    }

    @Override
    public void checkJWT(String jwt, Handler<AsyncResult<GoogleIdToken.Payload>> resultHandler) {
        vertx.<GoogleIdToken.Payload>executeBlocking(future -> {
            if (jwt == null) {
                future.complete(null);
            } else {
                GoogleIdToken idToken;

                try {
                    idToken = verifier.verify(jwt);

                    logger.info(idToken);

                    if (idToken == null) {
                        future.fail(new RuntimeException("Could not verify JWT..."));
                    } else {
                        future.complete(idToken.getPayload());
                    }
                } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
                    logger.error("\nERROR " + GOOGLE + " Auth: " + e.getMessage());

                    future.fail(e);
                }
            }
        }, false, payloadResult -> {
            if (payloadResult.succeeded()) {
                resultHandler.handle(Future.succeededFuture(payloadResult.result()));
            } else {
                resultHandler.handle(Future.failedFuture(payloadResult.cause()));
            }
        });
    }
}
