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

import com.nannoq.tools.auth.services.providers.utils.InstaGramUser;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.LoggerFactory;
import org.jinstagram.Instagram;
import org.jinstagram.auth.InstagramAuthService;
import org.jinstagram.auth.model.Token;
import org.jinstagram.auth.model.Verifier;
import org.jinstagram.auth.oauth.InstagramService;
import org.jinstagram.exceptions.InstagramException;

import static com.nannoq.tools.auth.services.AuthenticationServiceImpl.INSTAGRAM;

/**
 * This class defines an instagram provider which will check an incoming token and verify its authenticity towards
 * instagram and return an InstaGramUser object.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class InstaGram implements Provider<InstaGramUser> {
    private final Vertx vertx;
    private final String clientSecret;
    private final InstagramService instagramService;

    public InstaGram(Vertx vertx, JsonObject appConfig, String callBackUrl) {
        this.vertx = vertx;
        String clientId = appConfig.getString("instaClientId");
        this.clientSecret = appConfig.getString("instaClientSecret");
        instagramService = new InstagramAuthService()
                .apiKey(clientId)
                .apiSecret(clientSecret)
                .callback(callBackUrl)
                .scope("basic public_content follower_list likes comments relationships")
                .build();
    }

    @Override
    public void checkJWT(String tokenString, Handler<AsyncResult<InstaGramUser>> resultHandler) {
        vertx.<InstaGramUser>executeBlocking(future -> {
            Token token = instagramService.getAccessToken(new Verifier(tokenString));
            Instagram instagram = new Instagram(token.getToken(), clientSecret);

            try {
                future.complete(new InstaGramUser(instagram.getCurrentUserInfo()));
            } catch (InstagramException e) {
                LoggerFactory.getLogger(InstaGram.class.getSimpleName()).error(INSTAGRAM + " ERROR: " + e);

                future.complete(null);
            }
        }, false, instaGramResult -> {
            if (instaGramResult.succeeded()) {
                resultHandler.handle(Future.succeededFuture(instaGramResult.result()));
            } else {
                resultHandler.handle(Future.failedFuture(instaGramResult.cause()));
            }
        });
    }
}
