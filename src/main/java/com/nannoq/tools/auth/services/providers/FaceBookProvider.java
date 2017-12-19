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

import com.nannoq.tools.auth.services.providers.utils.FaceBookUser;
import facebook4j.*;
import facebook4j.auth.AccessToken;
import facebook4j.conf.ConfigurationBuilder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import static com.nannoq.tools.auth.services.AuthenticationServiceImpl.FACEBOOK;

/**
 * This class defines a facebook provider which will check an incoming token and verify its authenticity towards
 * facebook and return a FaceBookUser object.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class FaceBookProvider implements Provider<FaceBookUser> {
    private static final Logger logger = LoggerFactory.getLogger(FaceBookProvider.class.getSimpleName());

    @Override
    public void checkJWT(Vertx vertx, JsonObject appConfig, String token,
                         Handler<AsyncResult<FaceBookUser>> resultHandler) {
        vertx.<FaceBookUser>executeBlocking(future -> {
            AccessToken authToken = new AccessToken(token);
            String appId = appConfig.getString("faceBookAppId");
            String appSecret = appConfig.getString("faceBookAppSecret");

            ConfigurationBuilder cb = new ConfigurationBuilder();
            cb.setAppSecretProofEnabled(true);
            cb.setOAuthAppId(appId);
            cb.setOAuthAppSecret(appSecret);
            Facebook facebook = new FacebookFactory(cb.build()).getInstance();
            facebook.setOAuthPermissions("public_profile,email,user_friends");
            facebook.setOAuthAccessToken(authToken);

            try {
                User user = facebook.getMe(new Reading()
                        .fields("id,email,name,first_name,middle_name,last_name,verified,picture"));
                FaceBookUser faceBookUser = new FaceBookUser(user);
                faceBookUser.setPictureUrl(facebook.users().getPictureURL(user.getId(), 400, 400).toString());

                future.complete(faceBookUser);
            } catch (FacebookException e) {
                logger.error("AUTH " + FACEBOOK + " Error: " + e);

                future.fail(new UnknownError());
            }
        }, false, facebookResult -> {
            if (facebookResult.succeeded()) {
                resultHandler.handle(Future.succeededFuture(facebookResult.result()));
            } else {
                resultHandler.handle(Future.failedFuture(facebookResult.cause()));
            }
        });
    }
}
