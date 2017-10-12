package com.nannoq.tools.auth.utils;

import com.nannoq.tools.auth.AuthGlobals;
import com.nannoq.tools.auth.models.AuthPackage;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 24/02/2017.
 */
public interface AuthPackageHandler {
    void processDirectAuth(AuthPackage authPackage, String userId,
                           Handler<AsyncResult<JsonObject>> resultHandler);

    void processOAuthFlow(AuthPackage authPackage, String userId,
                          String finalUrl, AuthGlobals.AUTH_ORIGIN authOrigin,
                          Handler<AsyncResult<JsonObject>> resultHandler);
}
