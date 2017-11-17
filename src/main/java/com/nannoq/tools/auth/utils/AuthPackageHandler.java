package com.nannoq.tools.auth.utils;

import com.nannoq.tools.auth.models.AuthPackage;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

/**
 * This class describes the AuthPackageHandler Interface, it can be used by the AuthenticationService implementation to
 * separate oauth flow and direct convert authentications strategies.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
public interface AuthPackageHandler {
    void processDirectAuth(AuthPackage authPackage, String userId,
                           Handler<AsyncResult<JsonObject>> resultHandler);

    void processOAuthFlow(AuthPackage authPackage, String userId,
                          String finalUrl, Handler<AsyncResult<JsonObject>> resultHandler);
}
