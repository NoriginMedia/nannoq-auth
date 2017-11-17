package com.nannoq.tools.auth.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * This class defines the Authorizer interface. It can be used be a VerificationService implementation to call
 * authorization logic.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
public interface Authorizer {
    boolean isAsync();
    boolean authorize(Jws<Claims> claims, String domainIdentifier, Authorization authorization) throws IllegalAccessException;
    void authorize(Jws<Claims> claims, String domainIdentifier, Authorization authorization, Handler<AsyncResult<Boolean>> resultHandler);
    void block(String domainIdentifier, String userId, Handler<AsyncResult<Boolean>> resultHandler);
}
