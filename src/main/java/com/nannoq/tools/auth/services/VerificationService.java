package com.nannoq.tools.auth.services;

import com.nannoq.tools.auth.models.VerifyResult;
import com.nannoq.tools.auth.utils.Authorization;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.ProxyClose;
import io.vertx.codegen.annotations.ProxyGen;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import javax.annotation.Nonnull;

/**
 * This class defines the VerificationService interface. It is used for verifying singular and all tokens, and revoking
 * JWT's.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
@ProxyGen
@VertxGen
public interface VerificationService {
    @Fluent
    VerificationService verifyJWT(@Nonnull String token, @Nonnull Authorization authorization,
                                  @Nonnull Handler<AsyncResult<VerifyResult>> resultHandler);

    @Fluent
    VerificationService revokeToken(@Nonnull String token, @Nonnull Handler<AsyncResult<Boolean>> resultHandler);
    
    @Fluent
    VerificationService verifyJWTValidity(@Nonnull Handler<AsyncResult<Boolean>> resultHandler);

    @ProxyClose
    void close();
}
