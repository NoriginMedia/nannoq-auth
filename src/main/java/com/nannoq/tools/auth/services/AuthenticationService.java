package com.nannoq.tools.auth.services;

import com.nannoq.tools.auth.models.AuthPackage;
import com.nannoq.tools.auth.models.TokenContainer;
import io.vertx.codegen.annotations.*;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import javax.annotation.Nonnull;

/**
 * Created by anders on 25/12/2016.
 */
@ProxyGen
@VertxGen
public interface AuthenticationService {
    @Fluent
    AuthenticationService createJwtFromProvider(@Nonnull String token, @Nonnull String authProvider,
                                                @Nonnull String feedId, @Nullable String authOrigin,
                                                @Nonnull Handler<AsyncResult<AuthPackage>> resultHandler);

    @Fluent
    AuthenticationService refresh(@Nonnull String refreshToken,
                                  @Nonnull Handler<AsyncResult<TokenContainer>> resultHandler);

    @ProxyClose
    void close();
}
