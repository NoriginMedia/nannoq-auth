package com.nannoq.tools.auth.webhandlers;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Created by anders on 02/08/16.
 */
public class ApiKeyHandler implements Handler<RoutingContext> {
    private final String apiKey;

    public ApiKeyHandler(String apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    public void handle(RoutingContext routingContext) {
        String incomingKey = routingContext.request().getHeader("Authorization");

        if (incomingKey.startsWith("APIKEY ")) {
            String key = incomingKey.substring("APIKEY".length()).trim();

            if (key.equals(apiKey)) {
                routingContext.next();
            } else {
                unAuthorized(routingContext);
            }
        }
    }

    private void unAuthorized(RoutingContext routingContext) {
        routingContext.fail(401);
    }
}
