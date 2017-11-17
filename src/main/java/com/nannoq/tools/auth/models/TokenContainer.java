package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * This class defines a container for an accessToken (JWT) and a refreshToken.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
@DataObject(generateConverter = true)
public class TokenContainer {
    private final String accessToken;
    private final String refreshToken;

    public TokenContainer(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public TokenContainer(JsonObject jsonObject) {
        this.accessToken = jsonObject.getString("accessToken");
        this.refreshToken = jsonObject.getString("refreshToken");
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("accessToken", accessToken)
                .put("refreshToken", refreshToken);
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
