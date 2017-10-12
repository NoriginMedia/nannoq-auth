package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 19/09/16.
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
