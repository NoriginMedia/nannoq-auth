package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 05/11/2016.
 */
@DataObject(generateConverter = true)
public class AuthPackage {
    private TokenContainer tokenContainer;
    private UserProfile userProfile;

    public AuthPackage(TokenContainer tokenContainer, UserProfile userProfile) {
        this.tokenContainer = tokenContainer;
        this.userProfile = userProfile;
    }

    public AuthPackage(JsonObject jsonObject) {
        this.tokenContainer = new TokenContainer(jsonObject.getJsonObject("tokenContainer"));
        this.userProfile = Json.decodeValue(
                jsonObject.getJsonObject("userProfile").encode(), UserProfile.class);
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("tokenContainer", tokenContainer.toJson())
                .put("userProfile", userProfile.toJson());
    }

    public TokenContainer getTokenContainer() {
        return tokenContainer;
    }

    public UserProfile getUserProfile() {
        return userProfile;
    }
}
