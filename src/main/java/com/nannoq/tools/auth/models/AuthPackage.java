package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 05/11/2016.
 */
@DataObject(generateConverter = true)
public class AuthPackage {
    private String feedId;
    private String userType;
    private TokenContainer tokenContainer;
    private UserProfile userProfile;

    public AuthPackage(String feedId, String userType, TokenContainer tokenContainer, UserProfile userProfile) {
        this.feedId = feedId;
        this.userType = userType;
        this.tokenContainer = tokenContainer;
        this.userProfile = userProfile;
    }

    public AuthPackage(JsonObject jsonObject) {
        this.feedId = jsonObject.getString("feedId");
        this.userType = jsonObject.getString("userType");
        this.tokenContainer = new TokenContainer(jsonObject.getJsonObject("tokenContainer"));
        this.userProfile = Json.decodeValue(
                jsonObject.getJsonObject("userProfile").encode(), UserProfile.class);
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("feedId", feedId)
                .put("userType", userType)
                .put("tokenContainer", tokenContainer.toJson())
                .put("userProfile", userProfile.toJson());
    }

    public String getFeedId() {
        return feedId;
    }

    public String getUserType() {
        return userType;
    }

    public TokenContainer getTokenContainer() {
        return tokenContainer;
    }

    public UserProfile getUserProfile() {
        return userProfile;
    }
}
