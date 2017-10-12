package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 04/01/2017.
 */
@DataObject(generateConverter = true)
public class VerifyResult {
    private String id;
    private String userType;
    private String feedId;

    public VerifyResult() {}

    public VerifyResult(String id, String userType, String feedId) {
        this.id = id;
        this.userType = userType;
        this.feedId = feedId;
    }

    public VerifyResult(JsonObject jsonObject) {
        this.id = jsonObject.getString("id");
        this.userType = jsonObject.getString("userType");
        this.feedId = jsonObject.getString("feedId");
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("id", id)
                .put("userType", userType)
                .put("feedId", feedId);
    }

    public String getId() {
        return id;
    }

    public String getUserType() {
        return userType;
    }

    public String getFeedId() {
        return feedId;
    }
}
