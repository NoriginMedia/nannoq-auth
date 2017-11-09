package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 04/01/2017.
 */
@DataObject(generateConverter = true)
public class VerifyResult {
    private String id;

    public VerifyResult() {}

    public VerifyResult(String id) {
        this.id = id;
    }

    public VerifyResult(JsonObject jsonObject) {
        this.id = jsonObject.getString("id");
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("id", id);
    }

    public String getId() {
        return id;
    }
}
