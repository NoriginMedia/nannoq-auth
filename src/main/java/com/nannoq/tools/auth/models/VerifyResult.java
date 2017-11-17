package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * This class defines a result to verify requests, currently only returns id.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
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
