package com.nannoq.tools.auth.utils;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import static com.nannoq.tools.auth.AuthGlobals.GLOBAL_AUTHORIZATION;
import static com.nannoq.tools.auth.AuthGlobals.VALIDATION_REQUEST;
import static com.nannoq.tools.auth.utils.AuthorizationConverter.fromJson;

/**
 * This class defines the object sent to the VerificationService to authorize a request. Currently support method based
 * on models, with an optional domainIdentifier to authorize creators.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
@DataObject(generateConverter = true)
public class Authorization {
    private String model;
    private String method;
    private String domainIdentifier;

    public Authorization() {}

    public Authorization(JsonObject jsonObject) {
        fromJson(jsonObject, this);
    }

    public JsonObject toJson() {
        return JsonObject.mapFrom(this);
    }

    public boolean validate() {
        return (domainIdentifier != null &&
                (domainIdentifier.equals(VALIDATION_REQUEST) || domainIdentifier.equals(GLOBAL_AUTHORIZATION)) ||
                (model != null && method != null && domainIdentifier != null));
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getDomainIdentifier() {
        return domainIdentifier;
    }

    public void setDomainIdentifier(String domainIdentifier) {
        this.domainIdentifier = domainIdentifier;
    }
}
