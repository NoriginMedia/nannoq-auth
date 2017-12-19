/*
 * MIT License
 *
 * Copyright (c) 2017 Anders Mikkelsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.nannoq.tools.auth.utils;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.Fluent;
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

    @Fluent
    public Authorization setModel(String model) {
        this.model = model;

        return this;
    }

    public String getMethod() {
        return method;
    }

    @Fluent
    public Authorization setMethod(String method) {
        this.method = method;

        return this;
    }

    public String getDomainIdentifier() {
        return domainIdentifier;
    }

    @Fluent
    public Authorization setDomainIdentifier(String domainIdentifier) {
        this.domainIdentifier = domainIdentifier;

        return this;
    }

    public static Authorization global() {
        return new Authorization().setDomainIdentifier(VALIDATION_REQUEST);
    }
}
