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

package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * This class defines a generic UserProfile with basic userinfo.
 *
 * @author Anders Mikkelsen
 * @version 17.11.2017
 */
@DataObject(generateConverter = true)
public class UserProfile {
    protected String userId;
    protected String email;
    protected String name;
    protected String givenName;
    protected String familyName;
    protected String pictureUrl;
    protected boolean emailVerified;

    public UserProfile() {}

    public UserProfile(JsonObject jsonObject) {
        this.userId = jsonObject.getString("userId");
        this.email = jsonObject.getString("email");
        this.name = jsonObject.getString("name");
        this.givenName = jsonObject.getString("givenName");
        this.familyName = jsonObject.getString("familyName");
        this.pictureUrl = jsonObject.getString("pictureUrl");
        this.emailVerified = jsonObject.getBoolean("emailVerified");
    }

    public JsonObject toJson() {
        return new JsonObject()
                .put("userId", userId)
                .put("email", email)
                .put("name", name)
                .put("givenName", givenName)
                .put("familyName", familyName)
                .put("pictureUrl", pictureUrl)
                .put("emailVerified", emailVerified);
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }
}
