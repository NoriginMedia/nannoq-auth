package com.nannoq.tools.auth.models;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Created by anders on 20/09/16.
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
