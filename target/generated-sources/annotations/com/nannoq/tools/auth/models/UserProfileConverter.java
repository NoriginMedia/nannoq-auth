/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.nannoq.tools.auth.models;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter for {@link com.nannoq.tools.auth.models.UserProfile}.
 *
 * NOTE: This class has been automatically generated from the {@link com.nannoq.tools.auth.models.UserProfile} original class using Vert.x codegen.
 */
public class UserProfileConverter {

  public static void fromJson(JsonObject json, UserProfile obj) {
    if (json.getValue("email") instanceof String) {
      obj.setEmail((String)json.getValue("email"));
    }
    if (json.getValue("emailVerified") instanceof Boolean) {
      obj.setEmailVerified((Boolean)json.getValue("emailVerified"));
    }
    if (json.getValue("familyName") instanceof String) {
      obj.setFamilyName((String)json.getValue("familyName"));
    }
    if (json.getValue("givenName") instanceof String) {
      obj.setGivenName((String)json.getValue("givenName"));
    }
    if (json.getValue("name") instanceof String) {
      obj.setName((String)json.getValue("name"));
    }
    if (json.getValue("pictureUrl") instanceof String) {
      obj.setPictureUrl((String)json.getValue("pictureUrl"));
    }
    if (json.getValue("userId") instanceof String) {
      obj.setUserId((String)json.getValue("userId"));
    }
  }

  public static void toJson(UserProfile obj, JsonObject json) {
    if (obj.getEmail() != null) {
      json.put("email", obj.getEmail());
    }
    json.put("emailVerified", obj.isEmailVerified());
    if (obj.getFamilyName() != null) {
      json.put("familyName", obj.getFamilyName());
    }
    if (obj.getGivenName() != null) {
      json.put("givenName", obj.getGivenName());
    }
    if (obj.getName() != null) {
      json.put("name", obj.getName());
    }
    if (obj.getPictureUrl() != null) {
      json.put("pictureUrl", obj.getPictureUrl());
    }
    if (obj.getUserId() != null) {
      json.put("userId", obj.getUserId());
    }
  }
}