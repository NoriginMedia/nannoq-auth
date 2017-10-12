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
 * Converter for {@link com.nannoq.tools.auth.models.AuthPackage}.
 *
 * NOTE: This class has been automatically generated from the {@link com.nannoq.tools.auth.models.AuthPackage} original class using Vert.x codegen.
 */
public class AuthPackageConverter {

  public static void fromJson(JsonObject json, AuthPackage obj) {
  }

  public static void toJson(AuthPackage obj, JsonObject json) {
    if (obj.getFeedId() != null) {
      json.put("feedId", obj.getFeedId());
    }
    if (obj.getTokenContainer() != null) {
      json.put("tokenContainer", obj.getTokenContainer().toJson());
    }
    if (obj.getUserProfile() != null) {
      json.put("userProfile", obj.getUserProfile().toJson());
    }
    if (obj.getUserType() != null) {
      json.put("userType", obj.getUserType());
    }
  }
}