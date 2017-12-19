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
 */

package com.nannoq.tools.auth.services.providers.utils;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.nannoq.tools.auth.models.UserProfile;

/**
 * This class defines a google user as created from a google token.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class GoogleUser extends UserProfile {
    public GoogleUser() {}

    public GoogleUser(GoogleIdToken.Payload payload) {
        this.email = payload.getEmail();
        this.name = payload.get("name") != null ? payload.get("name").toString() : "N/A";
        this.givenName = payload.get("given_name") != null ? payload.get("given_name").toString() : "N/A";
        this.familyName = payload.get("family_name") != null ? payload.get("family_name").toString() : "N/A";
        this.pictureUrl = payload.get("picture") != null ? payload.get("picture").toString().replaceFirst("s96-c", "s400-c") : "N/A";
        this.emailVerified = payload.getEmailVerified();
    }
}
