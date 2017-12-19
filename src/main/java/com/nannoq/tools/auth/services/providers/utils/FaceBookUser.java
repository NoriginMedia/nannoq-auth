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

import com.nannoq.tools.auth.models.UserProfile;
import com.nannoq.tools.repository.models.ModelUtils;
import facebook4j.User;

/**
 * This class defines a facebook user as created from a facebook token.
 *
 * @author Anders Mikkelsen
 * @version 13/11/17
 */
public class FaceBookUser extends UserProfile {
    public FaceBookUser() {}

    public FaceBookUser(User user) {
        this.email = user.getEmail();
        this.name = user.getName();
        this.givenName = user.getFirstName();
        this.familyName = user.getLastName();
        this.pictureUrl = user.getPicture() != null ? user.getPicture().getURL().toString() : "N/A";
        this.emailVerified = user.isVerified();

        if (email == null || email.equalsIgnoreCase("")) {
            generateFakeEmail(user);
        }
    }

    private void generateFakeEmail(User user) {
        this.email = ModelUtils.returnNewEtag(user.getId() != null ? user.getId().hashCode() :
                name != null ? name.hashCode() : this.hashCode()) + "@facebook.notfound.com";
    }
}
