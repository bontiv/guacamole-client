/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.auth.ldap.user;

import com.google.inject.Inject;
import java.util.Set;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;

/**
 * An LDAP-specific implementation of AuthenticatedUser, associating a
 * particular set of credentials with the LDAP authentication provider.
 */
public class AuthenticatedUser extends AbstractAuthenticatedUser {

    /**
     * Reference to the authentication provider associated with this
     * authenticated user.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * The credentials provided when this user was authenticated.
     */
    private Credentials credentials;

    /**
     * The unique identifiers of all user groups which affect the permissions
     * available to this user.
     */
    private Set<String> effectiveGroups;

    /**
     * Initializes this AuthenticatedUser with the given credentials and set of
     * effective user groups.
     *
     * @param credentials
     *     The credentials provided when this user was authenticated.
     *
     * @param effectiveGroups
     *     The unique identifiers of all user groups which affect the
     *     permissions available to this user.
     */
    public void init(Credentials credentials, Set<String> effectiveGroups) {
        this.credentials = credentials;
        this.effectiveGroups = effectiveGroups;
        setIdentifier(credentials.getUsername());
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

    @Override
    public Set<String> getEffectiveUserGroups() {
        return effectiveGroups;
    }

}
