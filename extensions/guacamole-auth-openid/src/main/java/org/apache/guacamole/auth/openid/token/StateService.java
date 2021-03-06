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

package org.apache.guacamole.auth.openid.token;

import com.google.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Base64;
import java.util.Random;

/**
 * Service class for token state
 */

@Singleton
public class StateService {


    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(StateService.class);


    /**
     * Variable name in session for state.
     */
    private static String STATE_VARIABLE_NAME = "openid_state";

    /**
     * Request from browser.
     */
    private HttpServletRequest request;

    /**
     * Generate a new state
     * @return
     * state string
     */
    public String generate() {
        Random sr = new Random();
        byte seed[] = new byte[15];
        sr.nextBytes(seed);

        String data = new String(Base64.getEncoder().encode(seed));

        // remove + character which are interpreted as spaces.
        data = data.replaceAll("/\\+/", "");

        this.request.getSession().setAttribute(this.STATE_VARIABLE_NAME, data);
        return data;
    }

    /**
     * Set request object to get session object and state parameters.
     * @param request
     */
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    /**
     * Check the session state.
     * @return
     *   True if state is valid.
     */
    public boolean check() {
        String state = this.request.getParameter("state");
        HttpSession session = this.request.getSession();
        String requireState = (String)session.getAttribute(STATE_VARIABLE_NAME);

        if (state == null) {
            logger.info("No OpenID state provided by parameter.");
            return false;
        }

        if (!state.equals(requireState)) {
            logger.info(String.format("Bad state provided: Expected <%s>, get <%s>", requireState, state));
            return false;
        }

        logger.debug("Allow state parameter.");
        session.removeAttribute(STATE_VARIABLE_NAME);
        return true;
    }

}
