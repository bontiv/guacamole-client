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

package org.apache.guacamole;

import org.apache.guacamole.protocol.GuacamoleStatus;


/**
 * An exception which is thrown when the client has sent too much data. This
 * usually indicates that a server-side buffer is not large enough to
 * accommodate the data, or protocol specifications prohibit data of the size
 * received.
 */
public class GuacamoleClientOverrunException extends GuacamoleClientException {

    private static final long serialVersionUID = 5159605363266195550L;

    /**
     * Creates a new GuacamoleClientOverrunException with the given message and cause.
     *
     * @param message A human readable description of the exception that
     *                occurred.
     * @param cause The cause of this exception.
     */
    public GuacamoleClientOverrunException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new GuacamoleClientOverrunException with the given message.
     *
     * @param message A human readable description of the exception that
     *                occurred.
     */
    public GuacamoleClientOverrunException(String message) {
        super(message);
    }

    /**
     * Creates a new GuacamoleClientOverrunException with the given cause.
     *
     * @param cause The cause of this exception.
     */
    public GuacamoleClientOverrunException(Throwable cause) {
        super(cause);
    }

    @Override
    public GuacamoleStatus getStatus() {
        return GuacamoleStatus.CLIENT_OVERRUN;
    }

}
