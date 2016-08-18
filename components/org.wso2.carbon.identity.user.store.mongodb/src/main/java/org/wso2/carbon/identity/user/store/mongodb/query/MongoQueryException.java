/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.user.store.mongodb.query;

/**
 * MongoDB prepared statement exception class
 */
@SuppressWarnings("unused")
public class MongoQueryException extends Exception {

    private static final long serialVersionUID = 1997753363232807009L;


    /**
     * Default Exception constructor
     */
    public MongoQueryException() {

    }

    /**
     * Exception constructor with exception message
     *
     * @param message exception message
     */
    public MongoQueryException(String message) {

        super(message);
    }

    /**
     * Exception constructor with throwable reason
     *
     * @param reason Throwable reason
     */
    public MongoQueryException(Throwable reason) {

        super(reason);
    }

    /**
     * Exception constructor with throwable reason and message
     *
     * @param message exception message
     * @param reason  Throwable reason
     */
    public MongoQueryException(String message, Throwable reason) {

        super(message, reason);
    }


}
