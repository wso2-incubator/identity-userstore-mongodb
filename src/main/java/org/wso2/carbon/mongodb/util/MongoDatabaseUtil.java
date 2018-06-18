/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.mongodb.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.DBCursor;
import com.mongodb.BulkWriteResult;
import com.mongodb.AggregationOutput;
import com.mongodb.DBObject;
import com.mongodb.BasicDBObject;
import com.mongodb.DBCollection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import org.wso2.carbon.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.mongodb.query.MongoDBQueryException;
import org.wso2.carbon.mongodb.user.store.mgt.MongoDBRealmConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreException;

/**
 * MongoDB database operations
 */
public class MongoDatabaseUtil {

    private static final Log log = LogFactory.getLog(MongoDatabaseUtil.class);
    private static long connectionsClosed;

    private static DB db = null;

    /**
     * Return the realm data source of user store.
     *
     * @param realmConfiguration of user store
     * @return DB connection
     * @throws UserStoreException if any error occurred
     */
    public static synchronized DB getRealmDataSource(RealmConfiguration realmConfiguration) throws UserStoreException {
        try {
            return (db == null ? createRealmDataSource(realmConfiguration) : db);
        } catch (UserStoreException e) {
            throw new UserStoreException("Failed to retrieve realm data source", e);
        }
    }

    /**
     * @param realmConfiguration of user store
     * @return DB connection
     * @throws UserStoreException if any error occurred
     */
    public static DB createRealmDataSource(RealmConfiguration realmConfiguration) throws UserStoreException {
        String password;
        String url;
        String username;

        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.URL) != null) {
            url = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.URL);
        } else {
            throw new UserStoreException("Required property '" + MongoDBRealmConstants.URL +
                    "' not found for the primary UserStoreManager in user_mgt.xml. Cannot start server!");
        }

        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USERNAME) != null) {
            username = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USERNAME);
        } else {
            throw new UserStoreException("Required property '" + MongoDBRealmConstants.USERNAME +
                    "' not found for the primary UserStoreManager in user_mgt.xml. Cannot start server!");
        }

        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD) != null) {
            password = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD);
        } else {
            throw new UserStoreException("Required property '" + MongoDBRealmConstants.PASSWORD +
                    "' not found for the primary UserStoreManager in user_mgt.xml. Cannot start server!");
        }

        String urlWithCredentials = url.replaceFirst("://", "://" + username + ":" + password + "@");

        MongoClientURI clientURI = new MongoClientURI(urlWithCredentials);
        MongoClient mongoClient = new MongoClient(clientURI);

        //noinspection ConstantConditions
        if (clientURI.getDatabase() == null) {
            if (log.isDebugEnabled()) {
                log.debug("URL provided: " + clientURI);
            }
            throw new UserStoreException("Property '" + MongoDBRealmConstants.URL +
                    "' provided in user_mgt.xml does not contain the database name. Cannot start server!");
        }

        //noinspection deprecation
        db = mongoClient.getDB(clientURI.getDatabase());
        return db;
    }

    /**
     * Retrieve integer values from database.
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @return int value
     * @throws MongoDBQueryException if null data provided to mongodb query
     */
    public static int getIntegerValueFromDatabase(DB dbConnection, String stmt, Map<String, Object> params)
            throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        int value = -1;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
            for (String key : keys) {
                if (!(key.equals("collection") || key.equals("projection"))) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new MongoDBQueryException("Null Data Provided as the query parameter");
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            }
                        }
                    }
                }
            }
            DBCursor cursor = prepStmt.find();
            while (cursor.hasNext()) {
                value = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
            }
            return value;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to retrieve integer values from database", e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    /**
     * Update user role in batch mode to database.
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws MongoDBQueryException if null data provided to mongodb query or any other query error occurred
     */
    public static void updateUserRoleMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params)
            throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
            int batchParamIndex = -1;
            Iterator<String> searchKeys = keys.iterator();
            int[] values = null;
            String listKey = "";
            while (searchKeys.hasNext()) {
                String key = searchKeys.next();
                if (!(key.equals("collection") || key.equals("projection") || key.equals("$set"))) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new MongoDBQueryException("Null Data Provided as the query parameter");
                            } else if (entry.getValue() instanceof int[]) {
                                values = (int[]) entry.getValue();
                                batchParamIndex = 1;
                                listKey = key;
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            }
                        }
                    }
                }
            }
            if (batchParamIndex != -1) {
                for (int value : values) {
                    if (value > 0) {
                        prepStmt.setInt(listKey, value);
                        if (updateTrue(keys)) {
                            prepStmt.updateBatch();
                        } else {
                            int Id = MongoDatabaseUtil.getIncrementedSequence(dbConnection, "UM_USER_ROLE");
                            prepStmt.setInt("UM_ID", Id);
                            prepStmt.addBatch();
                        }
                    }
                }
                if (updateTrue(keys)) {
                    BulkWriteResult updateResult = prepStmt.updateBulk();
                    if (log.isDebugEnabled()) {
                        log.debug("Bulk update results: " + updateResult);
                    }
                } else {
                    BulkWriteResult insertResult = prepStmt.insertBulk();
                    if (log.isDebugEnabled()) {
                        log.debug("Bulk insert results: " + insertResult);
                    }
                }
            }
            localConnection = true;
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query: " + stmt + "; Status: " + batchParamIndex);
            }
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to update user role mapping in batch mode", e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }


    /**
     * Delete user role in batch mode.
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws MongoDBQueryException if remove operation of MongoPreparedStatement fails
     */
    public static void deleteUserRoleMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params)
            throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            int[] roleIDS = (int[]) params.get("UM_ROLE_ID");
            for (int roleID : roleIDS) {
                prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
                int userID = (Integer) params.get("UM_USER_ID");
                prepStmt.setInt("UM_USER_ID", userID);
                prepStmt.setInt("UM_ROLE_ID", roleID);
                int tenantID = (Integer) params.get("UM_TENANT_ID");
                prepStmt.setInt("UM_TENANT_ID", tenantID);
                prepStmt.remove();
            }
            localConnection = true;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to delete user role mapping in batch mode", e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * Delete user in batch mode from database.
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws MongoDBQueryException if remove operation of MongoPreparedStatement fails
     */
    public static void deleteUserMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params)
            throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            int[] userIDS = (int[]) params.get("UM_USER_ID");
            for (int userID : userIDS) {
                prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
                int roleID = (Integer) params.get("UM_ROLE_ID");
                prepStmt.setInt("UM_USER_ID", userID);
                prepStmt.setInt("UM_ROLE_ID", roleID);
                Object roleTenantValue = params.get("UM_ROLE_TENANT_ID");
                Object userTenantValue = params.get("UM_USER_TENANT_ID");
                Object tenantValue = params.get("UM_TENANT_ID");

                if (roleTenantValue != null) {
                    int roleTenantId = (Integer) roleTenantValue;
                    prepStmt.setInt("UM_ROLE_TENANT_ID", roleTenantId);
                }
                if (userTenantValue != null) {
                    int userTenantId = (Integer) userTenantValue;
                    prepStmt.setInt("UM_USER_TENANT_ID", userTenantId);
                }
                if (tenantValue != null) {
                    int tenantId = (Integer) tenantValue;
                    prepStmt.setInt("UM_TENANT_ID", tenantId);
                }
                prepStmt.remove();
            }
            localConnection = true;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to delete user mapping in batch mode", e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * Check whether the query is update query.
     *
     * @param keys of json query
     * @return boolean status
     */
    public static boolean updateTrue(List<String> keys) {
        for (String key : keys) {
            if (key.contains("$set")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieve keys from json query.
     *
     * @param stmt of JSONObject
     */
    public static List<String> getKeys(JSONObject stmt) {
        int index = 0;
        List<String> keys = new ArrayList<>();
        Iterator<String> keysFind = stmt.keys();
        while (keysFind.hasNext()) {
            String key = keysFind.next();
            keys.add(index, key);
            if (stmt.get(key) instanceof JSONObject) {
                JSONObject value = stmt.getJSONObject(key);
                key = value.keys().next();
                if (key.equals("$set")) {

                    String names[] = JSONObject.getNames(value.getJSONObject(key));
                    for (String name : names) {

                        keys.add(index, name);
                        index++;
                    }
                }
                keys.add(index, key);
            }
            index++;
        }
        return keys;
    }

    /**
     * Close the DB connection
     *
     * @param dbConnection to close
     */
    public static void closeConnection(DB dbConnection) {
        if (dbConnection != null) {
            incrementConnectionsClosed();
        }
    }

    private static void closeStatement(MongoPreparedStatement preparedStatement) {
        if (preparedStatement != null) {
            preparedStatement.close();
        }
    }

    private static void closeStatements(MongoPreparedStatement... prepStatements) {
        if (prepStatements != null && prepStatements.length > 0) {
            for (MongoPreparedStatement stmt : prepStatements) {
                closeStatement(stmt);
            }
        }
    }

    /**
     * Close the connection to the database
     *
     * @param dbConnection to be closed
     */
    private static void closeAllConnections(DB dbConnection, MongoPreparedStatement... prepStatements) {
        closeStatements(prepStatements);
        closeConnection(dbConnection);
    }

    private static synchronized void incrementConnectionsClosed() {
        if (connectionsClosed != Long.MAX_VALUE) {
            connectionsClosed++;
        }
    }

    /**
     * Update exact user role with params from database.
     *
     * @param dbConnection    of user store
     * @param sharedRoles     to update
     * @param mongoQuery      query to execute in mongodb
     * @param currentTenantId current logged in user tenantId
     * @param tenantIds       supplied tenantIds
     * @param userName        given user name
     * @throws MongoDBQueryException if insert or update operation of MongoPreparedStatement fails
     */
    public static void updateUserRoleMappingWithExactParams(DB dbConnection, String mongoQuery, String[] sharedRoles,
                                                            String userName, Integer[] tenantIds, int currentTenantId)
            throws MongoDBQueryException {

        MongoPreparedStatement ps = null;
        boolean localConnection = false;
        try {
            ps = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            JSONObject jsonKeys = new JSONObject(mongoQuery);
            List<String> keys = getKeys(jsonKeys);
            byte count;
            byte index = 0;
            for (String role : sharedRoles) {
                count = 0;
                ps.setString(keys.get(++count), role);
                ps.setInt(keys.get(++count), tenantIds[index]);
                ps.setString(keys.get(++count), userName);
                ps.setInt(keys.get(++count), currentTenantId);
                ps.setInt(keys.get(++count), currentTenantId);
                ps.setInt(keys.get(++count), tenantIds[index]);
                if (updateTrue(keys)) {
                    ps.insert();
                } else {
                    ps.update();
                }
                ++index;
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query: " + mongoQuery);
            }
            localConnection = true;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to update exact user role", e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, ps);
        }
    }

    /**
     * Retrieve string values from database.
     *
     * @param dbConnection   of user store
     * @param params         values to filter from database
     * @param mongoQuery     query to execute in mongodb
     * @param isAggregate    status
     * @param multipleLookUp status
     * @throws MongoDBQueryException if find operation of MongoPreparedStatement fails
     */
    public static String[] getStringValuesFromDatabase(DB dbConnection, String mongoQuery, Map<String, Object> params,
                                                       boolean isAggregate, boolean multipleLookUp)
            throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        String[] values = new String[0];
        JSONObject jsonKeys = new JSONObject(mongoQuery);
        List<String> keys;
        if (isAggregate) {
            keys = getKeys(jsonKeys.getJSONObject("$match"));
        } else {
            keys = getKeys(jsonKeys);
        }
        try {
            Iterator<String> searchKeys = keys.iterator();
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            while (searchKeys.hasNext()) {
                String key = searchKeys.next();
                if (!(key.equals("collection") || key.equals("projection"))) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (params.get(key) == null) {
                                prepStmt.setString(key, null);
                            } else if (params.get(key) instanceof String) {
                                prepStmt.setString(key, (String) params.get(key));
                            } else if (params.get(key) instanceof Integer) {
                                prepStmt.setInt(key, (Integer) params.get(key));
                            }
                        }
                    }
                }
            }
            if (!isAggregate) {
                DBCursor cursor = prepStmt.find();
                List<String> lst = new ArrayList<>();
                while (cursor.hasNext()) {
                    lst.add(cursor.next().toString());
                }
                if (lst.size() > 0) {
                    values = lst.toArray(new String[lst.size()]);
                }
            } else {
                prepStmt.setMultiLookUp(multipleLookUp);
                //noinspection deprecation
                AggregationOutput result = prepStmt.aggregate();
                Iterable<DBObject> ite = result.results();
                List<String> lst = new ArrayList<>();
                Iterator<DBObject> foundResults = ite.iterator();
                List<String> projection = getKeys(jsonKeys.getJSONObject("$project"));
                String projectionKey = "";
                for (String pKey : projection) {
                    if (pKey.equals("_id")) {
                        continue;
                    }
                    projectionKey = pKey;
                }
                while (foundResults.hasNext()) {
                    lst.add(foundResults.next().get(projectionKey).toString());
                }
                if (lst.size() > 0) {
                    values = lst.toArray(new String[lst.size()]);
                }
            }
            return values;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to retrieve the string values from database", e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    /**
     * Get auto increment sequence.
     *
     * @param dbConnection of user store
     * @param collection   to auto increment
     * @return int sequence
     */
    public static int getIncrementedSequence(DB dbConnection, String collection) {
        DBObject checkObject = new BasicDBObject("name", collection);
        DBCollection collect = dbConnection.getCollection("COUNTERS");
        DBCursor cursor = collect.find(checkObject);
        int seq = 0;
        boolean isEmpty = true;
        while (cursor.hasNext()) {
            double value = Double.parseDouble(cursor.next().get("seq").toString());
            seq = (int) value;
            isEmpty = false;
        }
        if (isEmpty) {
            collect.insert(new BasicDBObject("name", collection).append("seq", ++seq));
        } else {
            collect.update(new BasicDBObject("name", collection), new BasicDBObject("$set",
                    new BasicDBObject("seq", ++seq)));
        }
        return seq;
    }

    /**
     * Get distinct string value of key in document.
     *
     * @param dbConnection of user store
     * @param mongoQuery   to execute
     * @param params       to filter from database
     * @return String[] distinct string values
     *
     * @throws MongoDBQueryException if distinct operation of MongoPreparedStatement fails
     */
    public static String[] getDistinctStringValuesFromDatabase(DB dbConnection, String mongoQuery, Map<String,
            Object> params) throws MongoDBQueryException {

        MongoPreparedStatement prepStmt = null;
        String[] values = new String[0];
        JSONObject jsonKeys = new JSONObject(mongoQuery);
        List<String> keys;
        keys = getKeys(jsonKeys);
        try {
            Iterator<String> searchKeys = keys.iterator();
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            while (searchKeys.hasNext()) {
                String key = searchKeys.next();
                if (!(key.equals("collection") || key.equals("projection"))) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (params.get(key) == null) {
                                prepStmt.setString(key, null);
                            } else if (params.get(key) instanceof String) {
                                prepStmt.setString(key, (String) params.get(key));
                            } else if (params.get(key) instanceof Integer) {
                                prepStmt.setInt(key, (Integer) params.get(key));
                            }
                        }
                    }
                }
            }
            List result = prepStmt.distinct();
            if (!result.isEmpty()) {

                values = new String[result.size()];
                int index = 0;
                for (Object res : result) {

                    values[index] = res.toString();
                    index++;
                }
            }
            return values;
        } catch (MongoDBQueryException e) {
            throw new MongoDBQueryException("Failed to get distinct string values from database", e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }
}
