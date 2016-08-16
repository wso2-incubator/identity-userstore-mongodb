/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.user.store.mongodb.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Date;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.mongodb.DB;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.WriteConcern;
import com.mongodb.DBCursor;
import com.mongodb.WriteResult;
import com.mongodb.AggregationOutput;
import com.mongodb.DBObject;
import com.mongodb.BasicDBObject;
import com.mongodb.DBCollection;
import com.mongodb.MongoException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bson.types.BSONTimestamp;
import org.json.JSONObject;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoQueryException;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoPreparedStatementImpl;
import org.wso2.carbon.identity.user.store.mongodb.userstoremanager.MongoDBRealmConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * MongoDB database operations
 */
@SuppressWarnings({"deprecation", "WeakerAccess", "unused"})
public class MongoDatabaseUtil {

    private static final Log log = LogFactory.getLog(DatabaseUtil.class);
    private static long connectionsCreated;
    private static long connectionsClosed;
    private static ExecutorService executor = null;

    private static DB dataSource = null;

    /**
     * return the realm datasource of user store
     *
     * @param realmConfiguration of user store
     * @return DB connection
     */
    public static synchronized DB getRealmDataSource(RealmConfiguration realmConfiguration) {

        if (dataSource == null) {
            return createRealmDataSource(realmConfiguration);
        } else {
            return dataSource;
        }
    }

    /**
     * @param realmConfiguration of user store
     * @return DB connection
     */
    public static DB createRealmDataSource(RealmConfiguration realmConfiguration) {
        // TODO Auto-generated method stub
        List<ServerAddress> seeds = new ArrayList<ServerAddress>();
        char[] pass;
        int port;
        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD) != null) {
            pass = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PASSWORD).toCharArray();

        } else {
            pass = "admin123".toCharArray();
        }
        List<MongoCredential> credentials = new ArrayList<MongoCredential>();
        String userName;
        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USER_NAME) != null) {

            userName = realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.USER_NAME);
        } else {
            userName = "admin";
        }
        if (realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PORT).length() > 0) {

            port = Integer.parseInt(realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.PORT));
        } else {
            port = 27017;
        }
        seeds.add(new ServerAddress(realmConfiguration.getUserStoreProperty(MongoDBRealmConstants.URL), port));
        credentials.add(
                MongoCredential.createCredential(userName, "wso2_carbon_db", pass)
        );
        MongoClient mongoClient = new MongoClient(seeds, credentials);
        mongoClient.setWriteConcern(WriteConcern.JOURNALED);
        dataSource = mongoClient.getDB("wso2_carbon_db");
        return dataSource;
    }

    /**
     * retrieve integer values from database
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @return int value
     * @throws UserStoreException if any error occurred
     */
    public static int getIntegerValueFromDatabase(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        int value = -1;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
            for (String key : keys) {
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new UserStoreException("Null Data Provided");
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
        } catch (NullPointerException ex) {
            log.error(ex.getMessage(), ex);
            throw new UserStoreException(ex.getMessage(), ex);
        } catch (MongoQueryException ex) {
            log.error(ex.getMessage(), ex);
            log.error("Using JSON Query :" + stmt);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    /**
     * update user role in batch mode to database
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void updateUserRoleMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

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
                if (!key.equals("collection") && !key.equals("projection") && !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new UserStoreException("Null data provided");
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

                    prepStmt.updateBulk();
                } else {

                    prepStmt.insertBulk();
                }
            }
            localConnection = true;
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + stmt + ": and result is"
                        + batchParamIndex);
            }
        } catch (MongoQueryException ex) {

            log.error(ex.getMessage(), ex);
            log.error("Using json : " + stmt);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }


    /**
     * delete user role in batch mode
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void deleteUserRoleMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

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
        } catch (MongoQueryException ex) {

            log.error(ex.getMessage(), ex);
            log.error("Using json : " + stmt);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * delete user in batch mode from database
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void deleteUserMappingInBatchMode(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            int[] userIDS = (int[]) params.get("UM_USER_ID");
            for (int userID : userIDS) {

                prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
                int roleID = (Integer) params.get("UM_ROLE_ID");
                prepStmt.setInt("UM_USER_ID", userID);
                prepStmt.setInt("UM_ROLE_ID", roleID);
                int tenantID = (Integer) params.get("UM_TENANT_ID");
                prepStmt.setInt("UM_TENANT_ID", tenantID);
                prepStmt.remove();
            }
        } catch (MongoQueryException ex) {

            log.error(ex.getMessage(), ex);
            log.error("Using json : " + stmt);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * update database with any modifier
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void updateDatabase(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        WriteResult result;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
            for (String key : keys) {
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                prepStmt.setString(key, null);
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            } else if (entry.getValue() instanceof Date) {
                                Date date = (Date) entry.getValue();
                                BSONTimestamp timestamp = new BSONTimestamp((int) date.getTime(), 1);
                                prepStmt.setTimeStamp(key, timestamp);
                            }
                        }
                    }
                }
            }
            int domainId = getIncrementedSequence(dbConnection, "UM_DOMAIN");
            prepStmt.setInt("UM_DOMAIN_ID", domainId);
            result = updateTrue(keys) ? prepStmt.update() : prepStmt.insert();
            if (log.isDebugEnabled()) {
                log.debug("Executed query is " + stmt + " and number of updated rows :: " + result.getN());
            }
        } catch (MongoQueryException ex) {
            log.error("Error! " + ex.getMessage(), ex);
            log.error("Using json " + stmt);
            throw new UserStoreException("Error! " + ex.getMessage(), ex);
        } catch (Exception e) {
            log.error("Error! " + e.getMessage(), e);
            throw new UserStoreException("Error! " + e.getMessage(), e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    /**
     * delete values from database
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param stmt         query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void deleteFromDatabase(DB dbConnection, String stmt, Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        WriteResult result;
        JSONObject jsonKeys = new JSONObject(stmt);
        List<String> keys = getKeys(jsonKeys);
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, stmt);
            Iterator<String> searchKeys = keys.iterator();
            while (searchKeys.hasNext()) {
                if (!searchKeys.next().equals("collection")) {
                    if (params.get(searchKeys.next()) == null) {
                        prepStmt.setString(searchKeys.next(), null);
                    } else if (params.get(searchKeys.next()) instanceof String) {
                        prepStmt.setString(searchKeys.next(), (String) params.get(searchKeys.next()));
                    } else if (params.get(searchKeys.next()) instanceof Integer) {
                        prepStmt.setInt(searchKeys.next(), (Integer) params.get(searchKeys.next()));
                    } else if (params.get(searchKeys.next()) instanceof Date) {
                        Date date = (Date) params.get(searchKeys.next());
                        BSONTimestamp timestamp = new BSONTimestamp((int) date.getTime(), 1);
                        prepStmt.setTimeStamp(searchKeys.next(), timestamp);
                    }
                }
            }
            result = prepStmt.remove();
            if (log.isDebugEnabled()) {
                log.debug("Executed query is " + stmt + " and number of deleted documents :: " + result.getN());
            }
        } catch (MongoQueryException ex) {
            log.error("Error! " + ex.getMessage(), ex);
            log.error("Using json " + stmt);
            throw new UserStoreException("Error! " + ex.getMessage(), ex);
        } catch (Exception e) {
            log.error("Error! " + e.getMessage(), e);
            throw new UserStoreException("Error! " + e.getMessage(), e);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    /**
     * check whether the query is update query
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
     * retrieve keys from json query
     *
     * @param stmt of JSONObject
     */
    public static List<String> getKeys(JSONObject stmt) {

        int index = 0;
        List<String> keys = new ArrayList<String>();
        Iterator<String> keysfind = stmt.keys();
        while (keysfind.hasNext()) {
            String key = keysfind.next();
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
     * close the connection to database
     *
     * @param dbConnection to close
     */
    public static void closeConnection(DB dbConnection) {

        if (dbConnection != null) {
            try {
                incrementConnectionsClosed();
            } catch (MongoException e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }
    }

    private static void closeStatement(MongoPreparedStatement preparedStatement) {

        if (preparedStatement != null) {
            try {
                preparedStatement.close();
            } catch (Exception e) {
                log.error("Database error. Could not close statement. Continuing with others. - " + e.getMessage(), e);
            }
        }

    }

    private static void closeStatements(MongoPreparedStatement... prepStmts) {

        if (prepStmts != null && prepStmts.length > 0) {
            for (MongoPreparedStatement stmt : prepStmts) {
                closeStatement(stmt);
            }
        }

    }

    /**
     * close the connection to database
     *
     * @param dbConnection to close
     */
    public static void closeAllConnections(DB dbConnection, MongoPreparedStatement... prepStmts) {

        closeStatements(prepStmts);
        closeConnection(dbConnection);
    }

    /**
     * close the connection to database
     *
     * @return long connections created
     */
    public static long getConnectionsCreated() {
        return connectionsCreated;
    }

    /**
     * close the connection to database
     *
     * @return long connections closed
     */
    public static long getConnectionsClosed() {
        return connectionsClosed;
    }

    @SuppressWarnings("unused")
    public static synchronized void incrementConnectionsCreated() {
        if (connectionsCreated != Long.MAX_VALUE) {
            connectionsCreated++;
        }
    }

    public static synchronized void incrementConnectionsClosed() {
        if (connectionsClosed != Long.MAX_VALUE) {
            connectionsClosed++;
        }
    }

    /**
     * log all database connections
     */
    public static void logDatabaseConnections() {
        executor = Executors.newCachedThreadPool();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                executor.shutdownNow();
            }
        });
        final ScheduledExecutorService scheduler =
                Executors.newScheduledThreadPool(10);
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                scheduler.shutdownNow();
            }
        });
        Runnable runnable = new Runnable() {
            public void run() {
                log.debug("Total Number of Connections Created      : " +
                        getConnectionsCreated());
                log.debug("Total Number of Connections Closed       : " +
                        getConnectionsClosed());
            }
        };
        scheduler.scheduleAtFixedRate(runnable, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * update exact user role with params from database
     *
     * @param dbConnection    of user store
     * @param sharedRoles     to update
     * @param mongoQuery      query to execute in mongodb
     * @param currentTenantId current logged in user tenantId
     * @param tenantIds       supplied tenantIds
     * @param userName        given user name
     * @throws UserStoreException if any error occurred
     */
    public static void updateUserRoleMappingWithExactParams(DB dbConnection, String mongoQuery, String[] sharedRoles, String userName, Integer[] tenantIds, int currentTenantId) throws UserStoreException {

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

                if (updateTrue(keys))
                    ps.insert();
                else
                    ps.update();
                ++index;
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoQuery);
            }
        } catch (Exception e) {
            String errorMessage = "Using sql : " + mongoQuery + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, ps);
        }
    }

    /**
     * delete values from database
     *
     * @param dbConnection   of user store
     * @param params         values to filter from database
     * @param mongoQuery     query to execute in mongodb
     * @param isAggregrate   status
     * @param multipleLookUp status
     * @throws UserStoreException if any error occurred
     */
    public static String[] getStringValuesFromDatabase(DB dbConnection, String mongoQuery, Map<String, Object> params, boolean isAggregrate, boolean multipleLookUp) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        String[] values = new String[0];
        JSONObject jsonKeys = new JSONObject(mongoQuery);
        List<String> keys;
        if (isAggregrate) {

            keys = getKeys(jsonKeys.getJSONObject("$match"));
        } else {

            keys = getKeys(jsonKeys);
        }
        try {
            Iterator<String> searchKeys = keys.iterator();
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            while (searchKeys.hasNext()) {
                String key = searchKeys.next();
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
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
            if (!isAggregrate) {
                DBCursor cursor = prepStmt.find();
                List<String> lst = new ArrayList<String>();
                while (cursor.hasNext()) {
                    lst.add(cursor.next().toString());
                }
                if (lst.size() > 0) {
                    values = lst.toArray(new String[lst.size()]);
                }
            } else {
                prepStmt.multiLookUp(multipleLookUp);
                AggregationOutput result = prepStmt.aggregate();
                Iterable<DBObject> ite = result.results();
                List<String> lst = new ArrayList<String>();
                Iterator<DBObject> foundResults = ite.iterator();
                List<String> projection = getKeys(jsonKeys.getJSONObject("$project"));
                String projectionKey = "";
                for (String pkey : projection) {

                    if (pkey.equals("_id")) {

                        continue;
                    }
                    projectionKey = pkey;
                }
                while (foundResults.hasNext()) {

                    lst.add(foundResults.next().get(projectionKey).toString());
                }
                if (lst.size() > 0) {
                    values = lst.toArray(new String[lst.size()]);
                }
            }
            return values;
        } catch (NullPointerException ex) {
            log.error(ex.getMessage(), ex);
            throw new UserStoreException(ex.getMessage(), ex);
        } catch (MongoQueryException ex) {
            log.error(ex.getMessage(), ex);
            log.error("Using JSON Query :" + mongoQuery);
            throw new UserStoreException(ex.getMessage(), ex);
        } catch (org.wso2.carbon.user.api.UserStoreException ex) {
            log.error(ex.getMessage(), ex);
            log.error("Using JSON Query :" + mongoQuery);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }
    }

    public static void udpateUserRoleMappingInBatchModeForInternalRoles(DB dbConnection, String mongoStmt, String primaryDomain, Object... params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            int batchParamIndex = -1;
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String[]) {
                        batchParamIndex = i;
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i + 1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i + 1), (Integer) param);
                    }
                }
            }
            int[] count = new int[batchParamIndex];
            if (batchParamIndex != -1) {
                String[] values = (String[]) params[batchParamIndex];
                int i = 0;
                for (String value : values) {
                    String strParam = value;
                    //add domain if not set
                    strParam = UserCoreUtil.addDomainToName(strParam, primaryDomain);
                    //get domain from name
                    String domainParam = UserCoreUtil.extractDomainFromName(strParam);
                    if (domainParam != null) {
                        domainParam = domainParam.toUpperCase();
                    }
                    //set domain to mongodb
                    prepStmt.setString(keys.get(params.length + 1), domainParam);
                    //remove domain before persisting
                    String nameWithoutDomain = UserCoreUtil.removeDomainFromName(strParam);
                    //set name in mongodb
                    prepStmt.setString(keys.get(batchParamIndex + 1), nameWithoutDomain);
                    WriteResult result = prepStmt.update();
                    count[i] = result.getN();
                    i++;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoStmt + ": and result is"
                        + Arrays.toString(count));
            }
        } catch (MongoQueryException e) {
            String errorMessage = "Using Mongo Query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeConnection(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    public static String[] getStringValuesFromDatabaseForInternalRoles(DB dbConnection, String mongoStmt, Object... params) throws UserStoreException {

        String[] values = new String[0];
        MongoPreparedStatement prepStmt;
        DBCursor cursor;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i + 1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i + 1), (Integer) param);
                    }
                }
            }
            cursor = prepStmt.find();
            List<String> lst = new ArrayList<String>();
            while (cursor.hasNext()) {
                String name = cursor.next().get(keys.get(1)).toString();
                String domain = cursor.next().get(keys.get(2)).toString();
                if (domain != null) {
                    name = UserCoreUtil.addDomainToName(name, domain);
                }
                lst.add(name);
            }
            if (lst.size() > 0) {
                values = lst.toArray(new String[lst.size()]);
            }
            return values;
        } catch (MongoQueryException e) {
            String errorMessage = "Using mongo query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * update user role mapping in batch mode
     *
     * @param dbConnection of user store
     * @param params       values to filter from database
     * @param mongoStmt    query to execute in mongodb
     * @throws UserStoreException if any error occurred
     */
    public static void udpateUserRoleMappingInBatchMode(DB dbConnection, String mongoStmt, Object... params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoStmt);
            JSONObject jsonKeys = new JSONObject(mongoStmt);
            List<String> keys = getKeys(jsonKeys);
            int batchParamIndex = -1;
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Null data provided.");
                    } else if (param instanceof String[]) {
                        batchParamIndex = i;
                    } else if (param instanceof String) {
                        prepStmt.setString(keys.get(i + 1), (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(keys.get(i + 1), (Integer) param);
                    }
                }
            }
            int count[] = new int[batchParamIndex];
            WriteResult result;
            if (batchParamIndex != -1) {
                String[] values = (String[]) params[batchParamIndex];
                int i = 0;
                for (String value : values) {
                    prepStmt.setString(keys.get(batchParamIndex + 1), value);
                    result = prepStmt.update();
                    count[i] = result.getN();
                    i++;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Executed a batch update. Query is : " + mongoStmt + ": and result is"
                        + Arrays.toString(count));
            }
        } catch (MongoQueryException e) {
            String errorMessage = "Using mongo query : " + mongoStmt + " " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            if (localConnection) {
                MongoDatabaseUtil.closeAllConnections(dbConnection);
            }
            MongoDatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

    /**
     * get auto increment sequence
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

            collect.update(new BasicDBObject("name", collection), new BasicDBObject("$set", new BasicDBObject("seq", ++seq)));
        }
        return seq;
    }

    /**
     * get distinct string value of key in document
     *
     * @param dbConnection of user store
     * @param mongoQuery   to execute
     * @param params       to filter from database
     * @return String[] distinct string values
     */
    public static String[] getDistinctStringValuesFromDatabase(DB dbConnection, String mongoQuery, Map<String, Object> params) throws UserStoreException {

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
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
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
        } catch (NullPointerException ex) {
            log.error(ex.getMessage(), ex);
            throw new UserStoreException(ex.getMessage(), ex);
        } catch (MongoQueryException ex) {
            log.error(ex.getMessage(), ex);
            log.error("Using JSON Query :" + mongoQuery);
            throw new UserStoreException(ex.getMessage(), ex);
        } finally {
            MongoDatabaseUtil.closeAllConnections(dbConnection, prepStmt);
        }

    }
}
