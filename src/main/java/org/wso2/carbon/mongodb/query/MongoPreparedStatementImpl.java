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

package org.wso2.carbon.mongodb.query;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.BulkWriteOperation;
import com.mongodb.WriteResult;
import com.mongodb.DBCursor;
import com.mongodb.AggregationOutput;
import com.mongodb.BasicDBObject;
import com.mongodb.BulkWriteRequestBuilder;
import com.mongodb.BulkWriteResult;
import com.mongodb.BulkUpdateRequestBuilder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * MongoDB Prepared Statement interface implementation class
 */
public class MongoPreparedStatementImpl implements MongoPreparedStatement {

    private static final Log log = LogFactory.getLog(MongoPreparedStatementImpl.class);

    private static final String MONGO_REGEX_FIELD = "$regex";
    private static final String MONGO_OPTIONS_FIELD = "$options";
    private static final String MONGO_LOOKUP_FIELD = "$lookup";
    private static final String MONGO_CASE_INSENSITIVE_OPTION = "i";
    private static final String MONGO_PROJECTION_FIELD = "projection";
    private static final String MONGO_COLLECTION_FIELD = "collection";
    private static final String MONGO_DISTINCT_FIELD = "distinct";
    private static final String MONGO_SET_FIELD = "$set";
    private static final String MONGO_PROJECT_FIELD = "$project";
    private static final String MONGO_SORT_FIELD = "$sort";
    private static final String MONGO_GROUP_FIELD = "$group";
    private static final String MONGO_UNWIND_FIELD = "$unwind";
    private static final String MONGO_LOOKUP_SUB = "$lookup_sub";
    private static final String MONGO_UNWIND_SUB = "$unwind_sub";
    private static final String MONGO_DEPENDENCY_FIELD = "dependency";
    private static final String MONGO_MATCH_FIELD = "$match";
    private static final String UM_USER_NAME = "UM_USER_NAME";

    private DB db = null;
    private DBCollection collection = null;
    private DBObject query = null;
    private DBObject projection;
    private String defaultQuery;
    private HashMap<String, Object> parameterValue;
    private JSONObject queryJson;
    private int parameterCount;
    private Map<String, Object> mapQuery = null;
    private Map<String, Object> mapProjection = null;
    private Map<String, Object> mapMatch = null;
    private Map<String, Object> mapProject = null;
    private Map<String, Object> mapSort = null;
    private Map<String, Object> mapLookUp = null;
    private Map<String, Object> mapGroup = null;
    private Map<String, Object> mapUnwind = null;
    private BulkWriteOperation bulkWrite = null;
    private boolean multipleLookUpStatus = false;
    private ArrayList<Map<String, Object>> multiMapLookup;
    private ArrayList<Map<String, Object>> multiMapUnwind;
    private String distinctKey;
    private boolean isCaseSensitive;
    private Map<String, Object> mapMatchCaseInSensitive = null;
    private Map<String, Object> mapCaseQuery = null;

    /**
     * Constructor with two arguments
     *
     * @param db    DB connection to mongodb
     * @param query to execute
     */
    public MongoPreparedStatementImpl(DB db, String query) {
        if (this.db == null) {
            this.db = db;
        }
        if (mapQuery == null && mapProjection == null) {
            mapQuery = new HashMap<>();
            mapProjection = new HashMap<>();
        }
        if (mapMatch == null) {
            mapMatch = new HashMap<>();
        }
        this.multiMapLookup = new ArrayList<>();
        this.multiMapUnwind = new ArrayList<>();
        this.defaultQuery = query;
        this.queryJson = new JSONObject(defaultQuery);
        this.parameterValue = new HashMap<>();
        this.projection = null;
        this.parameterCount = 0;
        this.distinctKey = "";
        this.isCaseSensitive = true;

        if (mapMatchCaseInSensitive == null) {
            this.mapMatchCaseInSensitive = new HashMap<>();
        }
        if (mapCaseQuery == null) {
            this.mapCaseQuery = new HashMap<>();
        }
        if (query.contains(MONGO_LOOKUP_FIELD)) {
            setMultiLookUp(true);
        }
        if (log.isDebugEnabled()) {
            log.info("Is multiple lookup enabled for the prepared statement: " + isMultipleLookUp());
        }
    }

    /**
     * Convert JSON Object to Map Object
     *
     * @param object to convert
     * @return Map object
     */
    private static Map<String, Object> toMap(JSONObject object) {
        Map<String, Object> map = new HashMap<>();

        Iterator<String> keysItr = object.keys();
        while (keysItr.hasNext()) {
            String key = keysItr.next();
            Object value = object.get(key);

            if (value instanceof JSONArray) {
                value = toList((JSONArray) value);
            } else if (value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            map.put(key, value);
        }
        return map;
    }

    /**
     * Convert JSON Array to List Object
     *
     * @param array to convert to List
     * @return List object
     */
    private static List<Object> toList(JSONArray array) {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            Object value = array.get(i);
            if (value instanceof JSONArray) {
                value = toList((JSONArray) value);
            } else if (value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            list.add(value);
        }
        return list;
    }

    public void close() {
        this.db = null;
        this.collection = null;
        this.query = null;
        this.projection = null;
        this.parameterValue = null;
        this.defaultQuery = null;
        this.queryJson = null;
        this.parameterCount = 0;
        this.mapQuery = null;
        this.mapProjection = null;
        this.mapMatch = null;
        this.mapLookUp = null;
        this.mapProject = null;
        this.mapSort = null;
        this.mapGroup = null;
        this.mapUnwind = null;
        this.bulkWrite = null;
        this.multiMapUnwind = null;
        this.multiMapLookup = null;
        this.distinctKey = "";
        this.isCaseSensitive = true;
        this.mapMatchCaseInSensitive = null;
        this.mapCaseQuery = null;
    }

    public void setInt(String key, int parameter) {
        parameterValue.put(key, parameter);
    }

    public void setString(String key, String parameter) {
        parameterValue.put(key, parameter);
    }

    public void setDate(String key, Date date) {
        parameterValue.put(key, date);
    }

    public void setBoolean(String key, boolean parameter) {
        parameterValue.put(key, parameter);
    }

    public WriteResult insert() throws MongoDBQueryException {
        if (!matchArguments(this.queryJson)) {
            throw new MongoDBQueryException("Parameter count mismatch");
        } else {
            if (convertToDBObject(defaultQuery)) {
                return this.collection.insert(this.query);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Using query: " + defaultQuery);
                }
                throw new MongoDBQueryException("Invalid query format - no collection found");
            }
        }
    }

    public void setMultiLookUp(boolean status) {
        multipleLookUpStatus = status;
    }

    public DBCursor find() throws MongoDBQueryException {
        if (!matchArguments(this.queryJson)) {
            throw new MongoDBQueryException("Parameter count mismatch");
        } else {
            if (convertToDBObject(defaultQuery)) {
                if (this.projection == null && this.query == null) {
                    return this.collection.find();
                } else if (this.projection == null) {
                    return this.collection.find(this.query);
                } else {
                    return this.collection.find(this.query, this.projection);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Using query: " + defaultQuery);
                }
                throw new MongoDBQueryException("Invalid query format - no collection found");
            }
        }
    }

    public List distinct() throws MongoDBQueryException {
        if (!matchArguments(this.queryJson)) {
            throw new MongoDBQueryException("Parameter count mismatch");
        } else {
            if (convertToDBObject(defaultQuery)) {
                return this.collection.distinct(this.distinctKey, this.query);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Using query: " + defaultQuery);
                }
                throw new MongoDBQueryException("Invalid query format - no collection found");
            }
        }
    }

    @SuppressWarnings("deprecation")
    public AggregationOutput aggregate() {
        JSONObject defaultObject = new JSONObject(defaultQuery);
        getAggregationObjects(defaultObject);
        List<DBObject> pipeline = new ArrayList<>();

        // Add lookup attribute to pipeline
        if (mapLookUp != null) {
            addLookUpAttribute(pipeline);
        }
        // Add unwind attribute to pipeline
        if (mapUnwind != null) {
            addUnwindAttribute(pipeline);
        }
        // Add match attribute to pipeline
        if (mapMatch != null) {
            addMatchAttribute(pipeline);
        }
        // Add sort attribute to pipeline
        if (mapSort != null) {
            addSortAttribute(pipeline);
        }
        // Add group attribute to pipeline
        if (mapGroup != null) {
            addGroupAttribute(pipeline);
        }
        // Add project attribute to pipeline
        if (mapProject != null) {
            addProjectAttribute(pipeline);
        }
        return this.collection.aggregate(pipeline);
    }

    public WriteResult update() throws MongoDBQueryException {
        if (!matchArguments(this.queryJson)) {
            throw new MongoDBQueryException("Parameter count mismatch");
        } else {
            if (convertToDBObject(defaultQuery)) {
                return this.collection.update(this.query, new BasicDBObject(MONGO_SET_FIELD, this.projection));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Using query: " + defaultQuery);
                }
                throw new MongoDBQueryException("Invalid query format - no collection found");
            }
        }
    }

    public WriteResult remove() throws MongoDBQueryException {
        if (!matchArguments(this.queryJson)) {
            throw new MongoDBQueryException("Parameter count mismatch");
        } else {
            if (convertToDBObject(defaultQuery)) {
                return this.collection.remove(this.query);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Using query: " + defaultQuery);
                }
                throw new MongoDBQueryException("Invalid query format - no collection found");
            }
        }
    }

    public BulkWriteResult insertBulk() {
        return this.bulkWrite.execute();
    }

    public BulkWriteResult updateBulk() {
        return this.bulkWrite.execute();
    }

    public void addBatch() throws MongoDBQueryException {
        if (convertToDBObject(defaultQuery)) {
            if (bulkWrite == null) {
                bulkWrite = this.collection.initializeUnorderedBulkOperation();
            }
            bulkWrite.insert(this.query);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using query: " + defaultQuery);
            }
            throw new MongoDBQueryException("Invalid query format - no collection specified");
        }

    }

    public void updateBatch() throws MongoDBQueryException {
        if (convertToDBObject(defaultQuery)) {
            if (bulkWrite == null) {
                bulkWrite = this.collection.initializeUnorderedBulkOperation();
            }
            BulkWriteRequestBuilder bulkWriteRequestBuilder = bulkWrite.find(this.query);
            BulkUpdateRequestBuilder updateReq = bulkWriteRequestBuilder.upsert();
            updateReq.replaceOne(this.projection);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using query: " + defaultQuery);
            }
            throw new MongoDBQueryException("Invalid query format - no collection specified");
        }
    }

    /**
     * Check whether the provided arguments are equal to the parameters in json query
     *
     * @param query type JSONObject
     * @return boolean status whether the argument correct or not
     */
    private boolean matchArguments(JSONObject query) {
        // Iterate over json query and match the query parameters with given values
        Iterator<String> keys = query.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            try {
                JSONObject value = query.getJSONObject(key);
                matchArguments(value);
            } catch (Exception e) {
                if (query.get(key).equals("?")) {
                    this.parameterCount++;
                }
            }
        }
        return parameterValue.size() == this.parameterCount;
    }

    /**
     * String JSON formatted query convert to DBObject
     *
     * @param query to execute
     * @return boolean status
     */
    private boolean convertToDBObject(String query) {
        JSONObject queryObject = new JSONObject(query);
        if (queryObject.has(MONGO_COLLECTION_FIELD)) {
            String collection = queryObject.getString(MONGO_COLLECTION_FIELD);
            this.collection = this.db.getCollection(collection);
            queryObject.remove(MONGO_COLLECTION_FIELD);
            // Check whether the query has distinct key word
            if (queryObject.has(MONGO_DISTINCT_FIELD)) {
                this.distinctKey = queryObject.getString(MONGO_DISTINCT_FIELD);
            }
            // If query has $set attribute then query will be update query
            if (query.contains(MONGO_SET_FIELD)) {
                getUpdateObject(queryObject);
            } else {
                setQueryObject(queryObject, false);
            }
            return true;
        }
        return false;

    }

    /**
     * set passed values to query parameters
     *
     * @param object to execute
     * @param status boolean status
     */
    private void setQueryObject(JSONObject object, boolean status) {
        boolean hasProjection = status;
        Iterator<String> keys = object.keys();
        //set query parameter values with given values
        while (keys.hasNext()) {
            String key = keys.next();
            Object val = null;
            try {
                JSONObject value = object.getJSONObject(key);
                if (key.equals(MONGO_PROJECTION_FIELD)) {
                    hasProjection = true;
                }
                setQueryObject(value, hasProjection);
            } catch (Exception e) {
                // If a case insensitive then check for $regex attribute
                if (key.equals(MONGO_REGEX_FIELD)) {
                    key = UM_USER_NAME;
                    this.isCaseSensitive = false;
                }
                // Replace query parameter with respective value
                if (parameterValue.containsKey(key)) {
                    val = parameterValue.get(key);
                }
            }
            if (val != null && !val.equals("%")) {
                if (!this.isCaseSensitive) {
                    if (key.equals(UM_USER_NAME)) {
                        mapCaseQuery.put(MONGO_REGEX_FIELD, val);
                        mapCaseQuery.put(MONGO_OPTIONS_FIELD, MONGO_CASE_INSENSITIVE_OPTION);
                    } else {
                        mapQuery.put(key, val);
                    }
                } else {
                    mapQuery.put(key, val);
                }
            }
            if (hasProjection && !key.equals(MONGO_PROJECTION_FIELD)) {
                mapProjection.put(key, object.get(key));
            }
        }
        if (this.isCaseSensitive) {
            this.query = new BasicDBObject(mapQuery);
        } else {
            this.query = new BasicDBObject(mapQuery).append(UM_USER_NAME, mapCaseQuery);
        }
        if (!mapProjection.isEmpty()) {
            this.projection = new BasicDBObject(mapProjection);
        }
    }

    /**
     * get the updated object
     *
     * @param object to update
     */
    private void getUpdateObject(JSONObject object) {
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object val;
            if (key.equals(MONGO_PROJECTION_FIELD)) {
                JSONObject setObject = object.getJSONObject(key);
                setUpdateObject(setObject.getJSONObject(MONGO_SET_FIELD));
            } else {
                if (parameterValue.containsKey(key)) {
                    val = parameterValue.get(key);
                    mapQuery.put(key, val);
                }
            }
        }
        this.query = new BasicDBObject(mapQuery);
    }

    /**
     * Convert JSON Query to Aggregation Pipeline Object
     *
     * @param stmt JSONObject
     */
    private void getAggregationObjects(JSONObject stmt) {

        Iterator<String> keys = stmt.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (key.equals(MONGO_COLLECTION_FIELD)) {
                this.collection = db.getCollection(stmt.get(key).toString());
            } else {
                JSONObject value = stmt.getJSONObject(key);
                if (key.equals(MONGO_LOOKUP_FIELD) || key.contains(MONGO_LOOKUP_SUB)) {
                    if (isMultipleLookUp()) {
                        mapLookUp = toMap(value);
                    } else {
                        mapLookUp = toMap(value);
                        multiMapLookup.add(mapLookUp);
                    }
                } else if (key.equals(MONGO_PROJECT_FIELD)) {
                    mapProject = toMap(value);
                } else if (key.equals(MONGO_SORT_FIELD)) {
                    mapSort = toMap(value);
                } else if (key.equals(MONGO_GROUP_FIELD)) {
                    mapGroup = toMap(value);
                } else if (key.equals(MONGO_UNWIND_FIELD) || key.equals(MONGO_UNWIND_SUB)) {
                    if (isMultipleLookUp()) {
                        mapUnwind = toMap(value);
                    } else {
                        mapUnwind = toMap(value);
                        multiMapUnwind.add(mapUnwind);
                    }
                } else {
                    setMatchObject(value);
                }
            }
        }
    }

    /**
     * set object parameter with passed values
     *
     * @param stmt to set values
     */
    private void setMatchObject(JSONObject stmt) {

        String[] elementNames = JSONObject.getNames(stmt);
        for (String elementName : elementNames) {
            Object value = stmt.get(elementName);
            if (parameterValue.containsKey(elementName)) {
                Object val = parameterValue.get(elementName);
                if (!(value instanceof JSONObject) && !val.equals("%")) {
                    mapMatch.put(elementName, val);
                } else {
                    if (value instanceof JSONObject) {
                        JSONObject match = (JSONObject) value;
                        String[] elements = JSONObject.getNames(match);
                        for (String element : elements) {
                            if (!val.equals("%")) {
                                if (element.equals(MONGO_REGEX_FIELD)) {
                                    mapMatchCaseInSensitive.put(element, val);
                                } else {
                                    mapMatchCaseInSensitive.put(element, MONGO_CASE_INSENSITIVE_OPTION);
                                }
                                this.isCaseSensitive = false;
                            }
                        }
                    } else {
                        if (!val.equals("%")) {
                            mapMatch.put(elementName, val);
                        }
                    }
                }
            }
        }
    }

    /**
     * JSON query will update with  user values
     *
     * @param stmt to update
     */
    private void setUpdateObject(JSONObject stmt) {
        String[] elementNames = JSONObject.getNames(stmt);
        for (String elementName : elementNames) {
            if (parameterValue.containsKey(elementName)) {
                Object val = parameterValue.get(elementName);
                mapProjection.put(elementName, val);
            }
        }
        if (!mapProjection.isEmpty()) {
            this.projection = new BasicDBObject(mapProjection);
        }
    }

    /**
     * Check for multiple look up for aggregation pipeline
     *
     * @return boolean status
     */
    private boolean isMultipleLookUp() {
        return multipleLookUpStatus;
    }

    /**
     * Add lookup attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addLookUpAttribute(List<DBObject> pipeline) {
        if (isMultipleLookUp()) {
            DBObject lookup = new BasicDBObject(MONGO_LOOKUP_FIELD, new BasicDBObject(mapLookUp));
            pipeline.add(lookup);
        } else {
            int track = 0;
            // Add the json query object to aggregation pipeline in order manner
            while (track < multiMapLookup.size()) {
                for (Map<String, Object> map : multiMapLookup) {
                    if (map.containsKey(MONGO_DEPENDENCY_FIELD)) {
                        map.remove(MONGO_DEPENDENCY_FIELD);
                        DBObject lookup = new BasicDBObject(MONGO_LOOKUP_FIELD, new BasicDBObject(map));
                        if (!pipeline.contains(lookup)) {
                            for (Map<String, Object> unwindSearch : multiMapUnwind) {
                                String key = "$" + map.get("as");
                                if (unwindSearch.containsValue(key) && !pipeline.isEmpty()) {
                                    DBObject unwind = new BasicDBObject(MONGO_UNWIND_FIELD,
                                            new BasicDBObject(unwindSearch));
                                    pipeline.add(unwind);
                                    pipeline.add(lookup);
                                    track++;
                                }
                            }
                        }
                    } else {
                        DBObject lookup = new BasicDBObject(MONGO_LOOKUP_FIELD, new BasicDBObject(map));
                        if (!pipeline.contains(lookup)) {
                            pipeline.add(lookup);
                            for (Map<String, Object> unwindSearch : multiMapUnwind) {
                                String key = "$" + map.get("as");
                                if (unwindSearch.containsValue(key)) {
                                    DBObject unwind = new BasicDBObject(MONGO_UNWIND_FIELD,
                                            new BasicDBObject(unwindSearch));
                                    pipeline.add(unwind);
                                    track++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Add unwind attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addUnwindAttribute(List<DBObject> pipeline) {
        if (isMultipleLookUp()) {
            DBObject unwind = new BasicDBObject(MONGO_UNWIND_FIELD, new BasicDBObject(mapUnwind));
            pipeline.add(unwind);
        }
    }

    /**
     * Add match attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addMatchAttribute(List<DBObject> pipeline) {
        DBObject match;
        if (this.isCaseSensitive) {
            match = new BasicDBObject(MONGO_MATCH_FIELD, new BasicDBObject(mapMatch));
        } else {
            match = new BasicDBObject(MONGO_MATCH_FIELD, new BasicDBObject(mapMatch).
                    append(UM_USER_NAME, new BasicDBObject(mapMatchCaseInSensitive)));
        }
        pipeline.add(match);
    }

    /**
     * Add sort attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addSortAttribute(List<DBObject> pipeline) {
        DBObject sort = new BasicDBObject(MONGO_SORT_FIELD, new BasicDBObject(mapSort));
        pipeline.add(sort);
    }

    /**
     * Add group attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addGroupAttribute(List<DBObject> pipeline) {
        DBObject group = new BasicDBObject(MONGO_GROUP_FIELD, new BasicDBObject(mapGroup));
        pipeline.add(group);
    }

    /**
     * Add project attribute to pipeline
     *
     * @param pipeline pipeline list, which needs to be modified
     */
    private void addProjectAttribute(List<DBObject> pipeline) {
        DBObject project = new BasicDBObject(MONGO_PROJECT_FIELD, new BasicDBObject(mapProject));
        pipeline.add(project);
    }
}
