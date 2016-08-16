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

package org.wso2.carbon.identity.user.store.mongodb.query;

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
import com.mongodb.DBRef;
import com.mongodb.WriteResult;
import com.mongodb.DBCursor;
import com.mongodb.AggregationOutput;
import com.mongodb.BasicDBObject;
import com.mongodb.MongoException;
import com.mongodb.DBEncoder;
import com.mongodb.WriteConcern;
import com.mongodb.BulkWriteRequestBuilder;
import com.mongodb.BulkWriteResult;
import com.mongodb.BulkUpdateRequestBuilder;
import org.bson.types.BSONTimestamp;
import org.bson.types.Binary;
import org.bson.types.Symbol;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * MongoDB Prepared Statement interface implementation class
 */
public class MongoPreparedStatementImpl implements MongoPreparedStatement{

	private DB db=null;
	private DBCollection collection=null;
	private DBObject query=null;
	private DBObject projection;
	private String defaultQuery;
	private HashMap<String, Object> parameterValue;
	private JSONObject queryJson;
	private int parameterCount;
	private Map<String,Object> mapQuery = null;
	private Map<String,Object> mapProjection = null;
	private Map<String,Object> mapMatch = null;
	private Map<String,Object> mapProject = null;
	private Map<String,Object> mapSort = null;
	private Map<String,Object> mapLookUp = null;
	private Map<String,Object> mapGroup = null;
	private Map<String,Object> mapUnwind = null;
    //private boolean multiInsertTrue = false;
   // private List<DBObject> queryList = null;
   // private List<DBObject> projectionList = null;
    private BulkWriteOperation bulkWrite = null;
	private  boolean multipleLookUp = false;
    private ArrayList<Map<String,Object>> multiMapLookup = null;
    private ArrayList<Map<String,Object>> multiMapUnwind = null;
    //private static boolean dependencyTrue = false;
    private String distinctKey = "";
    private boolean isCaseSensitive = true;
	private Map<String,Object> mapMatchCaseInSensitive = null;
    private Map<String,Object> mapCaseQuery = null;

    /**
     * Constructor with two arguments
     * @param db DB connection to mongodb
     * @param query to execute
     */
	public MongoPreparedStatementImpl(DB db,String query){
	
		if(this.db == null){
			this.db = db;
		}
		if(mapQuery == null && mapProjection == null){

			mapQuery = new HashMap<String, Object>();
			mapProjection = new HashMap<String, Object>();
		}
		if(mapMatch == null){
			mapMatch = new HashMap<String, Object>();
		}
        this.multiMapLookup = new ArrayList<Map<String, Object>>();
        this.multiMapUnwind = new ArrayList<Map<String, Object>>();
		this.defaultQuery = query;
		this.queryJson = new JSONObject(defaultQuery);
		parameterValue = new HashMap<String, Object>();
		this.projection = null;
		this.parameterCount = 0;
        this.distinctKey = "";
        this.isCaseSensitive = true;
        if(mapMatchCaseInSensitive == null){

            this.mapMatchCaseInSensitive = new HashMap<String, Object>();
        }
        if(mapCaseQuery == null) {
            this.mapCaseQuery = new HashMap<String, Object>();
        }
	}


    public void close() {
		
		this.db = null;
		this.collection = null;
		this.query = null;
		this.projection = null;
		this.parameterValue =null;
		this.defaultQuery = null;
		this.queryJson = null;
		this.parameterCount = 0;
		this.mapQuery = null;
		this.mapProjection = null;
		this.mapMatch = null;
		this.mapLookUp = null;
		this.mapProject =null;
		this.mapSort = null;
		this.mapGroup = null;
		this.mapUnwind = null;
        this.bulkWrite =null;
        this.multiMapUnwind = null;
        this.multiMapLookup = null;
        this.distinctKey = "";
        this.isCaseSensitive = true;
        this.mapMatchCaseInSensitive = null;
        this.mapCaseQuery = null;
	}



	public void setInt(String key, int parameter){
	
		parameterValue.put(key,parameter);
	}



	public void setDouble(String key, double parameter){

		parameterValue.put(key,parameter);
	}



	public void setString(String key, String parameter){
	
		parameterValue.put(key, parameter);
	}



	public void setTimeStamp(String key, BSONTimestamp timeStamp){
		
		parameterValue.put(key, timeStamp);
	}



	public void setObject(String key, Object object) {
		
		parameterValue.put(key, object);
	}



	public void setDate(String key, Date date){
		
		parameterValue.put(key, date);
	}



	public void setBoolean(String key, boolean parameter){
		
		parameterValue.put(key, parameter);
	}



	public void setDBPointer(String key, DBRef dbRef){
		
		parameterValue.put(key, dbRef);
	}



	public void setSymbol(String key, Symbol symbol){
		
		parameterValue.put(key, symbol);
	}



	public void setRegularExpression(String key, String parameter){
		
		parameterValue.put(key, parameter);
	}

	public void setLong(String key, long parameter){
		
		parameterValue.put(key, parameter);
	}

	public void setBinary(String key, Binary stream) {

		parameterValue.put(key,stream);
	}

	public void setArray(String key,ArrayList<Object> parameters){
	
		parameterValue.put(key,parameters);
	}

	public WriteResult insert() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.insert(this.query);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public DBCursor find() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){

                    if (this.projection == null && this.query == null) {
                        return this.collection.find();
                    } else if (this.projection == null) {
                        return this.collection.find(this.query);
                    } else {
                        return this.collection.find(this.query, this.projection);
                    }
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}

    public List distinct() throws MongoQueryException {

        if(!matchArguments(this.queryJson)){
            throw new MongoQueryException("Parameter count not matched with query parameters");
        }
        else {
            if(convertToDBObject(defaultQuery)) {
                return this.collection.distinct(this.distinctKey, this.query);
            }else{
                throw new MongoQueryException("Query format is invalid no collection found");
            }
        }
    }

    public void multiLookUp(boolean status) {

        multipleLookUp = status;
    }

    public AggregationOutput aggregate() throws UserStoreException{

        JSONObject defaultObject = new JSONObject(defaultQuery);
        getAggregrationObjects(defaultObject);
        try{
            List<DBObject> pipeline = new ArrayList<DBObject>();
            //add lookup attribute to pipeline
            if(mapLookUp != null) {

                if(isMultipleLookUp()) {

                    DBObject lookup = new BasicDBObject("$lookup", new BasicDBObject(mapLookUp));
                    pipeline.add(lookup);
                }else{
                    int track = 0;
                    //add the json query object to aggregration pipeline in order manner
                    while(track < multiMapLookup.size()) {
                        for (Map<String, Object> map : multiMapLookup) {
                            if (map.containsKey("dependency")) {
                                map.remove("dependency");
                                DBObject lookup = new BasicDBObject("$lookup", new BasicDBObject(map));
                                if (!pipeline.contains(lookup)) {
                                    for (Map<String, Object> unwindSearch : multiMapUnwind) {
                                        String key = "$" + map.get("as");
                                        if (unwindSearch.containsValue(key) && !pipeline.isEmpty()) {

                                            DBObject unwind = new BasicDBObject("$unwind", new BasicDBObject(unwindSearch));
                                            pipeline.add(unwind);
                                            pipeline.add(lookup);
                                            track++;
                                        }
                                    }
                                }
                            } else {

                                DBObject lookup = new BasicDBObject("$lookup", new BasicDBObject(map));
                                if (!pipeline.contains(lookup)) {
                                    pipeline.add(lookup);
                                    for (Map<String, Object> unwindSearch : multiMapUnwind) {

                                        String key = "$" + map.get("as");
                                        if (unwindSearch.containsValue(key)) {

                                            DBObject unwind = new BasicDBObject("$unwind", new BasicDBObject(unwindSearch));
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
            //add unwind attribute to pipeline
			if(mapUnwind != null){

				if(isMultipleLookUp()) {
					DBObject unwind = new BasicDBObject("$unwind", new BasicDBObject(mapUnwind));
					pipeline.add(unwind);
				}
			}
            //add match attribute to pipeline
            if(mapMatch != null){

                DBObject match;
                if(this.isCaseSensitive) {
                    match = new BasicDBObject("$match", new BasicDBObject(mapMatch));
                }else{

                    match = new BasicDBObject("$match",new BasicDBObject(mapMatch).append("UM_USER_NAME",new BasicDBObject(mapMatchCaseInSensitive)));
                }
                pipeline.add(match);
            }
            //add sort attribute to pipeline
            if(mapSort != null){

                DBObject sort = new BasicDBObject("$sort",new BasicDBObject(mapSort));
                pipeline.add(sort);
            }
            //add group attribute to pipeline
            if(mapGroup != null){

                DBObject group = new BasicDBObject("$group",new BasicDBObject(mapGroup));
                pipeline.add(group);
            }
            //add project attribute to pipeline
            if(mapProject != null) {

                DBObject project = new BasicDBObject("$project", new BasicDBObject(mapProject));
                pipeline.add(project);
            }

            return this.collection.aggregate(pipeline);
        }catch(MongoException e){

            throw new UserStoreException(e.getMessage());
        }
    }

	public WriteResult update() throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection));
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi) throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern) throws MongoQueryException {
		
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern, DBEncoder encoder)
			throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern,
			boolean byPassDocumentValidation,DBEncoder encoder) throws MongoQueryException {
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.update(this.query,new BasicDBObject("$set",this.projection),upsert,multi,aWriteConcern,byPassDocumentValidation,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult updateMulti() throws MongoQueryException {
		
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.updateMulti(this.query,new BasicDBObject("$set",this.projection));
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}



	public WriteResult remove() throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}
	
	public WriteResult remove(WriteConcern concern) throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query,concern);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}
	
	public WriteResult remove(WriteConcern concern,DBEncoder encoder) throws MongoQueryException{
		// TODO Auto-generated method stub
		if(!matchArguments(this.queryJson)){
			throw new MongoQueryException("Parameter count not matched with query parameters");
		}
		else{
			if(convertToDBObject(defaultQuery)){
				return this.collection.remove(this.query,concern,encoder);
			}else{
				throw new MongoQueryException("Query format is invalid no collection found");
			}
		}
	}

	public BulkWriteResult insertBulk() throws MongoQueryException {

		try {

			return this.bulkWrite.execute();

		}catch (Exception e){

			throw new MongoQueryException("Query Exception:"+e.getLocalizedMessage());
		}
	}

	public BulkWriteResult updateBulk() throws MongoQueryException {

        try {

            return this.bulkWrite.execute();
        }catch (Exception e){

            throw new MongoQueryException("Query Exception:"+e.getLocalizedMessage());
        }
    }

    public void addBatch() throws MongoQueryException{

        if (convertToDBObject(defaultQuery)) {

            if (bulkWrite == null) {
                bulkWrite = this.collection.initializeUnorderedBulkOperation();
            }
            bulkWrite.insert(this.query);
        } else {

            throw new MongoQueryException("Query format is invalid no collection found");
        }

    }

    public void updateBatch() throws MongoQueryException{

        if (convertToDBObject(defaultQuery)) {

            if(bulkWrite == null){

                bulkWrite = this.collection.initializeUnorderedBulkOperation();
            }
            BulkWriteRequestBuilder bulkWriteRequestBuilder = bulkWrite.find(this.query);
            BulkUpdateRequestBuilder updateReq = bulkWriteRequestBuilder.upsert();
            updateReq.replaceOne(this.projection);
        } else {

            throw new MongoQueryException("Query format is invalid no collection found");
        }

    }

    /**
     * check whether the provided arguments are equal to the parameters in json query
     * @param query type JSONObject
     * @return boolean status whether the argument correct or not
     */
	private boolean matchArguments(JSONObject query){

        //iterate over json query and match the query parameters with given values
		Iterator<String> keys = query.keys();
		while(keys.hasNext()){
			String key = keys.next();
	        try{
	             JSONObject value = query.getJSONObject(key);
	             matchArguments(value);
	        }catch(Exception e){
	        	if(query.get(key).equals("?")){
	        		this.parameterCount++;
	        	}
	        }
		}
		return parameterValue.size() == this.parameterCount;
	}


    /**
     *  String JSON formatted query convert to DBObject
     *  @param query to execute
     *  @return boolean status
     */
	private boolean convertToDBObject(String query){
		
		JSONObject queryObject = new JSONObject(query);
		if(queryObject.has("collection")){
			String collection = queryObject.getString("collection");
			this.collection = this.db.getCollection(collection);
			queryObject.remove("collection");
            //check whether the query has distinct key word
            if(queryObject.has("distinct")){

                this.distinctKey = queryObject.getString("distinct");
            }
            //if query has $set attribute then query will be update query
            if(query.contains("$set")){

                getUpdateObject(queryObject);
            }else {

                setQueryObject(queryObject, false);
            }
			return true;
		}
		else{
			return false;
		}
	}

    /**
     *  set passed values to query parameters
     *  @param object to execute
     *  @param status boolean status
     */
	private void setQueryObject(JSONObject object,boolean status){

        boolean hasProjection = status;
        Iterator<String> keys = object.keys();
        //set query parameter values with given values
        while(keys.hasNext()){
            String key = keys.next();
            Object val=null;
            try{
                JSONObject value = object.getJSONObject(key);
                if(key.equals("projection")){
                    hasProjection = true;
                }
                setQueryObject(value,hasProjection);
            }catch(Exception e){

                //if a case insensitive then check for $regex attribute
				if(key.equals("$regex")){

					key = "UM_USER_NAME";
                    this.isCaseSensitive = false;
				}
                //replace query parameter with respective value
                if(parameterValue.containsKey(key)){
                    val = parameterValue.get(key);
                }
            }
            if(val != null && !val.equals("%")){

                if(!this.isCaseSensitive){

                    if(key.equals("UM_USER_NAME")) {
                        mapCaseQuery.put("$regex", val);
                        mapCaseQuery.put("$options", "i");
                    }
                    else{
                        mapQuery.put(key,val);
                    }

                }else {
                    mapQuery.put(key, val);
                }
            }
            if(hasProjection && !key.equals("projection")){

                mapProjection.put(key, object.get(key));
            }
        }
        if(this.isCaseSensitive) {
            this.query = new BasicDBObject(mapQuery);
        }else{
            this.query = new BasicDBObject(mapQuery).append("UM_USER_NAME",mapCaseQuery);
        }
        if(!mapProjection.isEmpty()){
            this.projection = new BasicDBObject(mapProjection);
        }
	}

    /**
     *  get the value setted updated object
     *  @param object to update
     */
    private void getUpdateObject(JSONObject object){

        Iterator<String> keys = object.keys();
        while(keys.hasNext()) {
            String key = keys.next();
            Object val;
            if(key.equals("projection")){

                JSONObject setObject = object.getJSONObject(key);
                setUpdateObject(setObject.getJSONObject("$set"));
            }else{

                if(parameterValue.containsKey(key)){
                    val = parameterValue.get(key);
                    mapQuery.put(key,val);
                }
            }
        }
        this.query = new BasicDBObject(mapQuery);
    }

    /**
     *  Convert JSON Query to Aggregration Pipeline Object
     *  @param stmt JSONObject
     */
    private void getAggregrationObjects(JSONObject stmt){

        Iterator<String> keys = stmt.keys();
        while(keys.hasNext()){

            String key = keys.next();
            JSONObject value=null;
            try{
                if(!key.equals("collection"))
                {
                    value = stmt.getJSONObject(key);
                }
            }catch(JSONException e){

                throw new JSONException(e.getMessage());
            }
            if(key.equals("collection")){

                this.collection = db.getCollection(stmt.get(key).toString());
            }else if(key.equals("$lookup") || key.contains("$lookup_sub")){

                if(isMultipleLookUp()) {

                    mapLookUp = toMap(value);
                }else{

                    mapLookUp = toMap(value);
                    multiMapLookup.add(mapLookUp);
                }
            }else if(key.equals("$project")){

                mapProject = toMap(value);
            }else if(key.equals("$sort")){

                mapSort = toMap(value);
            }else if(key.equals("$group")){

                mapGroup = toMap(value);
            }else if(key.equals("$unwind") || key.equals("$unwind_sub")){
                if(isMultipleLookUp()) {
                    mapUnwind = toMap(value);
                }else{
                    mapUnwind = toMap(value);
                    multiMapUnwind.add(mapUnwind);
                }
            }else{

                setMatchObject(value);
            }
        }
    }

    /**
     *  set object parameter with passed values
     *  @param stmt to set values
     */
    private void setMatchObject(JSONObject stmt){

        String[] elementNames = JSONObject.getNames(stmt);
        for (String elementName : elementNames) {

            Object value = stmt.get(elementName);
            if (parameterValue.containsKey(elementName)) {
                Object val = parameterValue.get(elementName);
                if (!(value instanceof JSONObject) && !val.equals("%")) {
                    mapMatch.put(elementName, val);
                }else{

                    if(value instanceof JSONObject) {
                        JSONObject match = (JSONObject) value;
                        String[] elements = JSONObject.getNames(match);
                        for (String element : elements) {

                            if (!val.equals("%")) {
                                if (element.equals("$regex")) {
                                    mapMatchCaseInSensitive.put(element, val);
                                } else {
                                    mapMatchCaseInSensitive.put(element, "i");
                                }
                                this.isCaseSensitive = false;
                            }
                        }
                    }else{
                        if(!val.equals("%")) {
                            mapMatch.put(elementName, val);
                        }
                    }
                }
            }
        }
    }

    /**
     *  JSON query will update with  user values
     *  @param stmt to update
     */
    private void setUpdateObject(JSONObject stmt){

        String[] elementNames = JSONObject.getNames(stmt);
        for (String elementName : elementNames) {
            //String value = stmt.getString(elementName);
            if (parameterValue.containsKey(elementName)) {
                Object val = parameterValue.get(elementName);
                mapProjection.put(elementName, val);
            }
        }
        if(!mapProjection.isEmpty()){
            this.projection = new BasicDBObject(mapProjection);
        }
    }

    /**
     *  Convert JSON Object to Map Object
     *  @param object to convert
     *  @return Map object
     */
    private static Map<String, Object> toMap(JSONObject object) throws JSONException {
        Map<String, Object> map = new HashMap<String, Object>();

        Iterator<String> keysItr = object.keys();
        while(keysItr.hasNext()) {
            String key = keysItr.next();
            Object value = object.get(key);

            if(value instanceof JSONArray) {
                value = toList((JSONArray) value);
            }

            else if(value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            map.put(key, value);
        }
        return map;
    }

    /**
     *  Convert JSON Array to List Object
     *  @param array to convert to List
     *  @return List object
     */
    private static List<Object> toList(JSONArray array) throws JSONException {
        List<Object> list = new ArrayList<Object>();
        for(int i = 0; i < array.length(); i++) {
            Object value = array.get(i);
            if(value instanceof JSONArray) {
                value = toList((JSONArray) value);
            }

            else if(value instanceof JSONObject) {
                value = toMap((JSONObject) value);
            }
            list.add(value);
        }
        return list;
    }

    /**
     *  Check for multiple look up for aggregration pipeline
     *  @return boolean status
     */
    private boolean isMultipleLookUp() {
        return !multipleLookUp;
    }

}
