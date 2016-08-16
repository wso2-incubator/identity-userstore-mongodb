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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;


import com.mongodb.DBRef;
import com.mongodb.WriteResult;
import com.mongodb.DBCursor;
import com.mongodb.AggregationOutput;
import com.mongodb.WriteConcern;
import com.mongodb.DBEncoder;
import com.mongodb.BulkWriteResult;
import org.bson.types.BSONTimestamp;
import org.bson.types.Binary;
import org.bson.types.Symbol;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * MongoDB Prepared Statement Interface
 */
@SuppressWarnings({"unused", "UnusedReturnValue"})
public interface MongoPreparedStatement {

    /**
     * set int parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setInt(String key, int parameter);

    /**
     * set double parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setDouble(String key, double parameter);

    /**
     * set String parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setString(String key, String parameter);

    /**
     * set bson timestamp parameter value to respective query parameter
     * @param key of json query
     * @param timeStamp value to set to query parameter
     */
	void setTimeStamp(String key, BSONTimestamp timeStamp);

    /**
     * set ArrayList parameter value to respective query parameter
     * @param key of json query
     * @param parameters value to set to query parameter
     */
	void setArray(String key, ArrayList<Object> parameters);

    /**
     * set Object parameter value to respective query parameter
     * @param key of json query
     * @param object value to set to query parameter
     */
	void setObject(String key, Object object);

    /**
     * set date parameter value to respective query parameter
     * @param key of json query
     * @param date value to set to query parameter
     */
	void setDate(String key, Date date);

    /**
     * set boolean parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setBoolean(String key, boolean parameter);

    /**
     * set DBRef parameter value to respective query parameter
     * @param key of json query
     * @param dbRef value to set to query parameter
     */
	void setDBPointer(String key, DBRef dbRef);

    /**
     * set Symbol parameter value to respective query parameter
     * @param key of json query
     * @param symbol value to set to query parameter
     */
	void setSymbol(String key, Symbol symbol);

    /**
     * set regular expression parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setRegularExpression(String key, String parameter);

    /**
     * set long parameter value to respective query parameter
     * @param key of json query
     * @param parameter value to set to query parameter
     */
	void setLong(String key, long parameter);

    /**
     * set binary parameter value to respective query parameter
     * @param key of json query
     * @param stream value to set to query parameter
     */
	void setBinary(String key, Binary stream);

    /**
     * close the connection
     */
	void close();

    /**
     * insert document to mongodb
     * @return  WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult insert() throws MongoQueryException;

    /**
     * search documents from mongodb
     * @return DBCursor instance
     * @throws MongoQueryException if any exception occurred
     */
	DBCursor find() throws MongoQueryException;

    /**
     * search documents through aggregration pipeline from mongodb
     * @return AggregrationOutput instance
     * @throws UserStoreException if any exception occurred
     */
	AggregationOutput aggregate() throws UserStoreException;

    /**
     * update document in mongodb
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult update() throws MongoQueryException;

    /**
     * update document to mongodb
     * @param upsert boolean status
     * @param multi boolean status
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult update(boolean upsert, boolean multi) throws MongoQueryException;

    /**
     * update document to mongodb
     * @param upsert boolean status
     * @param multi boolean status
     * @param aWriteConcern WriteConcern value
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern) throws MongoQueryException;

    /**
     * update document to mongodb
     * @param upsert boolean status
     * @param multi boolean status
     * @param aWriteConcern WriteConcern value
     * @param encoder DBEncoder value
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern, DBEncoder encoder) throws MongoQueryException;

    /**
     * update document to mongodb
     * @param upsert boolean status
     * @param multi boolean status
     * @param aWriteConcern WriteConcern value
     * @param byPassDocumentValidation boolean status
     * @param encoder DBEncoder instance
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult update(boolean upsert, boolean multi, WriteConcern aWriteConcern, boolean byPassDocumentValidation, DBEncoder encoder) throws MongoQueryException;

    /**
     * update multiple documents mongodb
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult updateMulti() throws MongoQueryException;

    /**
     * remove document in mongodb
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult remove() throws MongoQueryException;

    /**
     * remove document in mongodb
     * @param concern WriteConcern status
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult remove(WriteConcern concern) throws MongoQueryException;

    /**
     * remove document in mongodb
     * @param concern WriteConcern status
     * @param encoder DBEncoder instance
     * @return WriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	WriteResult remove(WriteConcern concern, DBEncoder encoder) throws MongoQueryException;

    /**
     * insert bulk documents to mongodb
     * @return BulkWriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	BulkWriteResult insertBulk() throws MongoQueryException;

    /**
     * update bulk documents to mongodb
     * @return BulkWriteResult instance
     * @throws MongoQueryException if any exception occurred
     */
	BulkWriteResult updateBulk() throws MongoQueryException;

    /**
     * add document to batch to bulk insert
     * @throws MongoQueryException if any exception occurred
     */
    void addBatch() throws MongoQueryException;

    /**
     * add document to batch to bulk update
     * @throws MongoQueryException if any exception occurred
     */
    void updateBatch() throws MongoQueryException;

    /**
     * get distinct set of values from mongodb
     * @return List of distinct
     * @throws MongoQueryException if any exception occurred
     */
	List distinct() throws MongoQueryException;

    /**
     * multiple lookup status
     * @param stat boolean status
     */
	void multiLookUp(boolean stat);
}
