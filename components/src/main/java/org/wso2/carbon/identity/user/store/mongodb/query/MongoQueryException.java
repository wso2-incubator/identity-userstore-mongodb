package org.wso2.carbon.identity.user.store.mongodb.query;

/**
 * MongoDB prepared statement exception class
 */
@SuppressWarnings("unused")
public class MongoQueryException extends Exception{

	private static final long serialVersionUID = 1997753363232807009L;


    /**
     * Default Exception constructor
     */
	public MongoQueryException(){

	}

    /**
     * Exception constructor with exception message
     * @param message exception message
     */
	public MongoQueryException(String message){
		
		super(message);
	}

    /**
     * Exception constructor with throwable reason
     * @param reason Throwable reason
     */
	public MongoQueryException(Throwable reason){

		super(reason);
	}

    /**
     * Exception constructor with throwable reason and message
     * @param message exception message
     * @param reason Throwable reason
     */
	public MongoQueryException(String message,Throwable reason){

		super(message,reason);
	}


}
