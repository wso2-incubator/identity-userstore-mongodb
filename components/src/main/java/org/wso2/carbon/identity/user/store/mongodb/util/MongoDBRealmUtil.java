package org.wso2.carbon.identity.user.store.mongodb.util;

import java.util.Map;

import org.wso2.carbon.identity.user.store.mongodb.userstoremanager.MongoDBRealmConstants;

/**
 * MongoDBRealmUtil loads all the default user store properties for configurations
 */
public class MongoDBRealmUtil {

    public static Map<String, String> getMONGO_QUERY(Map<String, String> properties) {

        if (!properties.containsKey(MongoDBRealmConstants.SELECT_USER)) {
            properties.put(MongoDBRealmConstants.SELECT_USER, MongoDBRealmConstants.SELECT_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_ROLE_LIST)) {
            properties.put(MongoDBRealmConstants.GET_ROLE_LIST, MongoDBRealmConstants.GET_ROLE_LIST_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USER_ROLE)) {
            properties.put(MongoDBRealmConstants.GET_USER_ROLE, MongoDBRealmConstants.GET_USER_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USER_FILTER)) {
            properties.put(MongoDBRealmConstants.GET_USER_FILTER,
                    MongoDBRealmConstants.GET_USER_FILTER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_IS_ROLE_EXISTING)) {
            properties.put(MongoDBRealmConstants.GET_IS_ROLE_EXISTING,
                    MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USERS_IN_ROLE)) {
            properties.put(MongoDBRealmConstants.GET_USERS_IN_ROLE,
                    MongoDBRealmConstants.GET_USERS_IN_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_IS_USER_EXISTING)) {
            properties.put(MongoDBRealmConstants.GET_IS_USER_EXISTING,
                    MongoDBRealmConstants.GET_IS_USER_EXISTING_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_PROPS_FOR_PROFILE)) {
            properties.put(MongoDBRealmConstants.GET_PROPS_FOR_PROFILE,
                    MongoDBRealmConstants.GET_PROPS_FOR_PROFILE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_PROP_FOR_PROFILE)) {
            properties.put(MongoDBRealmConstants.GET_PROP_FOR_PROFILE,
                    MongoDBRealmConstants.GET_PROP_FOR_PROFILE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_PROFILE_NAMES)) {
            properties.put(MongoDBRealmConstants.GET_PROFILE_NAMES,
                    MongoDBRealmConstants.GET_PROFILE_NAMES_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER)) {
            properties.put(MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER,
                    MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USERID_FROM_USERNAME)) {
            properties.put(MongoDBRealmConstants.GET_USERID_FROM_USERNAME,
                    MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME)) {
            properties.put(MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME,
                    MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_USER)) {
            properties.put(MongoDBRealmConstants.ADD_USER, MongoDBRealmConstants.ADD_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_USER_TO_ROLE)) {
            properties.put(MongoDBRealmConstants.ADD_USER_TO_ROLE,
                    MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_USER_PERMISSION)) {
            properties.put(MongoDBRealmConstants.ADD_USER_PERMISSION,
                    MongoDBRealmConstants.ADD_USER_PERMISSION_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_ROLE)) {
            properties.put(MongoDBRealmConstants.ADD_ROLE, MongoDBRealmConstants.ADD_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_ROLE_TO_USER)) {
            properties.put(MongoDBRealmConstants.ADD_ROLE_TO_USER,
                    MongoDBRealmConstants.ADD_ROLE_TO_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_ROLE_PERMISSION)) {
            properties.put(MongoDBRealmConstants.ADD_ROLE_PERMISSION,
                    MongoDBRealmConstants.ADD_ROLE_PERMISSION_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.REMOVE_USER_FROM_ROLE)) {
            properties.put(MongoDBRealmConstants.REMOVE_USER_FROM_ROLE,
                    MongoDBRealmConstants.REMOVE_USER_FROM_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.REMOVE_ROLE_FROM_USER)) {
            properties.put(MongoDBRealmConstants.REMOVE_ROLE_FROM_USER,
                    MongoDBRealmConstants.REMOVE_ROLE_FROM_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.DELETE_ROLE)) {
            properties.put(MongoDBRealmConstants.DELETE_ROLE, MongoDBRealmConstants.DELETE_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE)) {
            properties.put(MongoDBRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE,
                    MongoDBRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ON_DELETE_ROLE_DELETE_PERMISSION)) {
            properties.put(MongoDBRealmConstants.ON_DELETE_ROLE_DELETE_PERMISSION,
                    MongoDBRealmConstants.ON_DELETE_ROLE_DELETE_PERMISSION_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.DELETE_USER)) {
            properties.put(MongoDBRealmConstants.DELETE_USER, MongoDBRealmConstants.DELETE_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE)) {
            properties.put(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE,
                    MongoDBRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE)) {
            properties.put(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE,
                    MongoDBRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ON_DELETE_USER_DELETE_PERMISSION)) {
            properties.put(MongoDBRealmConstants.ON_DELETE_USER_DELETE_PERMISSION,
                    MongoDBRealmConstants.ON_DELETE_USER_DELETE_PERMISSION_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.UPDATE_USER_PASSWORD)) {
            properties.put(MongoDBRealmConstants.UPDATE_USER_PASSWORD,
                    MongoDBRealmConstants.UPDATE_USER_PASSWORD_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_USER_PROPERTY)) {
            properties.put(MongoDBRealmConstants.ADD_USER_PROPERTY,
                    MongoDBRealmConstants.ADD_USER_PROPERTY_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.USER_NAME_UNIQUE)) {
            properties.put(MongoDBRealmConstants.USER_NAME_UNIQUE,
                    MongoDBRealmConstants.USER_NAME_UNIQUE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.UPDATE_USER_PROPERTY)) {
            properties.put(MongoDBRealmConstants.UPDATE_USER_PROPERTY,
                    MongoDBRealmConstants.UPDATE_USER_PROPERTY_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.DELETE_USER_PROPERTY)) {
            properties.put(MongoDBRealmConstants.DELETE_USER_PROPERTY,
                    MongoDBRealmConstants.DELETE_USER_PROPERTY_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.UPDATE_ROLE_NAME)) {
            properties.put(MongoDBRealmConstants.UPDATE_ROLE_NAME,
                    MongoDBRealmConstants.UPDATE_ROLE_NAME_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_SHARED_ROLE_LIST)) {
            properties.put(MongoDBRealmConstants.GET_SHARED_ROLE_LIST,
                    MongoDBRealmConstants.GET_SHARED_ROLE_LIST_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_SHARED_ROLE)) {
            properties.put(MongoDBRealmConstants.GET_SHARED_ROLE,
                    MongoDBRealmConstants.GET_SHARED_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USER_LIST_OF_ROLE)) {
            properties.put(MongoDBRealmConstants.GET_USER_LIST_OF_ROLE,
                    MongoDBRealmConstants.GET_USER_LIST_OF_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.GET_USERNAME_FROM_TENANT_ID)) {
            properties.put(MongoDBRealmConstants.GET_USERNAME_FROM_TENANT_ID,
                    MongoDBRealmConstants.GET_USERNAME_FROM_TENANT_ID_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER)) {
            properties.put(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER,
                    MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE)) {
            properties.put(MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE,
                    MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.IS_DOMAIN_EXISTS)) {
            properties.put(MongoDBRealmConstants.IS_DOMAIN_EXISTS,
                    MongoDBRealmConstants.IS_DOMAIN_EXISTS_MONGO_QUERY);
        }
        if (!properties.containsKey(MongoDBRealmConstants.ADD_DOMAIN)) {
            properties.put(MongoDBRealmConstants.ADD_DOMAIN,
                    MongoDBRealmConstants.ADD_DOMAIN_MONGO_QUERY);
        }
        if (properties.containsKey(MongoDBRealmConstants.GET_SHARED_ROLES_FOR_USER)) {
            properties.put(MongoDBRealmConstants.GET_SHARED_ROLES_FOR_USER,
                    MongoDBRealmConstants.GET_SHARED_ROLES_FOR_USER_MONGO_QUERY);
        }
        if (properties.containsKey(MongoDBRealmConstants.ADD_SHARED_ROLE)) {
            properties.put(MongoDBRealmConstants.ADD_SHARED_ROLE,
                    MongoDBRealmConstants.ADD_SHARED_ROLE_MONGO_QUERY);
        }
        if (properties.containsKey(MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE)) {
            properties.put(MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE, MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE_MONGO_QUERY);
        }
        return properties;
    }
}
