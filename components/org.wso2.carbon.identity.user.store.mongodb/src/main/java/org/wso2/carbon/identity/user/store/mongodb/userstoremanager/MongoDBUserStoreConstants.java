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

package org.wso2.carbon.identity.user.store.mongodb.userstoremanager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.wso2.carbon.identity.user.store.mongodb.userstoremanager.caseinsensitive.MongoDBCaseInsensitiveConstants;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserStoreConfigConstants;

/**
 * MongoDB User Store properties Constants
 */
class MongoDBUserStoreConstants {


    private static final List<Property> CUSTOM_UM_MANDATORY_PROPERTIES_TEMP = new ArrayList<Property>();
    private static final List<Property> CUSTOM_UM_OPTIONAL_PROPERTIES_TEMP = new ArrayList<Property>();
    private static final List<Property> CUSTOM_UM_ADVANCED_PROPERTIES_TEMP = new ArrayList<Property>();

    private static void setProperty(String name, String value, String description) {
        Property property = new Property(name, value, description, null);
        CUSTOM_UM_OPTIONAL_PROPERTIES_TEMP.add(property);

    }
        /*private static void setMandatoryProperty(String name, String value, String description) {
            Property property = new Property(name, value, description, null);
	        CUSTOM_UM_MANDATORY_PROPERTIES.add(property);

	    }*/

    private static void setMandatoryProperty(String name, String displayName, String value,
                                             String description, boolean encrypt) {
        String propertyDescription = displayName + "#" + description;
        if (encrypt) {
            propertyDescription += "#encrypt";
        }
        Property property = new Property(name, value, propertyDescription, null);
        CUSTOM_UM_MANDATORY_PROPERTIES_TEMP.add(property);

    }

    private static void setAdvancedProperty(String name, String value) {
        Property property = new Property(name, value, "", null);
        CUSTOM_UM_ADVANCED_PROPERTIES_TEMP.add(property);

    }

    static {
        setMandatoryProperty(MongoDBRealmConstants.URL, "Connection URL", "127.0.0.1", "URL of the user store database", false);
        setMandatoryProperty(MongoDBRealmConstants.USER_NAME, "Connection Name", "admin", "Username for the database", false);
        setMandatoryProperty(MongoDBRealmConstants.PASSWORD, "Connection Password", "admin123", "Password for the database", true);
        setMandatoryProperty(MongoDBRealmConstants.PORT, "Connection port", "27017", "Port of MongoDB server running", false);

        setProperty("PasswordDigest", "SHA-256", UserStoreConfigConstants.passwordHashMethodDescription);
        setProperty(UserStoreConfigConstants.readGroups, "true", UserStoreConfigConstants.readLDAPGroupsDescription);
        setProperty("ReadOnly", "false", "Indicates whether the user store of this realm operates in the user read only mode or not");
        setProperty("IsEmailUserName", "false", "Indicates whether Email is used as user name (apply when realm operates in read only mode).");
        setProperty("DomainCalculation", "default", "Can be either default or custom (apply when realm operates in read only mode)");
        setProperty("StoreSaltedPassword", "true", "Indicates whether to salt the password");
        setProperty(UserStoreConfigConstants.writeGroups, "true", UserStoreConfigConstants.writeGroupsDescription);
        setProperty("UserNameUniqueAcrossTenants", "false", "An attribute used for multi-tenancy");
        setProperty("PasswordJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate passwords");
        setProperty("PasswordJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for password validation");
        setProperty("UsernameJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate user names");
//        setProperty("UsernameJavaRegEx","^[^~!#$;%^*+={}\\\\|\\\\\\\\&lt;&gt;,\\\'\\\"]{3,30}$","A regular expression to validate user names");
        setProperty("UsernameJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for username validation");
        setProperty("RolenameJavaRegEx", "^[\\S]{5,30}$", "A regular expression to validate role names");
//        setProperty("RolenameJavaRegEx","^[^~!#$;%^*+={}\\\\|\\\\\\\\&lt;&gt;,\\\'\\\"]{3,30}$","A regular expression to validate role names");
        setProperty("RolenameJavaScriptRegEx", "^[\\S]{5,30}$", "The regular expression used by the font-end components for role name validation");
        setProperty(UserStoreConfigConstants.SCIMEnabled, "false", UserStoreConfigConstants.SCIMEnabledDescription);
        setProperty(MongoDBCaseInsensitiveConstants.CASE_SENSITIVE_USERNAME, "true",
                MongoDBCaseInsensitiveConstants.CASE_SENSITIVE_USERNAME_DESCRIPTION);
        //Advanced Properties (No descriptions added for each property)
        setAdvancedProperty("Enable SCIM", "false");
        setAdvancedProperty("Is Bulk Import Supported", "false");
        setAdvancedProperty("Password Hashing Algorithm", "SHA-256");
        setAdvancedProperty("Multiple Attribute Separator ", ",");
        setAdvancedProperty("Enable Salted Passwords", "true");
        setAdvancedProperty("Maximum User List Length", "100");
        setAdvancedProperty("Maximum Role List Length", "100");
        setAdvancedProperty("Enable User Role Cache", "true");
        setAdvancedProperty("Make Username Unique Across Tenants", "false");
        setAdvancedProperty("validationQuery for the database", "");
        setAdvancedProperty("Validation Interval(time in milliseconds)", "");
        setAdvancedProperty("SelectUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE, MongoDBCaseInsensitiveConstants.SELECT_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetRoleListMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_TENANT_ID' : '?','UM_ROLE_NAME' : '?','UM_SHARED_ROLE' : '0','projection': {'UM_ROLE_NAME' : '1','UM_TENANT_ID' : 1,'UM_SHARED_ROLE' : 1,'_id' : '0'}}");
        setAdvancedProperty("GetSharedRoleListMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_SHARED_ROLE' : '1','projection' : {'UM_ROLE_NAME' : '1','UM_TENANT_ID' : '1','UM_SHARED_ROLE' : '1'}}");
        setAdvancedProperty("UserFilterMONGO_QUERY", "{'collection' : 'UM_USER','$match' : {'UM_USER_NAME' : '?','UM_TENANT_ID' : '?'},'$project' : {'UM_USER_NAME' : 1,'_id' : 0},'$sort' : {'UM_USER_NAME' : 1}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_USER_FILTER_CASE_INSENSITIVE
                , MongoDBCaseInsensitiveConstants.GET_USER_FILTER_MONGO_CASE_INSENSITIVE
        );
        setAdvancedProperty("UserRoleMONGO_QUERY", "{'collection' : 'UM_ROLE',$match : {'UM_TENANT_ID' : '?','userRole.UM_TENANT_ID' : '?','users.UM_TENANT_ID' : '?','users.UM_ID' : '?'},'$project' : {'UM_ROLE_NAME' : 1,'_id' : 0},'$lookup' : {'from' : 'UM_USER_ROLE','localField' : 'UM_ID','foreignField' : 'UM_ROLE_ID','as' : 'userRole'},'$unwind' : {'path' : '$userRole','preserveNullAndEmptyArrays' : false},'$lookup_sub' : {'from' : 'UM_USER','localField' : 'userRole.UM_USER_ID','foreignField' : 'UM_ID','as' : 'users','dependency' : 'userRole'},'$unwind_sub' : {'path' : '$users','preserveNullAndEmptyArrays' : false}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_USER_ROLE_CASE_INSENSITIVE
                , MongoDBCaseInsensitiveConstants.GET_USER_ROLE_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("UserSharedRoleMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE','$match' : {'user.UM_USER_NAME' : '?','UM_USER_TENANT_ID' : '$role.UM_TENANT_ID','UM_USER_TENANT_ID' : '?'},'$unwind' : '$role','$lookup' : [{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'user'},{'from' : 'UM_ROLE','localField' : 'UM_ROLE_ID','foreignField' : 'UM_ID','as' : 'role'}]}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_SHARED_ROLES_FOR_USER_CASE_INSENSITIVE, MongoDBCaseInsensitiveConstants
                .GET_SHARED_ROLES_FOR_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("IsRoleExistingMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : 1,'_id' : 0}}");
        setAdvancedProperty("GetUserListOfRoleMONGO_QUERY", "{'collection' : 'UM_USER',$match : {'UM_TENANT_ID' : '?','role.UM_ROLE_NAME' : '?','role.UM_TENANT_ID' : '?','userRole.UM_TENANT_ID' : '?'},'$project' : {'UM_USER_NAME' : 1,'_id' : 0},'$lookup' : {'from' : 'UM_USER_ROLE','localField' : 'UM_ID','foreignField' : 'UM_USER_ID','as' : 'userRole'},'$unwind' : {'path' : '$userRole','preserveNullAndEmptyArrays' : false},'$lookup_sub' : {'from' : 'UM_ROLE','localField' : 'userRole.UM_ROLE_ID','foreignField' : 'UM_ID','as' : 'role','dependency' : 'userRole'},'$unwind_sub' : {'path' : '$role','preserveNullAndEmptyArrays' : false}}");

        setAdvancedProperty("IsUserExistingMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : 1}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_IS_USER_EXISTING_CASE_INSENSITIVE, MongoDBCaseInsensitiveConstants
                .GET_IS_USER_EXISTING_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetUserPropertiesForProfileMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','$match' : {'UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?','users.UM_USER_NAME' : '?','users.UM_TENANT_ID' : '?'},'$lookup' : {'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'users'},'$unwind' : {'path' : '$users','preserveNullAndEmptyArrays' : false}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_PROPS_FOR_PROFILE_CASE_INSENSITIVE, "Get User " +
                MongoDBCaseInsensitiveConstants
                        .GET_PROPS_FOR_PROFILE_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetUserPropertyForProfileMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_PROP_FOR_PROFILE_CASE_INSENSITIVE, "Get User " +
                MongoDBCaseInsensitiveConstants
                        .GET_PROP_FOR_PROFILE_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetUserLisForPropertyMONGO_QUERY", "{'collection' : 'UM_USER','$match' : {'attribute.UM_ATTR_NAME' : '?','attribute.UM_ATTR_VALUE' : '?','attribute.UM_ATTR_NAME' : '?','attribute.UM_PROFILE_ID' : '?','attribute.UM_TENANT_ID' : '?','user.UM_TENANT_ID' : '?'},'$lookup' : {'from' : 'UM_USER_ATTRIBUTE','localField' : 'UM_ID','foreignField' : 'UM_USER_ID','as' : 'attribute'},'$project' : {'name' : '$_id','UM_USER_NAME' : 1}}");

        setAdvancedProperty("GetProfileNamesMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_TENANT_ID' : '?','projection' : {'UM_PROFILE_ID' : 1},'distinct' : 'UM_PROFILE_ID'}");
        setAdvancedProperty("GetUserProfileNamesMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','projection' : {'UM_PROFILE_ID' : '1'},'distinct' : 'UM_PROFILE_ID'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_PROFILE_NAMES_FOR_USER_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .GET_PROFILE_NAMES_FOR_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetUserIDFromUserNameMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_ID' : 1}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_USERID_FROM_USERNAME_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .GET_USERID_FROM_USERNAME_MONGO_INSENSITIVE);
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.ADD_ROLE_TO_USER_CASE_INSENSITIVE, MongoDBCaseInsensitiveConstants.ADD_ROLE_TO_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("GetUserNameFromTenantIDMONGO_QUERY", "{'collection' : 'UM_USER','UM_TENANT_ID' : '?','projection' : {'UM_USER_NAME' : 1}}");
        setAdvancedProperty("GetTenantIDFromUserNameMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','projection' : {'UM_USER_NAME' : 1}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.GET_TENANT_ID_FROM_USERNAME_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .GET_TENANT_ID_FROM_USERNAME_MONGO_INSENSITIVE);

        setAdvancedProperty("AddUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_USER_PASSWORD' : '?','UM_SALT_VALUE' : '?','UM_REQUIRE_CHANGE' : '?','UM_CHANGED_TIME' : '?','UM_TENANT_ID' : '?','UM_ID' : '?'}");
        setAdvancedProperty("AddUserToRoleMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.ADD_USER_TO_ROLE_CASE_INSENSITIVE, "Add User To Role " +
                MongoDBCaseInsensitiveConstants
                        .ADD_USER_TO_ROLE_MONGO__CASE_INSENSITIVE);
        setAdvancedProperty("AddRoleMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','UM_ID' : '?'}");
        setAdvancedProperty("AddSharedRoleMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_SHARED_ROLE' : '?'}}}");

        setAdvancedProperty("AddRoleToUserMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_TENANT_ID' : '?','UM_ID' : '?'}");
        setAdvancedProperty("AddSharedRoleToUserMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_USER_TENANT_ID' : '?','UM_ROLE_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.ADD_SHARED_ROLE_TO_USER_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .ADD_SHARED_ROLE_TO_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("RemoveUserFromSharedRoleMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID' : '?','UM_USER_TENANT_ID' : '?','UM_ROLE_TENANT_ID' : '?'}");
        setAdvancedProperty("RemoveUserFromRoleMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.REMOVE_USER_FROM_ROLE_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .REMOVE_USER_FROM_ROLE_MONGO_CASE_INSENSITIVE);

        setAdvancedProperty("RemoveRoleFromUserMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_USER_ID': '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.REMOVE_USER_FROM_ROLE_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .REMOVE_USER_FROM_ROLE_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("DeleteRoleMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty("OnDeleteRoleRemoveUserRoleMappingMONGO_QUERY ", "{'collection' : 'UM_USER_ROLE','UM_ROLE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.REMOVE_ROLE_FROM_USER_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .REMOVE_ROLE_FROM_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("DeleteUserMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.DELETE_USER_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants.DELETE_USER_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("OnDeleteUserRemoveUserRoleMappingMONGO_QUERY", "{'collection' : 'UM_USER_ROLE','UM_USER_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty("OnDeleteUserRemoveUserAttributeMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?',UM_TENANT_ID : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE_MONGO_CASE_INSENSITIVE);

        setAdvancedProperty("UpdateUserPasswordMONGO_QUERY", "{'collection' : 'UM_USER','UM_USER_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set'  : {'UM_USER_PASSWORD' : '?','UM_SALT_VALUE' : '?','UM_REQUIRE_CHANGE' : '?','UM_CHANGED_TIME' : '?'}}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.UPDATE_USER_PASSWORD_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .UPDATE_USER_PASSWORD_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("UpdateRoleNameMONGO_QUERY", "{'collection' : 'UM_ROLE','UM_ROLE_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_ROLE_NAME' : '?'}}}");

        setAdvancedProperty("AddUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_ATTR_VALUE' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty("UpdateUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?','projection' : {'$set' : {'UM_ATTR_VALUE' : '?'}}}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.UPDATE_USER_PROPERTY_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .UPDATE_USER_PROPERTY_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("DeleteUserPropertyMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.DELETE_USER_PROPERTY_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .DELETE_USER_PROPERTY_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("UserNameUniqueAcrossTenantsMONGO_QUERY", "{'collection' : 'UM_USER_ATTRIBUTE','UM_USER_ID' : '?','UM_ATTR_NAME' : '?','UM_PROFILE_ID' : '?','UM_TENANT_ID' : '?'}");
        setAdvancedProperty(MongoDBCaseInsensitiveConstants.USER_NAME_UNIQUE_CASE_INSENSITIVE,
                MongoDBCaseInsensitiveConstants
                        .USER_NAME_UNIQUE_MONGO_CASE_INSENSITIVE);
        setAdvancedProperty("IsDomainExistingMONGO_QUERY", "{'collection' : 'UM_DOMAIN','UM_DOMAIN_NAME' : '?','UM_TENANT_ID' : '?','projection' : {'UM_DOMAIN_ID' : 1}}");

        setAdvancedProperty("AddDomainMONGO_QUERY", "{'collection' : 'UM_DOMAIN','UM_DOMAIN_NAME' : '?','UM_TENANT_ID' : '?'}");

        setAdvancedProperty("UserSharedRoleMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE',{'$match' : {'user.UM_USER_NAME' : '?','UM_USER_TENANT_ID' : '?','UM_USER_TENANT_ID' : '$user.UM_TENANT_ID','UM_ROLE_TENANT_ID' : '$role.UM_TENANT_ID'},'$lookup' : '[{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'user'},{'from' : 'UM_ROLE','localField' : 'UM_ROLE_ID','foreignField' : 'UM_ID','as' : 'roles'}]',{'$unwind' : '$user'},{'$unwind' : '$roles'},'$project' : {'name' : '$_id','UM_ROLE_NAME' : 1,'roles.UM_TENANT_ID' : 1,'UM_SHARED_ROLE' : 1}}");
        setAdvancedProperty("GetUserListOfSharedRoleMONGO_QUERY", "{'collection' : 'UM_SHARED_USER_ROLE',$match : {'UM_ROLE_NAME' : '?','UM_USER_TENANT_ID' : '$user.UM_TENANT_ID','UM_ROLE_TENANT_ID' : '$role.UM_TENANT_ID'},'$lookup' : '[{'from' : 'UM_USER','localField' : 'UM_USER_ID','foreignField' : 'UM_ID','as' : 'users'},{'from' : 'UM_ROLE','localField' : 'UM_ROLE_ID','foreignField' : 'UM_ID','$project' : {'name' : '$_id','UM_USER_NAME',1}}]'}");

    }

    static final List<Property> CUSTOM_UM_MANDATORY_PROPERTIES = Collections.unmodifiableList(CUSTOM_UM_MANDATORY_PROPERTIES_TEMP);
    static final List<Property> CUSTOM_UM_OPTIONAL_PROPERTIES = Collections.unmodifiableList(CUSTOM_UM_OPTIONAL_PROPERTIES_TEMP);
    static final List<Property> CUSTOM_UM_ADVANCED_PROPERTIES = Collections.unmodifiableList(CUSTOM_UM_ADVANCED_PROPERTIES_TEMP);

}
