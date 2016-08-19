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

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Arrays;
import java.util.Set;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Collections;
import java.util.LinkedList;

import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.WriteResult;
import com.mongodb.DBCursor;
import com.mongodb.AggregationOutput;
import com.mongodb.BasicDBObject;
import com.mongodb.MongoException;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoQueryException;
import org.wso2.carbon.identity.user.store.mongodb.util.MongoDBRealmUtil;
import org.wso2.carbon.identity.user.store.mongodb.util.MongoDatabaseUtil;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoPreparedStatement;
import org.wso2.carbon.identity.user.store.mongodb.query.MongoPreparedStatementImpl;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.user.store.mongodb.userstoremanager.caseinsensitive.MongoDBCaseInsensitiveConstants;
import org.wso2.carbon.user.core.authorization.AuthorizationCache;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.hybrid.HybridJDBCConstants;
import org.wso2.carbon.user.core.hybrid.HybridRoleManager;
import org.wso2.carbon.user.core.UserCoreConstants;

import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.jdbc.JDBCRoleContext;
import org.wso2.carbon.user.core.system.SystemUserRoleManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.sql.DataSource;

/**
 * MongoDBUserStoreManager class for create MongoDBUserStore
 */
public class MongoDBUserStoreManager extends AbstractUserStoreManager {


    private int tenantId;
    private DB db;
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    private final SecureRandom random = new SecureRandom();
    private static final String SHA_1_PRNG = "SHA1PRNG";
    private static DataSource dataSource = null;
    private final org.apache.commons.logging.Log log = LogFactory.getLog(MongoDBUserStoreManager.class);

    /**
     * Empty Constructor
     */
    public MongoDBUserStoreManager() {


    }

    /**
     * Constructor which accept two parameters
     *
     * @param configuration RealmConfiguration to user store
     * @param tenantID      currently logged in tenantID
     */
    @SuppressWarnings("WeakerAccess")
    public MongoDBUserStoreManager(RealmConfiguration configuration, int tenantID) throws UserStoreException {
        this.realmConfig = configuration;
        this.tenantId = tenantID;
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig.getUserStoreProperties()));
        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }

        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }
        //initialize user role cache
        initUserRolesCache();
    }

    /**
     * Constructor with four arguments
     *
     * @param ds          datasource of user store
     * @param realmConfig realm configuration
     * @param tenantId    currently logged in tenantID
     * @param addInitData boolean status to filter whether initial data add or not to user store
     */
    @SuppressWarnings({"WeakerAccess", "UnusedParameters"})
    public MongoDBUserStoreManager(DB ds, RealmConfiguration realmConfig, int tenantId, boolean addInitData) throws UserStoreException {

        this(realmConfig, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));
        this.db = ds;
        if (ds == null) {
            ds = MongoDatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (ds == null) {
            throw new UserStoreException("User Management Data Source is null");
        }
        doInitialSetup();
        this.persistDomain();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
    }

    /**
     * Constructor with two parameters
     *
     * @param ds          mongodb datasource
     * @param realmConfig realm configuration
     */
    @SuppressWarnings("WeakerAccess")
    public MongoDBUserStoreManager(DB ds, RealmConfiguration realmConfig) throws UserStoreException {

        this(realmConfig, MultitenantConstants.SUPER_TENANT_ID);
        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));
        this.db = ds;
    }

    /**
     * constructor with  6 parameters
     *
     * @param realmConfig    realm configuration
     * @param properties     realm properties
     * @param claimManager   claim manager details
     * @param profileManager Profile Configuration Manager instance
     * @param realm          User Realm instance
     * @param tenantId       currently logged in tenantId
     */
    @SuppressWarnings("WeakerAccess")
    public MongoDBUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                   ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
                                   Integer tenantId) throws UserStoreException {
        this(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);

    }

    /**
     * constructor with  7 parameters
     *
     * @param realmConfig    realm configuration
     * @param properties     realm properties
     * @param claimManager   claim manager details
     * @param profileManager Profile Configuration Manager instance
     * @param realm          User Realm instance
     * @param tenantId       currently logged in tenantId
     * @param skipInitData   boolean status to check whether to skip intial data or not
     */
    @SuppressWarnings({"WeakerAccess", "UnusedParameters", "SameParameterValue"})
    public MongoDBUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                   ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
                                   Integer tenantId, boolean skipInitData) throws UserStoreException {

        this(realmConfig, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        try {
            db = loadUserStoreSpacificDataSoruce();

            if (db == null) {
                db = (DB) properties.get(UserCoreConstants.DATA_SOURCE);
            }
            if (db == null) {
                db = MongoDatabaseUtil.getRealmDataSource(realmConfig);
                properties.put(UserCoreConstants.DATA_SOURCE, db);
            }

            if (log.isDebugEnabled()) {
                log.debug("The MongoDBDataSource being used by MongoDBUserStoreManager :: "
                        + db.hashCode());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Loading JDBC datasource failed", e);
            }
        }

        properties.put(UserCoreConstants.DATA_SOURCE, db);

        //  this.db = db;

        realmConfig.setUserStoreProperties(MongoDBRealmUtil.getMONGO_QUERY(realmConfig
                .getUserStoreProperties()));

        this.persistDomain();
        doInitialSetup();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
                    !isInitSetupDone());
        }

        initUserRolesCache();

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
        /* Initialize user roles cache as implemented in AbstractUserStoreManager */

    }

    /**
     * get all user properties belong to provided user profile
     *
     * @param userName      username of user
     * @param propertyNames names of properties to get
     * @param profileName   profile name of user
     * @return map object of properties
     */
    protected Map<String, String> getUserPropertyValues(String userName, String[] propertyNames,
                                                        String profileName) throws UserStoreException {
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        MongoPreparedStatement prepStmt = null;
        String[] propertyNamesSorted = propertyNames.clone();
        Arrays.sort(propertyNamesSorted);
        Map<String, String> map = new HashMap<String, String>();
        DB db = loadUserStoreSpacificDataSoruce();
        try {
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROPS_FOR_PROFILE);
            prepStmt = new MongoPreparedStatementImpl(db, mongoQuery);
            prepStmt.setString("users.UM_USER_NAME", userName);
            prepStmt.setString("UM_PROFILE_NAME", profileName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("users.UM_TENANT_ID", tenantId);
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            AggregationOutput result = prepStmt.aggregate();
            Iterable<DBObject> ite = result.results();
            for (DBObject object : ite) {

                object.removeField("_id");
                object.removeField("users");
                Set<String> keys = object.keySet();
                for (String key : keys) {

                    String value = object.get(key).toString();
                    if (Arrays.binarySearch(propertyNamesSorted, key) < 0) {
                        continue;
                    }
                    map.put(key, value);
                }
            }
        } catch (Exception e) {

            throw new UserStoreException(e.getMessage(), e);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
        return map;
    }

    /**
     * check whether the supplied role is available in user store
     *
     * @param roleName role name to check
     * @return boolean
     */
    protected boolean doCheckExistingRole(String roleName) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);
        return isExistingMongoDBRole(roleContext);
    }

    /**
     * create context of given role
     *
     * @param roleName role name to create context
     * @return RoleContext created for given role
     */
    protected RoleContext createRoleContext(String roleName) throws UserStoreException {
        JDBCRoleContext searchCtx = new JDBCRoleContext();
        String[] roleNameParts = roleName.split(UserCoreConstants.TENANT_DOMAIN_COMBINER);
        int tenantId;
        if (roleNameParts.length > 1) {
            tenantId = Integer.parseInt(roleNameParts[1]);
            searchCtx.setTenantId(tenantId);
        } else {
            tenantId = this.tenantId;
            searchCtx.setTenantId(tenantId);
        }

        if (tenantId != this.tenantId) {
            searchCtx.setShared(true);
        }
        searchCtx.setRoleName(roleNameParts[0]);
        return searchCtx;
    }


    /**
     * check whether the role is exists in mongodb
     *
     * @param context of role created
     * @return boolean status whether the role exists or not
     */
    @SuppressWarnings("WeakerAccess")
    protected boolean isExistingMongoDBRole(RoleContext context) throws UserStoreException {

        boolean isExisting;
        String roleName = context.getRoleName();
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("UM_ROLE_NAME", roleName);
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_ROLE_EXISTING);
        if (mongoQuery == null) {
            throw new UserStoreException("The MongoDB Query statement for is role existing role null");
        }
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

            map.put("UM_TENANT_ID", ((JDBCRoleContext) context).getTenantId());
            isExisting = isValueExisting(mongoQuery, null, map);
        } else {
            isExisting = isValueExisting(mongoQuery, null, map);
        }
        return isExisting;
    }


    @SuppressWarnings("WeakerAccess")
    protected boolean isValueExisting(String mongoQuery, @SuppressWarnings("SameParameterValue") DB db, Map<String, Object> params) throws UserStoreException {

        boolean isExisting = false;
        //boolean doClose = false;
        try {

            if (db == null) {
                db = loadUserStoreSpacificDataSoruce();
                // doClose = true;
            }
            if (MongoDatabaseUtil.getIntegerValueFromDatabase(db, mongoQuery, params) > -1) {
                isExisting = true;
            }
            return isExisting;
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Using MongoQuery : " + mongoQuery);
            throw new UserStoreException(e.getMessage(), e);
        }
    }

    /**
     * check whether the user is exists in user store
     *
     * @param userName given to check
     * @return boolean true or false respectively for user exists or not
     */
    protected boolean doCheckExistingUser(String userName) throws UserStoreException {

        Map<String, Object> map = new HashMap<String, Object>();
        String mongoQuery;
        if (isCaseSensitiveUsername()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_IS_USER_EXISTING_CASE_INSENSITIVE);
        } else {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_IS_USER_EXISTING);
        }
        if (mongoQuery == null) {
            throw new UserStoreException("The sql statement for is user existing null");
        }
        boolean isExisting;
        map.put("UM_USER_NAME", userName);
        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if ("true".equals(isUnique)
                && !CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            String uniquenesMongo = realmConfig
                    .getUserStoreProperty(MongoDBRealmConstants.USER_NAME_UNIQUE);
            isExisting = isValueExisting(uniquenesMongo, null, map);
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID", tenantId);
                isExisting = isValueExisting(mongoQuery, null, map);
            } else {
                isExisting = isValueExisting(mongoQuery, null, map);
            }
        }
        return isExisting;
    }

    /**
     * get user list from provided properties
     *
     * @param property    name
     * @param value       of property name
     * @param profileName where property belongs to
     * @return String[] of users
     */
    protected String[] getUserListFromProperties(String property, String value, String profileName) throws UserStoreException {

        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        MongoPreparedStatement prepStmt = null;
        String[] users = new String[0];
        List<String> list = new ArrayList<String>();
        try {

            db = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_FOR_PROP);
            prepStmt = new MongoPreparedStatementImpl(db, mongoQuery);
            prepStmt.setString("UM_ATTR_NAME", property);
            prepStmt.setString("UM_ATTR_VALUE", value);
            prepStmt.setString("UM_PROFILE_ID", profileName);
            DBCursor cursor = prepStmt.find();
            while (cursor.hasNext()) {

                String name = cursor.next().get("UM_USER_NAME").toString();
                list.add(name);
            }
            if (list.size() > 0) {
                users = list.toArray(new String[list.size()]);
            }
        } catch (Exception e) {
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
        return users;
    }

    /**
     * responsible for authenticate user
     *
     * @param userName   of authenticating user
     * @param credential include user password of authenticating user
     * @return boolean if authenticate fail or not
     */
    protected boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        if (!checkUserNameValid(userName)) {
            return false;
        }

        if (!checkUserPasswordValid(credential)) {
            return false;
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            log.error("Anonnymous user trying to login");
            return false;
        }
        String mongoQuery = null;
        String password = (String) credential;
        boolean isAuthed = false;
        MongoPreparedStatement prepStmt = null;
        try {
            if (isCaseSensitiveUsername()) {

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.SELECT_USER);
            } else {
                mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE);
            }
            prepStmt = new MongoPreparedStatementImpl(db, mongoQuery);
            if (log.isDebugEnabled()) {
                log.debug(mongoQuery);
            }
            prepStmt.setString("UM_USER_NAME", userName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            DBCursor cursor = prepStmt.find();
            if (cursor.hasNext()) {

                DBObject object = cursor.next();
                String storedPassword = object.get("UM_USER_PASSWORD").toString();
                String saltValue = null;
                if ("true".equalsIgnoreCase(realmConfig
                        .getUserStoreProperty(MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = object.get("UM_SALT_VALUE").toString();
                }

                boolean requireChange = Boolean.parseBoolean(object.get("UM_REQUIRE_CHANGE").toString());
                Date timestamp = (Date) object.get("UM_CHANGED_TIME");
                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();

                if (requireChange && (timestamp.getTime() < date.getTime())) {
                    isAuthed = false;
                } else {
                    password = this.preparePassword(password, saltValue);
                    if ((storedPassword != null) && (storedPassword.equals(password))) {
                        isAuthed = true;
                    }
                }
            }
        } catch (Exception ex) {

            log.error("Using MongoDB Query : " + mongoQuery);
            throw new UserStoreException("Authentication Failure", ex);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }
        return isAuthed;
    }


    private String preparePassword(String password, String saltValue) throws UserStoreException {

        try {
            String digestInput = password;
            if (saltValue != null) {
                digestInput = password + saltValue;
            }
            String digsestFunction = realmConfig.getUserStoreProperties().get(
                    MongoDBRealmConstants.DIGEST_FUNCTION);
            if (digsestFunction != null) {

                if (digsestFunction
                        .equals(UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                    return password;
                }

                MessageDigest dgst = MessageDigest.getInstance(digsestFunction);
                byte[] byteValue = dgst.digest(digestInput.getBytes("UTF-8"));
                password = Base64.encode(byteValue);
            }
            return password;
        } catch (NoSuchAlgorithmException e) {
            throw new UserStoreException(e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            throw new UserStoreException(e.getMessage(), e);
        }
    }

    /**
     * add new user to mongodb user store
     *
     * @param userName              of new user
     * @param credential            of new user
     * @param roleList              of new user
     * @param claims                user claim values
     * @param profileName           user profile name
     * @param requirePasswordChange status to change password
     */
    protected void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims, String profileName, boolean requirePasswordChange) throws UserStoreException {

        persistUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
    }

    /**
     * update user credentials in user store
     *
     * @param userName      of user to update credentials
     * @param oldCredential of user
     * @param newCredential of user to update
     */
    protected void doUpdateCredential(String userName, Object newCredential, Object oldCredential) throws UserStoreException {

        this.doUpdateCredentialByAdmin(userName, newCredential);
    }

    /**
     * update admin user credentials in user store
     *
     * @param userName      of admin to update credentials
     * @param newCredential of user to update
     */
    protected void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {

        String mongoQuery;
        if (isCaseSensitiveUsername()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_USER_PASSWORD);
        } else {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.UPDATE_USER_PASSWORD_CASE_INSENSITIVE);
        }
        //MongoPreparedStatement prepStmt;
        Map<String, Object> map = new HashMap<String, Object>();
        String saltValue = null;
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for delete user claim value is null");
        }
        if ("true".equalsIgnoreCase(realmConfig.getUserStoreProperties().get(
                MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
            saltValue = generateSaltValue();
        }
        String password = this.preparePassword((String) newCredential, saltValue);
        map.put("UM_USER_NAME", userName);
        map.put("UM_USER_PASSWORD", password);

        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            map.put("UM_REQUIRE_CHANGE", false);
            map.put("UM_TENANT_ID", tenantId);
            map.put("UM_CHANGED_TIME", new Date());
            map.put("UM_SALT_VALUE", "");
            updateStringValuesToDatabase(null, mongoQuery, map);
        } else if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue != null) {
            map.put("UM_REQUIRE_CHANGE", false);
            map.put("UM_TENANT_ID", tenantId);
            map.put("UM_CHANGED_TIME", new Date());
            map.put("UM_SALT_VALUE", saltValue);
            updateStringValuesToDatabase(null, mongoQuery, map);
        } else if (!mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN) && saltValue == null) {
            map.put("UM_REQUIRE_CHANGE", false);
            map.put("UM_CHANGED_TIME", new Date());
            map.put("UM_SALT_VALUE", "");
            updateStringValuesToDatabase(null, mongoQuery, map);
        } else {

            map.put("UM_REQUIRE_CHANGE", false);
            map.put("UM_CHANGED_TIME", new Date());
            map.put("UM_SALT_VALUE", saltValue);
            updateStringValuesToDatabase(null, mongoQuery, map);
        }

    }

    private String generateSaltValue() {
        String saltValue;
        try {
            SecureRandom secureRandom = SecureRandom.getInstance(SHA_1_PRNG);
            byte[] bytes = new byte[16];
            //secureRandom is automatically seeded by calling nextBytes
            secureRandom.nextBytes(bytes);
            saltValue = Base64.encode(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA1PRNG algorithm could not be found.");
        }
        return saltValue;
    }

    private void updateStringValuesToDatabase(DB dbConnection, String mongoQuery,
                                              Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {

            if (dbConnection == null) {

                localConnection = true;
                dbConnection = loadUserStoreSpacificDataSoruce();
            }
            JSONObject jsonKeys = new JSONObject(mongoQuery);
            List<String> keys = MongoDatabaseUtil.getKeys(jsonKeys);
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            for (String key : keys) {
                if (!key.equals("collection") && !key.equals("projection") && !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : params.entrySet()) {

                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                throw new UserStoreException("Invalid data provided");
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            } else if (entry.getValue() instanceof Date) {
                                // Timestamp timestamp = new Timestamp(((Date) param).getTime());
                                // prepStmt.setTimestamp(i + 1, timestamp);
                                Date date = (Date) entry.getValue();
                                prepStmt.setDate(key, date);
                            } else if (entry.getValue() instanceof Boolean) {
                                prepStmt.setBoolean(key, (Boolean) entry.getValue());
                            }
                        }
                    }
                }
            }
            List<String> queryList = new ArrayList<String>();
            queryList.add(mongoQuery);
            WriteResult result = MongoDatabaseUtil.updateTrue(queryList) ? prepStmt.update() : prepStmt.insert();
            if (!result.isUpdateOfExisting()) {

                if (log.isDebugEnabled()) {

                    log.debug("No documents were updated");
                }
            } else {

                if (log.isDebugEnabled()) {

                    log.debug("Executed query is " + mongoQuery + " and number of updated documents ::" + result.getN());
                }
            }
        } catch (Exception e) {

            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            if (localConnection) {
                prepStmt.close();
            }
        }
    }

    private void updateUserClaimValuesToDatabase(DB dbConnection, Map<String, Object> map, boolean isUpdateTrue) throws UserStoreException {


        if (map == null) {

            throw new UserStoreException("Parameters cannot be null");
        } else {
            DBCollection collection = dbConnection.getCollection("UM_USER_ATTRIBUTE");
            try {
                if (!isUpdateTrue) {

                    int id = MongoDatabaseUtil.getIncrementedSequence(dbConnection, "UM_USER_ATTRIBUTE");
                    BasicDBObject query = new BasicDBObject("UM_ID", id);
                    for (Map.Entry<String, Object> entry : map.entrySet()) {

                        query.append(entry.getKey(), entry.getValue());
                    }
                    collection.insert(query);

                } else {

                    BasicDBObject condition = null;
                    BasicDBObject setQuery = null;
                    for (Map.Entry<String, Object> entry : map.entrySet()) {

                        if (entry.getKey().equals("UM_USER_ID") || entry.getKey().equals("UM_PROFILE_ID")) {

                            if (condition == null) {

                                condition = new BasicDBObject(entry.getKey(), entry.getValue());
                            } else {

                                condition.append(entry.getKey(), entry.getValue());
                            }
                        } else {

                            if (setQuery == null) {

                                setQuery = new BasicDBObject(entry.getKey(), entry.getValue());
                            } else {

                                setQuery.append(entry.getKey(), entry.getValue());
                            }
                        }
                    }

                    if (condition != null && setQuery != null) {
                        setQuery = new BasicDBObject("$set", setQuery);
                        collection.update(condition, setQuery);
                    }
                }
            } catch (com.mongodb.MongoQueryException ex) {

                if (log.isDebugEnabled()) {

                    log.debug("Exception occur while querying :" + ex.getMessage());
                }
                throw new UserStoreException("Error occured cannot add user store property :" + ex.getMessage());
            } catch (Exception ex) {

                if (log.isDebugEnabled()) {

                    log.debug("Exception occur while querying :" + ex.getMessage());
                }
                throw new UserStoreException("Error occured cannot add user store property :" + ex.getMessage());
            }
        }
    }

    private void deleteStringValuesFromDatabase(DB dbConnection, String mongoQuery,
                                                Map<String, Object> params) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {

            if (dbConnection == null) {

                localConnection = true;
                dbConnection = loadUserStoreSpacificDataSoruce();
            }
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            JSONObject jsonKeys = new JSONObject(mongoQuery);
            List<String> keys = MongoDatabaseUtil.getKeys(jsonKeys);
            for (String key : keys) {
                if (!key.equals("collection")) {
                    if (params.get(key) == null) {
                        prepStmt.setString(key, null);
                    } else if (params.get(key) instanceof String) {
                        prepStmt.setString(key, (String) params.get(key));
                    } else if (params.get(key) instanceof Integer) {
                        prepStmt.setInt(key, (Integer) params.get(key));
                    }
                }
            }
            WriteResult result = prepStmt.remove();
            if (!result.isUpdateOfExisting()) {

                if (log.isDebugEnabled()) {

                    log.debug("No documents were deleted");
                }
            } else {

                if (log.isDebugEnabled()) {

                    log.debug("Executed query is " + mongoQuery + " and number of deleted documents ::" + result.getN());
                }
            }

        } catch (Exception ex) {

            String msg = "Error occurred while deleting string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, ex);
            }
            throw new UserStoreException(msg, ex);
        } finally {
            if (localConnection) {
                prepStmt.close();
            }
        }
    }

    /**
     * delete user from userstore
     *
     * @param userName of user to delete
     * @throws UserStoreException exception if any occur
     */
    protected void doDeleteUser(String userName) throws UserStoreException {

        int user_id;
        DB dbConnection = loadUserStoreSpacificDataSoruce();
        try {
            user_id = getUserId(userName);
            if (user_id == 0) {

                log.warn("No registered user found for given user name");
            } else {

                String mongoQuery;
                String mongoQuery2;
                String mongoQuery3;
                Map<String, Object> map = new HashMap<String, Object>();
                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_USER_ROLE);
                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_USER_REMOVE_ATTRIBUTE);
                mongoQuery3 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_USER);
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    map.put("UM_USER_ID", user_id);
                    map.put("UM_TENANT_ID", tenantId);
                    map.put("UM_USER_NAME", userName);
                    map.put("UM_ID", user_id);
                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery, map);
                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery2, map);
                    this.deleteStringValuesFromDatabase(dbConnection, mongoQuery3, map);
                }
            }
        } catch (Exception e) {

            if (log.isDebugEnabled()) {

                log.debug("Error ocurred :" + e.getMessage());
            }
            throw new UserStoreException(e.getMessage());
        }

    }

    /**
     * set user claim value of registered user in user store
     *
     * @param userName    of registered user
     * @param claimValue  of user to set
     * @param claimURI    of user claim
     * @param profileName of user claims belongs to
     * @throws UserStoreException if any error occurred
     */
    protected void doSetUserClaimValue(String userName, String claimURI, String claimValue,
                                       String profileName) throws UserStoreException {

        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        if (claimValue == null) {
            throw new UserStoreException("Cannot set null values.");
        }
        DB dbConnection;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            String property = getClaimAtrribute(claimURI, userName, null);
            int userId = getUserId(userName);
            String value = getProperty(dbConnection, userId);
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("UM_USER_ID", userId);
            map.put("UM_PROFILE_ID", profileName);
            if (value == null) {
                addProperty(dbConnection, map);
            } else {
                map.put(property, value);
                updateProperty(dbConnection, map);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage =
                    "Error occurred while getting claim attribute for user : " + userName + " & claim URI : " +
                            claimURI;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception ex) {

            String msg =
                    "Database error occurred while saving user claim value for user : " + userName + " & claim URI : " +
                            claimURI + " claim value : " + claimValue;
            if (log.isDebugEnabled()) {
                log.debug(msg, ex);
            }
            throw new UserStoreException(msg, ex);
        }
    }

    /**
     * get a user claim property of given user
     *
     * @param dbConnection of mongodb
     * @param userId       of user to get property
     * @return property of given user
     * @throws UserStoreException if error occurred
     */
    @SuppressWarnings("WeakerAccess")
    protected String getProperty(DB dbConnection, int userId) throws UserStoreException {

        MongoPreparedStatement prepStmt = null;
        try {
            String mongoQuery;
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROP_FOR_PROFILE);
            if (mongoQuery == null) {

                throw new UserStoreException("The mng statement for add user property mongo query is null");
            }
            String value = null;
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            prepStmt.setInt("UM_USER_ID", userId);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            DBCursor cursor = prepStmt.find();
            while (cursor.hasNext()) {

                value = cursor.next().get("UM_ID").toString();
            }
            return value;
        } catch (Exception e) {

            String msg = "Error ocuured :";
            throw new UserStoreException(msg, e);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
    }

    /**
     * set user claim values of registered user in user store
     *
     * @param userName    of registered user
     * @param claims      of user to set
     * @param profileName of user claims belongs to
     * @throws UserStoreException if any error occurred
     */
    protected void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        if (claims.get(UserCoreConstants.PROFILE_CONFIGURATION) == null) {
            claims.put(UserCoreConstants.PROFILE_CONFIGURATION,
                    UserCoreConstants.DEFAULT_PROFILE_CONFIGURATION);
        }
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            Iterator<Map.Entry<String, String>> ite = claims.entrySet().iterator();
            Map<String, Object> map = new HashMap<String, Object>();
            while (ite.hasNext()) {

                Map.Entry<String, String> entry = ite.next();
                String claimUri = entry.getKey();
                String property = getClaimAtrribute(claimUri, userName, null);
                String value = entry.getValue();
                if (value.length() > 0) {
                    map.put(property, value);
                }
            }
            int userId = getUserId(userName);
            map.put("UM_USER_ID", userId);
            map.put("UM_PROFILE_ID", profileName);
            String userValueExsists = getProperty(dbConnection, userId);
            if (userValueExsists == null) {

                addProperty(dbConnection, map);
            } else {

                updateProperty(dbConnection, map);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {

            String errorMessage = "Error occurred while getting claim attribute for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {

            String msg = "Database error occurred while setting user claim values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }

    }

    private void updateProperty(DB dbConnection, Map<String, Object> map) throws UserStoreException {

        String mongoQuery;
        if (isCaseSensitiveUsername()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_USER_PROPERTY);
        } else {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.UPDATE_USER_PROPERTY_CASE_INSENSITIVE);

        }
        if (mongoQuery == null) {

            throw new UserStoreException("The sql statement for add user property sql is null");
        }
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

            map.put("UM_TENANT_ID", tenantId);
            updateUserClaimValuesToDatabase(dbConnection, map, true);
        } else {
            updateUserClaimValuesToDatabase(dbConnection, map, true);
        }
    }

    /**
     * delete user claim value of given user claim
     *
     * @param userName    of user
     * @param claimURI    to delete from user
     * @param profileName where claim belongs to
     * @throws UserStoreException if error occurred
     */
    protected void doDeleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if (profileName == null) {

            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        try {

            String property;
            if (UserCoreConstants.PROFILE_CONFIGURATION.equals(claimURI)) {
                property = UserCoreConstants.PROFILE_CONFIGURATION;
            } else {
                property = getClaimAtrribute(claimURI, userName, null);
            }

            dbConnection = loadUserStoreSpacificDataSoruce();
            this.deleteProperty(dbConnection, userName, property, profileName);

        } catch (org.wso2.carbon.user.api.UserStoreException e) {

            String errorMessage =
                    "Error occurred while getting claim attribute for user : " + userName + " & claim URI : " +
                            claimURI;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {

            String msg = "Database error occurred while deleting user claim value for user : " + userName +
                    " & claim URI : " + claimURI;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private void deleteProperty(DB dbConnection, String userName, String property, String profileName) throws UserStoreException, MongoQueryException {

        String mongoQuery;
        String query;
        Map<String, Object> map = new HashMap<String, Object>();
        if (isCaseSensitiveUsername()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_USER_PROPERTY);
            query = MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1;
        } else {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.DELETE_USER_PROPERTY_CASE_INSENSITIVE);
            query = MongoDBCaseInsensitiveConstants.SELECT_USER_MONGO_CASE_INSENSITIVE;
        }

        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, query);
        prepStmt.setString("UM_USER_NAME", userName);
        prepStmt.setInt("UM_TENANT_ID", tenantId);
        DBCursor cursor = prepStmt.find();
        if (cursor.hasNext()) {

            int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            map.put("UM_USER_ID", userId);
            map.put("UM_ATTR_NAME", property);
            map.put("UM_PROFILE_ID", profileName);
            if (mongoQuery == null) {

                throw new UserStoreException("The mongo statement for add user property mongo query is null");
            }
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }
        }
    }

    /**
     * delete user claim values of given user claims
     *
     * @param userName    of user
     * @param claims      to delete from user
     * @param profileName where claim belongs to
     * @throws UserStoreException if error occurred
     */
    protected void doDeleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {

        DB dbConnection = null;
        if (profileName == null) {
            profileName = UserCoreConstants.DEFAULT_PROFILE;
        }
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            for (String claimURI : claims) {
                String property = getClaimAtrribute(claimURI, userName, null);
                this.deleteProperty(dbConnection, userName, property, profileName);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error occurred while getting claim attribute for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } catch (Exception e) {
            String msg = "Database error occurred while deleting user claim values for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * @param roleName     of user to update
     * @param deletedUsers send this param fill with if want to remove user from role
     * @param newUsers     send this paramfill with if want to add user to role
     * @throws UserStoreException if any error occurred
     */
    protected void doUpdateUserListOfRole(String roleName, String deletedUsers[], String[] newUsers) throws UserStoreException {

        JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(roleName);
        roleName = ctx.getRoleName();
        int roleTenantId = ctx.getTenantId();
        boolean isShared = ctx.isShared();
        String mongoQuery;
        if (isCaseSensitiveUsername()) {

            mongoQuery = realmConfig.getUserStoreProperty(isShared ? MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE
                    : MongoDBRealmConstants.REMOVE_USER_FROM_ROLE);
        } else {

            mongoQuery = realmConfig.getUserStoreProperty(isShared ? MongoDBCaseInsensitiveConstants.REMOVE_USER_FROM_SHARED_ROLE_CASE_INSENSITIVE
                    : MongoDBCaseInsensitiveConstants.REMOVE_USER_FROM_ROLE_CASE_INSENSITIVE);
        }
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for remove user from role is null");
        }
        DB dbConnection = null;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            // Map<String,Object> map = new HashMap<String, Object>();
            String mongoQuery2;
            if (isShared) {

                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
            } else {

                mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
            }
            if (mongoQuery2 == null) {

                throw new UserStoreException("The mongo statement for add user to role is null");
            }
            int userIds[];
            if (deletedUsers != null && deletedUsers.length > 0) {
                userIds = getUserIDS(dbConnection, deletedUsers);
            } else {

                userIds = getUserIDS(dbConnection, newUsers);
            }

            String[] roles = {roleName};
            int roleIds[] = getRolesIDS(dbConnection, roles);
            Map<String, Object> mapRole = new HashMap<String, Object>();
            mapRole.put("UM_USER_ID", userIds);
            if (isShared) {

                mapRole.put("UM_ROLE_ID", roleIds[0]);
                if (newUsers.length > 0) {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                            mapRole);
                }
                if (deletedUsers.length > 0) {

                    MongoDatabaseUtil.deleteUserMappingInBatchMode(dbConnection, mongoQuery,
                            mapRole);
                }
            } else {
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    mapRole.put("UM_ROLE_ID", roleIds[0]);
                    mapRole.put("UM_TENANT_ID", roleTenantId);
                    if (newUsers.length > 0) {

                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                mapRole);
                    }
                    if (deletedUsers != null && deletedUsers.length > 0) {

                        MongoDatabaseUtil.deleteUserMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    }

                } else {

                    mapRole.put("UM_ROLE_ID", roleIds[0]);
                    if (newUsers.length > 0) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                mapRole);
                    }
                    if (deletedUsers.length > 0) {
                        MongoDatabaseUtil.deleteUserMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    }

                }
            }
        } catch (RuntimeException e) {

            throw e;
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }

    }

    /**
     * @param userName     of user to update
     * @param deletedRoles send this param fill with if want to remove role from user
     * @param newRoles     send this paramfill with if want to add role to user
     * @throws UserStoreException if any error occurred
     */
    protected void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles) throws UserStoreException {

        //MongoPreparedStatement prepStmt = null;
        DB dbConnection = null;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery;
            String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
            if (userNames.length > 1) {
                userName = userNames[1];
            }
            if (deletedRoles != null && deletedRoles.length > 0) {
                // if user name and role names are prefixed with domain name,
                // remove the domain name
                RoleBreakdown breakdown = getSharedRoleBreakdown(deletedRoles);
                String[] roles = breakdown.getRoles();

                // Integer[] tenantIds = breakdown.getTenantIds();

                String[] sharedRoles = breakdown.getSharedRoles();
                Integer[] sharedTenantIds = breakdown.getSharedTenantids();
                Map<String, Object> mapRole = new HashMap<String, Object>();
                if (roles.length > 0) {
                    if (isCaseSensitiveUsername()) {
                        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.REMOVE_ROLE_FROM_USER);
                    } else {
                        mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.REMOVE_ROLE_FROM_USER_CASE_INSENSITIVE);
                    }
                    if (mongoQuery.equals("")) {
                        throw new UserStoreException(
                                "The mongo statement for remove user from role is null");
                    }
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection, MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
                    prepStmt2.setString("UM_USER_NAME", userName);
                    int rolesID[] = getRolesIDS(dbConnection, roles);
                    int userID;
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        prepStmt2.setInt("UM_TENANT_ID", tenantId);
                    }
                    DBCursor cursor = prepStmt2.find();
                    userID = Integer.parseInt(cursor.next().get("UM_ID").toString());

                    mapRole.put("UM_USER_ID", userID);
                    mapRole.put("UM_ROLE_ID", rolesID);
                    if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                        mapRole.put("UM_TENANT_ID", tenantId);
                        MongoDatabaseUtil.deleteUserRoleMappingInBatchMode(dbConnection, mongoQuery,
                                mapRole);
                    } else {
                        MongoDatabaseUtil.deleteUserRoleMappingInBatchMode(dbConnection, mongoQuery, mapRole);
                    }
                }

                if (sharedRoles.length > 0) {

                    if (isCaseSensitiveUsername()) {
                        mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.REMOVE_USER_FROM_SHARED_ROLE);
                    } else {
                        mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.REMOVE_USER_FROM_SHARED_ROLE_CASE_INSENSITIVE);
                    }
                    if (mongoQuery == null) {
                        throw new UserStoreException(
                                "The sql statement for remove user from role is null");
                    }

                    MongoDatabaseUtil.updateUserRoleMappingWithExactParams(dbConnection, mongoQuery,
                            sharedRoles, userName,
                            sharedTenantIds, tenantId);
                }
            }
            String mongoQuery2 = null;
            if (newRoles != null && newRoles.length > 0) {
                // if user name and role names are prefixed with domain name,
                // remove the domain name

                RoleBreakdown breakdown = getSharedRoleBreakdown(newRoles);
                String[] roles = breakdown.getRoles();
                // Integer[] tenantIds = breakdown.getTenantIds();

                String[] sharedRoles = breakdown.getSharedRoles();
                Integer[] sharedTenantIds = breakdown.getSharedTenantids();
                int roleIds[] = getRolesIDS(dbConnection, roles);
                String users[] = {userName};
                int userIds[] = getUserIDS(dbConnection, users);
                Map<String, Object> map = new HashMap<String, Object>();
                map.put("UM_ROLE_ID", roleIds);
                map.put("UM_USER_ID", userIds[0]);
                if (roles.length > 0) {

                    if (isCaseSensitiveUsername()) {
                        mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                    } else {
                        mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.ADD_ROLE_TO_USER_CASE_INSENSITIVE);
                    }
                }
                if (mongoQuery2 == null) {

                    if (isCaseSensitiveUsername()) {
                        mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                    } else {
                        mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.ADD_ROLE_TO_USER_CASE_INSENSITIVE);
                    }
                }
                if (mongoQuery2 == null) {
                    throw new UserStoreException(
                            "The mongo statement for add user to role is null");
                } else {

                    if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                        map.put("UM_TENANT_ID", tenantId);
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                map);
                    } else {

                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, map);
                    }
                }


                if (sharedRoles.length > 0) {
                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);
                    if (mongoQuery2 == null) {
                        throw new UserStoreException(
                                "The sql statement for remove user from role is null");
                    }

                    MongoDatabaseUtil.updateUserRoleMappingWithExactParams(dbConnection, mongoQuery2,
                            sharedRoles, userName,
                            sharedTenantIds, tenantId);

                }

            }

        } catch (RuntimeException e) {

            throw e;
        } catch (Exception e) {

            String errorMessage = "Error occurred while getting database type from DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private RoleBreakdown getSharedRoleBreakdown(String[] rolesList) throws UserStoreException {
        List<String> roles = new ArrayList<String>();
        List<Integer> tenantIds = new ArrayList<Integer>();

        List<String> sharedRoles = new ArrayList<String>();
        List<Integer> sharedTenantIds = new ArrayList<Integer>();

        for (String role : rolesList) {

            String[] deletedRoleNames = role.split(CarbonConstants.DOMAIN_SEPARATOR);
            if (deletedRoleNames.length > 1) {
                role = deletedRoleNames[1];
            }

            JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(role);
            role = ctx.getRoleName();
            int roleTenantId = ctx.getTenantId();
            boolean isShared = ctx.isShared();

            if (isShared) {
                sharedRoles.add(role);
                sharedTenantIds.add(roleTenantId);
            } else {
                roles.add(role);
                tenantIds.add(roleTenantId);
            }

        }

        RoleBreakdown breakdown = new RoleBreakdown();

        // Non shared roles and tenant ids
        breakdown.setRoles(roles.toArray(new String[roles.size()]));
        breakdown.setTenantIds(tenantIds.toArray(new Integer[tenantIds.size()]));

        // Shared roles and tenant ids
        breakdown.setSharedRoles(sharedRoles.toArray(new String[sharedRoles.size()]));
        breakdown.setSharedTenantids(sharedTenantIds.toArray(new Integer[sharedTenantIds.size()]));

        return breakdown;

    }

    /**
     * get all roles list of a user
     *
     * @param userName of user to get role list
     * @param filter   if any filtering apply
     * @return String[] of rolelist of user
     * @throws UserStoreException if any error occurred
     */
    protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Getting roles of user: " + userName + " with filter: " + filter);
        }
        String mongoQuery;
        String query;
        if (isCaseSensitiveUsername()) {

            query = MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY;
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USER_ROLE);
        } else {
            query = MongoDBCaseInsensitiveConstants.GET_USERID_FROM_USERNAME_MONGO_INSENSITIVE;
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_USER_ROLE_CASE_INSENSITIVE);
        }
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db, query);
        prepStmt.setString("UM_USER_NAME", userName);
        if (MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

            prepStmt.setInt("UM_TENANT_ID", tenantId);
        }
        try {
            DBCursor cursor = prepStmt.find();
            int userId = 0;
            if (cursor.hasNext()) {

                userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
            }
            List<String> roles = new ArrayList<String>();
            String[] names;
            if (mongoQuery == null) {
                throw new UserStoreException("The mongo statement for retrieving user roles is null");
            }
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("users.UM_ID", userId);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("userRole.UM_TENANT_ID", tenantId);
                map.put("users.UM_TENANT_ID", tenantId);
                map.put("UM_TENANT_ID", tenantId);
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            } else {
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            }
            if (log.isDebugEnabled()) {
                if (names.length != 0) {
                    for (String name : names) {
                        log.debug("Found role: " + name);
                    }
                } else {
                    log.debug("No external role found for the user: " + userName);
                }
            }
            Collections.addAll(roles, names);
            return roles.toArray(new String[roles.size()]);
        } catch (MongoQueryException e) {

            String msg = "Error occurred while retrieving user roles.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
    }

    @SuppressWarnings("SameParameterValue")
    private String[] getStringValuesFromDatabase(String mongoQuery, Map<String, Object> params, boolean findStatus, boolean multipleLookUps)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + mongoQuery);
            for (Map.Entry<String, Object> entry : params.entrySet()) {

                log.debug("Input value:" + entry.getValue());
            }
        }

        String[] values = null;
        DB dbConnection = null;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            values = MongoDatabaseUtil.getStringValuesFromDatabase(dbConnection, mongoQuery, params, findStatus, multipleLookUps);
        } catch (Exception e) {

            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return values;
    }

    private String[] getDistinctStringValues(String mongoQuery, Map<String, Object> params) throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + mongoQuery);
            for (Map.Entry<String, Object> entry : params.entrySet()) {

                log.debug("Input value:" + entry.getValue());
            }
        }

        String[] values = null;
        DB dbConnection = null;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            values = MongoDatabaseUtil.getDistinctStringValuesFromDatabase(dbConnection, mongoQuery, params);
        } catch (Exception e) {

            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return values;
    }

    /**
     * get all shared role list of user
     *
     * @param userName     of user to get shared role list
     * @param filter       if any filter
     * @param tenantDomain of currently logged in
     * @return String[] of shred roles list of user
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doGetSharedRoleListOfUser(String userName,
                                                 String tenantDomain, String filter) throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Looking for shared roles for user: " + userName + " for tenant: " + tenantDomain);
        }
        if (isSharedGroupEnabled()) {
            // shared roles
            String mongoQuery;

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_SHARED_ROLES_FOR_USER);

            return getRoleNamesWithDomain(mongoQuery, userName, tenantId, true);
        }
        return new String[0];
    }

    @SuppressWarnings("SameParameterValue")
    private String[] getRoleNamesWithDomain(String mongoQuery, String userName, int tenantId,
                                            boolean appendDn) throws UserStoreException {

        DB dbConnection = null;
        MongoPreparedStatement prepStmt;
        List<String> roles = new ArrayList<String>();
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            //byte count = 0;
            prepStmt.setString("UM_USER_NAME", userName);
            prepStmt.setInt("UM_TENANT_ID", tenantId);
            DBCursor cursor = prepStmt.find();
            // String domain =
            //        realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            while (cursor.hasNext()) {

                String name = cursor.next().get("UM_ROLE_NAME").toString();
                int tenant = Integer.parseInt(cursor.next().get("UM_TENANT_ID").toString());
                if (appendDn) {
                    UserCoreUtil.addTenantDomainToEntry(name, String.valueOf(tenant));
                }
                roles.add(name);
            }
        } catch (Exception e) {

            String msg =
                    "Error occurred while retrieving role name with tenant id : " + tenantId + " & user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {

            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles.toArray(new String[roles.size()]);
    }

    /**
     * add new role to mongodb user store
     *
     * @param roleName of new role
     * @param userList ofnew role to add
     * @param shared   status of whether the role is shared or not
     * @throws UserStoreException if any exception occurred
     */
    protected void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException {

        Map<String, Object> map = new HashMap<String, Object>();
        if (shared && isSharedGroupEnabled()) {
            doAddSharedRole(roleName, userList);
        }
        DB dbConnection = null;
        String mongoQuery = "";
        String mongoQuery2 = "";
        Map<String, Object> mapRole = new HashMap<String, Object>();
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            // int[] userId = new int[userList.length];
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE);
            map.put("UM_ROLE_NAME", roleName);
            int roleId = MongoDatabaseUtil.getIncrementedSequence(dbConnection, "UM_ROLE");
            map.put("UM_ID", roleId);
            map.put("UM_SHARED_ROLE", 0);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID", tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }
            if (userList != null) {

                //String mongoQuery2 = null;
                if (isCaseSensitiveUsername()) {

                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_TO_ROLE);
                } else {

                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.ADD_USER_TO_ROLE_CASE_INSENSITIVE);
                }
                if (mongoQuery2 == null) {

                    throw new UserStoreException("Query Cannot be empty");
                }
                MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db, MongoDBRealmConstants.ADD_USER_TO_ROLE_MONGO_QUERY_CONDITION1);
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    String mongoCondition = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection, mongoCondition);
                    prepStmt2.setString("UM_ROLE_NAME", roleName);
                    prepStmt2.setInt("UM_TENANT_ID", tenantId);
                    DBCursor cursor = prepStmt2.find();
                    roleId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                    int[] userID = getUserIDS(dbConnection, userList);
                    mapRole.put("UM_USER_ID", userID);
                    mapRole.put("UM_ROLE_ID", roleId);
                    mapRole.put("UM_TENANT_ID", tenantId);
                    if (userID.length != 0) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                                mapRole);
                    }
                } else {

                    String mongoCondition = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
                    MongoPreparedStatement prepStmt2 = new MongoPreparedStatementImpl(dbConnection, mongoCondition);
                    int roleID;
                    prepStmt2.setString("UM_ROLE_NAME", roleName);
                    DBCursor cursor = prepStmt.find();
                    roleID = Integer.parseInt(cursor.next().get("UM_ID").toString());
                    int[] userID = getUserIDS(dbConnection, userList);
                    mapRole.put("UM_USER_ID", roleID);
                    mapRole.put("UM_ROLE_ID", userID);
                    if (userID.length != 0) {
                        MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, mapRole);
                    }
                }

            }
        } catch (RuntimeException e) {

            throw e;
        } catch (Exception e) {

            this.deleteStringValuesFromDatabase(dbConnection, mongoQuery2, mapRole);
            this.deleteStringValuesFromDatabase(dbConnection, mongoQuery, map);
            String msg = "Error occurred while adding role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private void doAddSharedRole(String roleName, String[] userList) throws UserStoreException {

        DB dbConnection = null;
        Map<String, Object> map = new HashMap<String, Object>();
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE);
            map.put("UM_ROLE_NAME", roleName);
            map.put("UM_SHARED_ROLE", roleName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }

            if (userList != null) {

                String mongoQuery2;
                if (isCaseSensitiveUsername()) {
                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_SHARED_ROLE_TO_USER);

                } else {

                    mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.ADD_SHARED_ROLE_TO_USER_CASE_INSENSITIVE);
                }
                String[] roles = {roleName};
                int roleID[] = getRolesIDS(dbConnection, roles);
                int[] userID = getUserIDS(dbConnection, userList);
                Map<String, Object> mapRole = new HashMap<String, Object>();
                mapRole.put("UM_USER_ID", roleID[0]);
                mapRole.put("UM_ROLE_ID", userID);
                if (mongoQuery2.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                    mapRole.put("UM_TENANT_ID", tenantId);
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2,
                            mapRole);
                } else {
                    MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, mongoQuery2, mapRole);
                }
            }
        } catch (RuntimeException e) {

            throw e;
        } catch (Exception e) {

            String msg = "Error occurred while adding role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    private int[] getUserIDS(DB dbConnection, String[] userList) throws MongoQueryException {

        String query;
        if (isCaseSensitiveUsername()) {
            query = MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY;
        } else {
            query = MongoDBCaseInsensitiveConstants.GET_USERID_FROM_USERNAME_MONGO_INSENSITIVE;
        }
        int userID[] = new int[userList.length];
        int index = 0;
        for (String user : userList) {

            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, query);
            if (query.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            prepStmt.setString("UM_USER_NAME", user);
            DBCursor cursor = prepStmt.find();
            if (cursor.hasNext()) {

                int id = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
                if (id > 0) {
                    userID[index] = id;
                }
            }
            index++;
            prepStmt.close();
        }
        return userID;
    }

    /**
     * delete given role
     *
     * @param roleName to delete from user store
     * @throws UserStoreException if any exception occurred
     */
    protected void doDeleteRole(String roleName) throws UserStoreException {

        Map<String, Object> map = new HashMap<String, Object>();
        String mongoQuery1 = realmConfig
                .getUserStoreProperty(MongoDBRealmConstants.ON_DELETE_ROLE_REMOVE_USER_ROLE);
        if (mongoQuery1 == null) {
            throw new UserStoreException("The mongo statement for delete user-role mapping is null");
        }
        String mongoQuery2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.DELETE_ROLE);
        if (mongoQuery2 == null) {
            throw new UserStoreException("The mongo statement for delete role is null");
        }
        DB dbConnection = null;
        try {

            dbConnection = loadUserStoreSpacificDataSoruce();
            String roles[] = {roleName};
            int roleIds[] = getRolesIDS(dbConnection, roles);
            map.put("UM_ROLE_ID", roleIds[0]);
            if (mongoQuery1.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                map.put("UM_ID", roleIds[0]);
                this.deleteStringValuesFromDatabase(dbConnection, mongoQuery1, map);
                this.deleteStringValuesFromDatabase(dbConnection, mongoQuery2, map);
            } else {
                map.put("UM_ID", roleIds[0]);
                this.deleteStringValuesFromDatabase(dbConnection, mongoQuery1, map);
                this.deleteStringValuesFromDatabase(dbConnection, mongoQuery2, map);
            }
        } catch (Exception e) {

            String msg = "Error occurred while deleting role : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * update role name of userstore
     *
     * @param roleName    to update
     * @param newRoleName to be updated
     * @throws UserStoreException if any exception occurred
     */
    protected void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {

        JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(roleName);
        Map<String, Object> map = new HashMap<String, Object>();
        if (isExistingRole(newRoleName)) {
            throw new UserStoreException("Role name: " + newRoleName
                    + " in the system. Please pick another role name.");
        }
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.UPDATE_ROLE_NAME);
        map.put("UM_ROLE_NAME", roleName);
        map.put("UM_NEW_ROLE_NAME", newRoleName);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for update role name is null");
        }
        DB dbConnection = null;
        try {

            roleName = ctx.getRoleName();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            } else {
                this.updateStringValuesToDatabase(dbConnection, mongoQuery, map);
            }
        } catch (Exception e) {
            String msg = "Error occurred while updating role name : " + roleName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
    }

    /**
     * get role name of user store
     *
     * @param filter       to filter the search
     * @param maxItemLimit to display per page
     * @return String[] of roles
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        String[] roles = new String[0];
        DB dbConnection = null;
        String mongoQuery;
        MongoPreparedStatement prepStmt;
        if (maxItemLimit == 0) {
            return roles;
        }
        try {

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (dbConnection == null) {

                throw new UserStoreException("null connection");
            }
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_ROLE_LIST);
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            prepStmt.setString("UM_ROLE_NAME", filter);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            //byte count = 0;
            DBCursor cursor;
            try {

                cursor = prepStmt.find();
                if (cursor != null) {
                    while (cursor.hasNext()) {
                        String name = cursor.next().get("UM_ROLE_NAME").toString();
                        // append the domain if exist
                        String domain =
                                realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                        name = UserCoreUtil.addDomainToName(name, domain);
                        lst.add(name);
                    }
                }
//
//			if (isSharedGroupEnabled()) {
//				lst.addAll(Arrays.asList(doGetSharedRoleNames(null, filter, maxItemLimit)));
//			}
//
                if (lst.size() > 0) {
                    roles = lst.toArray(new String[lst.size()]);
                }

            } catch (MongoQueryException e) {

                String errorMessage =
                        "Error while fetching roles from JDBC user store according to filter : " + filter +
                                " & max item limit : " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);

            }
        } catch (Exception e) {

            String msg = "Error occurred while retrieving role names for filter : " + filter + " & max item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles;
    }

    /**
     * get role name of user store
     *
     * @param filter       to filter the search
     * @param maxItemLimit to display per page
     * @return String[] of users
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {
        String[] users = new String[0];
        DB dbConnection = null;
        String mongoQuery;
        MongoPreparedStatement prepStmt;
        AggregationOutput cursor;
        if (maxItemLimit == 0) {
            return new String[0];
        }

        int givenMax;

        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }
        try {

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();

            dbConnection = loadUserStoreSpacificDataSoruce();

            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }

            if (isCaseSensitiveUsername()) {

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USER_FILTER);
            } else {

                mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_USER_FILTER_CASE_INSENSITIVE);
            }
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            prepStmt.setString("UM_USER_NAME", filter);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            try {
                cursor = prepStmt.aggregate();
            } catch (MongoException e) {
                String errorMessage =
                        "Error while fetching users according to filter : " + filter + " & max Item limit " +
                                ": " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
            if (cursor != null) {
                for (DBObject object : cursor.results()) {

                    String name = object.get("UM_USER_NAME").toString();
                    if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(name)) {
                        continue;
                    }
                    // append the domain if exist
                    String domain = realmConfig
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    name = UserCoreUtil.addDomainToName(name, domain);
                    lst.add(name);
                }
            }
            if (lst.size() > 0) {
                users = lst.toArray(new String[lst.size()]);
            }
            Arrays.sort(users);
        } catch (Exception e) {
            String msg = "Error occurred while retrieving users for filter : " + filter + " & max Item limit : " +
                    maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return users;
    }

    /**
     * get internal role names of given user
     *
     * @param userNames to filter the search
     * @return String[] of internal roles
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doGetDisplayNamesForInternalRole(String[] userNames) throws UserStoreException {
        return userNames;
    }

    /**
     * check whether the user in given role
     *
     * @param userName to filter the search
     * @param roleName to display per page
     * @return boolean status
     * @throws UserStoreException if any exception occurred
     */
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {

        String[] roles = doGetExternalRoleListOfUser(userName, "*");
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * get shared role names of user store
     *
     * @param tenantDomain of currently logged in
     * @param filter       to filter the search
     * @param maxItemLimit to display per page
     * @return String[] of shared roles
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit) throws UserStoreException {

        String[] roles = new String[0];
        DB dbConnection = null;
        String mongoQuery;
        MongoPreparedStatement prepStmt;
        DBCursor cursor;

        if (maxItemLimit == 0) {
            return roles;
        }
        try {

            if (!isSharedGroupEnabled()) {
                return roles;
            }

            if (filter != null && filter.trim().length() != 0) {
                filter = filter.trim();
                filter = filter.replace("*", "%");
                filter = filter.replace("?", "_");
            } else {
                filter = "%";
            }

            List<String> lst = new LinkedList<String>();
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (dbConnection == null) {
                throw new UserStoreException("null connection");
            }

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_SHARED_ROLE_LIST);
            prepStmt = new MongoPreparedStatementImpl(dbConnection, mongoQuery);
            //byte count=0;
            prepStmt.setString("UM_ROLE_NAME", filter);
            try {
                cursor = prepStmt.find();
            } catch (MongoQueryException e) {


                String errorMessage =
                        "Error while fetching roles from JDBC user store for tenant domain : " + tenantDomain +
                                " & filter : " + filter + "& max item limit : " + maxItemLimit;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
            // Expected columns UM_ROLE_NAME, UM_TENANT_ID, UM_SHARED_ROLE
            if (cursor != null) {
                while (cursor.hasNext()) {
                    String name = cursor.next().get("UM_SHARED_ROLE").toString();
                    int roleTenantId = Integer.parseInt(cursor.next().get("UM_TENANT_ID").toString());
                    // append the domain if exist
                    String domain =
                            realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    name = UserCoreUtil.addDomainToName(name, domain);
                    name = UserCoreUtil.addTenantDomainToEntry(name, String.valueOf(roleTenantId));
                    lst.add(name);
                }
            }

            if (lst.size() > 0) {
                roles = lst.toArray(new String[lst.size()]);
            }
        } catch (RuntimeException e) {

            throw e;
        } catch (Exception e) {
            String errorMessage =
                    "Error while retrieving roles from JDBC user store for tenant domain : " + tenantDomain +
                            " & filter : " + filter + "& max item limit : " + maxItemLimit;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return roles;
    }

    /**
     * get user list of role
     *
     * @param filter   to filter the search
     * @param roleName to search for users
     * @return String[] of users
     * @throws UserStoreException if any exception occurred
     */
    protected String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {
        RoleContext roleContext = createRoleContext(roleName);
        return getUserListOfMongoDBRole(roleContext);
    }

    private String[] getUserListOfMongoDBRole(RoleContext ctx) throws UserStoreException {

        String roleName = ctx.getRoleName();
        String[] names = null;
        String mongoQuery;
        Map<String, Object> map = new HashMap<String, Object>();
        if (!ctx.isShared()) {

            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_ROLE);
            if (mongoQuery == null) {
                throw new UserStoreException("The mongo statement for retrieving user roles is null");
            }
            map.put("role.UM_ROLE_NAME", roleName);
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                map.put("role.UM_TENANT_ID", tenantId);
                map.put("userRole.UM_TENANT_ID", tenantId);
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            } else {
                names = getStringValuesFromDatabase(mongoQuery, map, true, true);
            }
        } else if (ctx.isShared()) {
            map.put("UM_ROLE_NAME", roleName);
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERS_IN_SHARED_ROLE);
            names = getStringValuesFromDatabase(mongoQuery, map, true, true);
        }

        List<String> userList = new ArrayList<String>();

        String domainName =
                realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        if (names != null) {
            for (String user : names) {
                user = UserCoreUtil.addDomainToName(user, domainName);
                userList.add(user);
            }

            names = userList.toArray(new String[userList.size()]);
        }
        log.debug("Roles are not defined for the role name " + roleName);

        return names;
    }

    private DB loadUserStoreSpacificDataSoruce() {

        if (db == null) {
            return MongoDatabaseUtil.createRealmDataSource(realmConfig);
        } else {
            return db;
        }
    }

    /**
     * get profile names of user
     *
     * @param userName to  search
     * @return String[] of profile names
     * @throws UserStoreException if any exception occurred
     */
    public String[] getProfileNames(String userName) throws UserStoreException {

        userName = UserCoreUtil.removeDomainFromName(userName);
        String mongoQuery;
        if (isCaseSensitiveUsername()) {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER);
        } else {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_PROFILE_NAMES_FOR_USER_CASE_INSENSITIVE);
        }
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving  is null");
        }
        MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(this.db, MongoDBRealmConstants.GET_PROFILE_NAMES_FOR_USER_MONGO_QUERY_CONDITION);
        prepStmt.setInt("UM_TENANT_ID", tenantId);
        prepStmt.setString("UM_USER_NAME", userName);
        String[] names = null;
        try {
            DBCursor cursor = prepStmt.find();
            if (cursor.hasNext()) {

                int userId = Integer.parseInt(cursor.next().get("UM_ID").toString());
                Map<String, Object> map = new HashMap<String, Object>();
                map.put("UM_USER_ID", userId);
                if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                    map.put("UM_TENANT_ID", tenantId);
                    names = getDistinctStringValues(mongoQuery, map);
                } else {
                    names = getDistinctStringValues(mongoQuery, map);
                }
                if (names.length == 0) {
                    names = new String[]{UserCoreConstants.DEFAULT_PROFILE};
                } else {
                    Arrays.sort(names);
                    if (Arrays.binarySearch(names, UserCoreConstants.DEFAULT_PROFILE) < 0) {
                        // we have to add the default profile
                        String[] newNames = new String[names.length + 1];
                        int i;
                        for (i = 0; i < names.length; i++) {
                            newNames[i] = names[i];
                        }
                        newNames[i] = UserCoreConstants.DEFAULT_PROFILE;
                        names = newNames;
                    }
                }
            }
            return names;
        } catch (MongoQueryException e) {

            String errorMessage = "Error occurred while getting profile names from username : ";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
    }

    /**
     * get all profile names
     *
     * @return String[] of profile names
     * @throws UserStoreException if any exception occurred
     */
    public String[] getAllProfileNames() throws UserStoreException {
        String mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_PROFILE_NAMES);
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving profile names is null");
        }
        String[] names;
        Map<String, Object> map = new HashMap<String, Object>();
        if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
            map.put("UM_TENANT_ID", tenantId);
            names = getDistinctStringValues(mongoQuery, map);
        } else {
            names = getDistinctStringValues(mongoQuery, map);
        }

        return names;
    }

    /**
     * check the status if read only
     *
     * @return boolean status
     * @throws UserStoreException if any exception occurred
     */
    public boolean isReadOnly() throws UserStoreException {
        return "true".equalsIgnoreCase(realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY));
    }

    /**
     * get user id of given user
     *
     * @param username to find userId
     * @return int userId
     * @throws UserStoreException if any exception occurred
     */
    public int getUserId(String username) throws UserStoreException {
        String mongoQuery;
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("UM_USER_NAME", username);
        if (isCaseSensitiveUsername()) {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_USERID_FROM_USERNAME);
        } else {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_USERID_FROM_USERNAME_CASE_INSENSITIVE);
        }
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            if (mongoQuery.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                map.put("UM_TENANT_ID", tenantId);
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, map);
            } else {
                id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, map);
            }
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting user id from username : " + username;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return id;
    }

    /**
     * get tenantId of given user
     *
     * @param username to find tenantId
     * @return int tenantId
     * @throws UserStoreException if any exception occurred
     */
    public int getTenantId(String username) throws UserStoreException {
        if (this.tenantId != MultitenantConstants.SUPER_TENANT_ID) {
            throw new UserStoreException("Not allowed to perform this operation");
        }
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("UM_USER_NAME", username);
        String mongoQuery;
        if (isCaseSensitiveUsername()) {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBRealmConstants.GET_TENANT_ID_FROM_USERNAME);
        } else {
            mongoQuery = realmConfig.getUserStoreProperty(MongoDBCaseInsensitiveConstants.GET_TENANT_ID_FROM_USERNAME_CASE_INSENSITIVE);
        }
        if (mongoQuery == null) {
            throw new UserStoreException("The mongo statement for retrieving ID is null");
        }
        int id = -1;
        DB dbConnection = null;
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            id = MongoDatabaseUtil.getIntegerValueFromDatabase(dbConnection, mongoQuery, map);
        } catch (Exception e) {
            String errorMessage = "Error occurred while getting tenant ID from username : " + username;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            MongoDatabaseUtil.closeConnection(dbConnection);
        }
        return id;
    }

    /**
     * get currently logged in tenantId
     *
     * @return int tenantId
     * @throws UserStoreException if any exception occurred
     */
    public int getTenantId() throws UserStoreException {
        return this.tenantId;
    }

    /**
     * get properties of given tenant
     *
     * @param tenant to  search for properties
     * @return Map of properties
     * @throws UserStoreException if any exception occurred
     */
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant) throws org.wso2.carbon.user.api.UserStoreException {
        return getProperties((Tenant) tenant);
    }

    /**
     * check if multiple profile allowed
     *
     * @return boolean status of multiple profile
     */
    public boolean isMultipleProfilesAllowed() {
        return true;
    }

    public void addRememberMe(String userName, String token) throws org.wso2.carbon.user.api.UserStoreException {

        Connection dbConnection = null;
        try {
            dbConnection = dataSource.getConnection();
            String[] values = DatabaseUtil.getStringValuesFromDatabase(dbConnection,
                    HybridJDBCConstants.GET_REMEMBERME_VALUE_SQL, userName, tenantId);
            Date createdTime = Calendar.getInstance().getTime();
            if (values != null && values.length > 0 && values[0].length() > 0) {
                // udpate
                DatabaseUtil.updateDatabase(dbConnection,
                        HybridJDBCConstants.UPDATE_REMEMBERME_VALUE_SQL, token, createdTime,
                        userName, tenantId);
            } else {
                // add
                DatabaseUtil.updateDatabase(dbConnection,
                        HybridJDBCConstants.ADD_REMEMBERME_VALUE_SQL, userName, token, createdTime,
                        tenantId);
            }
            dbConnection.commit();
        } catch (SQLException e) {
            String msg = "Database error occurred while saving remember me token for tenant : " + tenantId;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } catch (Exception e) {
            String errorMessage = "Error occurred while saving remember me token";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection);
        }
    }

    public boolean isValidRememberMeToken(String userName, String token) throws org.wso2.carbon.user.api.UserStoreException {
        try {
            if (isExistingUser(userName)) {
                return isExistingRememberMeToken(userName, token);
            }
        } catch (Exception e) {
            log.error("Validating remember me token failed for" + userName);
            // not throwing exception.
            // because we need to seamlessly direct them to login uis
        }

        return false;
    }

    /**
     * load default user store configration properties
     *
     * @return Properties of default user store
     */
    public Properties getDefaultUserStoreProperties() {

        Property[] mandatoryProperties = MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.toArray(
                new Property[MongoDBUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.size()]
        );
        Property[] optionalProperties = MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.toArray(
                new Property[MongoDBUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.size()]
        );
        Property[] advancedProperties = MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.toArray(
                new Property[MongoDBUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.size()]
        );
        Properties properties = new Properties();
        properties.setMandatoryProperties(mandatoryProperties);
        properties.setOptionalProperties(optionalProperties);
        properties.setAdvancedProperties(advancedProperties);
        return properties;
    }

    /**
     * get properties of tenant
     *
     * @param tenant to  search
     * @return Map of properties
     * @throws UserStoreException if any exception occurred
     */
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        return this.realmConfig.getUserStoreProperties();
    }

    /**
     * check whether the bulk import support or not
     *
     * @return boolean status
     * @throws UserStoreException if any exception occurred
     */
    public boolean isBulkImportSupported() throws UserStoreException {
        return true;
    }

    /**
     * get realm configuration
     *
     * @return RealmConfiguration of logged in users
     */
    public RealmConfiguration getRealmConfiguration() {
        return this.realmConfig;
    }

    @SuppressWarnings("WeakerAccess")
    protected void persistUser(String userName, Object credential, String[] roleList,
                               Map<String, String> claims, String profileName,
                               boolean requirePasswordChange) throws UserStoreException {
        if (!checkUserNameValid(userName)) {
            throw new UserStoreException(
                    "User name not valid. User name must be a non null string with following format, " +
                            realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX));

        }

        if (!checkUserPasswordValid(credential)) {
            throw new UserStoreException(
                    "Credential not valid. Credential must be a non null string with following format, " +
                            realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));

        }

        boolean isExisting = checkExistingUserName(userName);
        if (isExisting) {
            throw new UserStoreException("User name : " + userName
                    + " exists in the system. Please pick another user name");
        }

        DB dbConnection = null;
        String password = (String) credential;
        String sqlStmt1 = "";
        String sqlStmt2 = "";
        Map<String, Object> map = new HashMap<String, Object>();
        Map<String, Object> mapRole = new HashMap<String, Object>();
        try {
            dbConnection = loadUserStoreSpacificDataSoruce();
            sqlStmt1 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER);

            String saltValue = null;

            if ("true".equals(realmConfig.getUserStoreProperties().get(
                    MongoDBRealmConstants.STORE_SALTED_PASSWORDS))) {
                byte[] bytes = new byte[16];
                random.nextBytes(bytes);
                saltValue = Base64.encode(bytes);
            }

            password = this.preparePassword(password, saltValue);
            map.put("UM_USER_PASSWORD", password);
            map.put("UM_USER_NAME", userName);
            map.put("UM_REQUIRE_CHANGE", requirePasswordChange);
            map.put("UM_CHANGED_TIME", new Date());
            int Id = MongoDatabaseUtil.getIncrementedSequence(dbConnection, "UM_USER");
            map.put("UM_ID", Id);
            // do all 4 possibilities
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue == null)) {
                map.put("UM_SALT_VALUE", "");
                map.put("UM_TENANT_ID", tenantId);
                this.updateUserValue(dbConnection, sqlStmt1, map);
            } else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
                map.put("UM_SALT_VALUE", saltValue);
                map.put("UM_TENANT_ID", tenantId);
                this.updateUserValue(dbConnection, sqlStmt1, map);
            } else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN)
                    && (saltValue == null)) {
                map.put("UM_SALT_VALUE", "");
                map.put("UM_TENANT_ID", 0);
                this.updateUserValue(dbConnection, sqlStmt1, map);
            } else {
                map.put("UM_SALT_VALUE", null);
                map.put("UM_TENANT_ID", 0);
                this.updateUserValue(dbConnection, sqlStmt1, map);
            }

            String[] roles;
            if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
                roles = new String[0];
            } else {
                if (roleList == null || roleList.length == 0) {
                    roles = new String[]{this.realmConfig.getEveryOneRoleName()};
                } else {
                    Arrays.sort(roleList);
                    if (Arrays.binarySearch(roleList, realmConfig.getEveryOneRoleName()) < 0) {
                        roles = new String[roleList.length + 1];
                        int i;
                        for (i = 0; i < roleList.length; i++) {
                            roles[i] = roleList[i];
                        }
                        roles[i] = realmConfig.getEveryOneRoleName();
                    } else {
                        roles = roleList;
                    }
                }
            }
            if (roles != null && roles.length > 1) {
                // add user to role.
                //String sqlStmt2;
                sqlStmt2 = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER
                        + "-" + "MONGO_QUERY");
                if (sqlStmt2 == null) {
                    sqlStmt2 = realmConfig
                            .getUserStoreProperty(MongoDBRealmConstants.ADD_ROLE_TO_USER);
                }
                MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, MongoDBRealmConstants.GET_USERID_FROM_USERNAME_MONGO_QUERY);
                prepStmt.setString("UM_USER_NAME", userName);
                int rolesID[] = getRolesIDS(dbConnection, roles);
                String[] users = {userName};
                int userID[] = getUserIDS(dbConnection, users);
                mapRole.put("UM_TENANT_ID", tenantId);
                mapRole.put("UM_USER_ID", userID[0]);
                mapRole.put("UM_ROLE_ID", rolesID);
                MongoDatabaseUtil.updateUserRoleMappingInBatchMode(dbConnection, sqlStmt2,
                        mapRole);

                if (claims != null) {
                    // add the properties
                    if (profileName == null) {
                        profileName = UserCoreConstants.DEFAULT_PROFILE;
                    }

                    for (Map.Entry<String, String> entry : claims.entrySet()) {
                        String claimURI = entry.getKey();
                        String propName = claimManager.getAttributeName(claimURI);
                        String propValue = entry.getValue();
                        int userId = getUserId(userName);
                        Map<String, Object> mapProperties = new HashMap<String, Object>();
                        mapProperties.put("UM_USER_ID", userId);
                        mapProperties.put("UM_PROFILE_ID", profileName);
                        if (propValue.length() > 0) {
                            mapProperties.put(propName, propValue);
                        }
                        addProperty(dbConnection, mapProperties);
                    }
                }
            }
        } catch (Throwable e) {

            if (dbConnection != null) {
                this.deleteStringValuesFromDatabase(dbConnection, sqlStmt1, map);
                this.deleteStringValuesFromDatabase(dbConnection, sqlStmt2, mapRole);
            }
            log.error(e.getMessage(), e);
            throw new UserStoreException(e.getMessage(), e);
        }

    }

    private int[] getRolesIDS(DB dbConnection, String[] roles) throws MongoQueryException {

        String query = MongoDBRealmConstants.GET_IS_ROLE_EXISTING_MONGO_QUERY;
        int rolesID[] = new int[roles.length];
        int index = 0;
        for (String role : roles) {

            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(dbConnection, query);
            if (query.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt("UM_TENANT_ID", tenantId);
            }
            prepStmt.setString("UM_ROLE_NAME", role);
            DBCursor cursor = prepStmt.find();
            if (cursor.hasNext()) {

                int id = (int) Double.parseDouble(cursor.next().get("UM_ID").toString());
                if (id > 0) {
                    rolesID[index] = id;
                }
            }
            index++;
            prepStmt.close();
        }
        return rolesID;
    }

    /**
     * update user values
     *
     * @param connection to  mongodb
     * @param map        user property
     * @param query      to update user value to mongodb
     * @throws UserStoreException if any exception occurred
     */
    @SuppressWarnings("WeakerAccess")
    protected void updateUserValue(DB connection, String query, Map<String, Object> map) throws UserStoreException {

        JSONObject jsonKeys = new JSONObject(query);
        List<String> keys = MongoDatabaseUtil.getKeys(jsonKeys);
        try {
            MongoPreparedStatement prepStmt = new MongoPreparedStatementImpl(connection, query);
            for (String key : keys) {
                if (!key.equals("collection") || !key.equals("projection") || !key.equals("$set")) {
                    for (Map.Entry<String, Object> entry : map.entrySet()) {
                        if (entry.getKey().equals(key)) {
                            if (entry.getValue() == null) {
                                prepStmt.setString(key, null);
                            } else if (entry.getValue() instanceof String) {
                                prepStmt.setString(key, (String) entry.getValue());
                            } else if (entry.getValue() instanceof Date) {
                                prepStmt.setDate(key, (Date) entry.getValue());
                            } else if (entry.getValue() instanceof Integer) {
                                prepStmt.setInt(key, (Integer) entry.getValue());
                            } else if (entry.getValue() instanceof Boolean) {
                                prepStmt.setBoolean(key, (Boolean) entry.getValue());
                            }
                        }
                    }
                }
            }
            if (MongoDatabaseUtil.updateTrue(keys)) {

                prepStmt.update();
            } else {
                prepStmt.insert();
            }

        } catch (MongoQueryException e) {

            log.error("Error! " + e.getMessage(), e);
            log.error("Using json " + query);
            throw new UserStoreException("Error! " + e.getMessage(), e);
        } catch (Exception ex) {

            log.error("Error! " + ex.getMessage(), ex);
            log.error("Using json " + query);
            throw new UserStoreException("Error! " + ex.getMessage(), ex);
        } finally {
            MongoDatabaseUtil.closeConnection(connection);
        }

    }

    /**
     * add user property
     *
     * @param dbConnection to  mongodb
     * @param map          user property
     * @throws UserStoreException if any exception occurred
     */
    @SuppressWarnings("WeakerAccess")
    public void addProperty(DB dbConnection, Map<String, Object> map) throws UserStoreException {

        try {

            String mongoStmt = realmConfig.getUserStoreProperty(MongoDBRealmConstants.ADD_USER_PROPERTY);
            if (mongoStmt == null) {
                throw new UserStoreException("The mongo query statement for add user property sql is null");
            }

            if (mongoStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {

                map.put("UM_TENANT_ID", tenantId);
                updateUserClaimValuesToDatabase(dbConnection, map, false);
            } else {
                updateUserClaimValuesToDatabase(dbConnection, map, false);
            }
        } catch (Exception e) {
            String msg = "Error occurred while adding user property for user : " + map.get("UM_USER_ID");
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
    }

    /**
     * find if user name exists
     *
     * @param userName to check
     * @return boolean status if user exists or not
     */
    @SuppressWarnings("WeakerAccess")
    protected boolean checkExistingUserName(String userName) {

        boolean isExisting = false;
        String isUnique = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_USERNAME_UNIQUE);
        if (this.db == null) {

            this.db = loadUserStoreSpacificDataSoruce();
        }
        DBCollection collection = this.db.getCollection("UM_USER");
        if ("true".equals(isUnique) && !CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userName)) {
            BasicDBObject uniqueUser = new BasicDBObject("UM_USER_NAME", userName);
            DBCursor cursor = collection.find(uniqueUser);
            isExisting = cursor.hasNext();
            if (log.isDebugEnabled()) {
                log.debug("The username should be unique across tenants.");
            }
        } else {

            BasicDBObject userSearch;
            if (isCaseSensitiveUsername()) {
                userSearch = new BasicDBObject("UM_USER_NAME", userName).append("UM_TENANT_ID", this.tenantId);
            } else {
                userSearch = new BasicDBObject("UM_USER_NAME", new BasicDBObject("$regex", userName).append("$options", "i")).append("UM_TENANT_ID", this.tenantId);
            }
            DBCursor cursor = collection.find(userSearch);
            if (cursor != null) {
                isExisting = cursor.hasNext();
            }
        }
        return isExisting;
    }

    /**
     * check if is existing remember me token
     *
     * @param userName to  mongodb
     * @param token    user property
     * @return boolean status of token exists or not
     * @throws UserStoreException,SQLException if any exception occurred
     */
    @SuppressWarnings("WeakerAccess")
    public boolean isExistingRememberMeToken(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException, SQLException {

        boolean isValid = false;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        String value = null;
        Date createdTime = null;
        Connection dbConnection = dataSource.getConnection();
        try {
            prepStmt = dbConnection.prepareStatement(HybridJDBCConstants.GET_REMEMBERME_VALUE_SQL);
            prepStmt.setString(1, userName);
            prepStmt.setInt(2, tenantId);
            rs = prepStmt.executeQuery();
            while (rs.next()) {
                value = rs.getString(1);
                createdTime = rs.getTimestamp(2);
            }
        } catch (SQLException e) {
            String errorMessage = "Error occurred while checking is existing remember me token for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (value != null && createdTime != null) {
            Calendar calendar = Calendar.getInstance();
            Date nowDate = calendar.getTime();
            calendar.setTime(createdTime);
            calendar.add(Calendar.SECOND, CarbonConstants.REMEMBER_ME_COOKIE_TTL);
            Date expDate = calendar.getTime();
            if (expDate.before(nowDate)) {
                // Do nothing remember me expired.
                // Return the user gracefully
                log.debug("Remember me token has expired !!");
            } else {

                // We also need to compare the token
                if (value.equals(token)) {
                    isValid = true;
                } else {
                    log.debug("Remember me token in DB and token in request are different !!");
                    //isValid = false;
                }
            }
        }

        return isValid;
    }

    public static class RoleBreakdown {
        private String[] roles;
        private Integer[] tenantIds;

        private String[] sharedRoles;
        private Integer[] sharedTenantids;

        public RoleBreakdown() {
        }

        public String[] getRoles() {
            return roles.clone();
        }

        public void setRoles(String[] roles) {
            this.roles = roles.clone();
        }

        @SuppressWarnings("unused")
        public Integer[] getTenantIds() {
            return tenantIds.clone();
        }

        public void setTenantIds(Integer[] tenantIds) {
            this.tenantIds = tenantIds.clone();
        }

        public String[] getSharedRoles() {
            return sharedRoles.clone();
        }

        public void setSharedRoles(String[] sharedRoles) {
            this.sharedRoles = sharedRoles.clone();
        }

        public Integer[] getSharedTenantids() {
            return sharedTenantids.clone();
        }

        public void setSharedTenantids(Integer[] sharedTenantids) {
            this.sharedTenantids = sharedTenantids.clone();
        }

    }

    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    protected void persistDomain() throws UserStoreException {

        String domain = UserCoreUtil.getDomainName(this.realmConfig);
        if (domain != null) {
            //  MongoUserCoreUtil.persistDomain(domain, this.tenantId, this.db);
            UserCoreUtil.persistDomain(domain, this.tenantId, dataSource);
        }
    }

    protected void addInitialAdminData(boolean addAdmin, boolean initialSetup) throws UserStoreException {

        if (realmConfig.getAdminRoleName() == null || realmConfig.getAdminUserName() == null) {
            log.error("Admin user name or role name is not valid. Please provide valid values.");
            throw new UserStoreException(
                    "Admin user name or role name is not valid. Please provide valid values.");
        }
        String adminUserName = UserCoreUtil.removeDomainFromName(realmConfig.getAdminUserName());
        String adminRoleName = UserCoreUtil.removeDomainFromName(realmConfig.getAdminRoleName());
        boolean userExist = false;
        boolean roleExist = false;
        boolean isInternalRole = false;
        try {
            if (Boolean.parseBoolean(this.getRealmConfiguration().getUserStoreProperty(
                    UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED))) {
                roleExist = doCheckExistingRole(adminRoleName);
            }
        } catch (Exception e) {
            //ignore
        }

        if (!roleExist) {
            try {
                roleExist = hybridRoleManager.isExistingRole(adminRoleName);
            } catch (Exception e) {
                //ignore
            }
            if (roleExist) {
                isInternalRole = true;
            }
        }

        try {
            userExist = doCheckExistingUser(adminUserName);
        } catch (Exception e) {
            //ignore
        }

        if (!userExist) {
            if (isReadOnly()) {
                String message = "Admin user can not be created in primary user store. " +
                        "User store is read only. " +
                        "Please pick a user name which is exist in the primary user store as Admin user";
                if (initialSetup) {
                    throw new UserStoreException(message);
                } else if (log.isDebugEnabled()) {
                    log.error(message);
                }
            } else if (addAdmin) {
                try {
                    this.doAddUser(adminUserName, realmConfig.getAdminPassword(),
                            null, null, null, false);
                } catch (Exception e) {
                    String message = "Admin user has not been created. " +
                            "Error occurs while creating Admin user in primary user store.";
                    if (initialSetup) {
                        throw new UserStoreException(message, e);
                    } else if (log.isDebugEnabled()) {
                        log.error(message, e);
                    }
                }
            } else {
                if (initialSetup) {
                    String message = "Admin user can not be created in primary user store. " +
                            "Add-Admin has been set to false. " +
                            "Please pick a User name which is exist in the primary user store as Admin user";
                    if (log.isDebugEnabled()) {
                        log.error(message);
                    }
                    throw new UserStoreException(message);
                }
            }
        }

        if (!roleExist) {
            if (addAdmin) {
                if (!isReadOnly() && writeGroupsEnabled) {
                    try {
                        this.doAddRole(adminRoleName, new String[]{adminUserName}, false);
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        String message = "Admin role has not been created. " +
                                "Error occurs while creating Admin role in primary user store.";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                } else {
                    // creates internal role
                    try {
                        hybridRoleManager.addHybridRole(adminRoleName, new String[]{adminUserName});
                        isInternalRole = true;
                    } catch (Exception e) {
                        String message = "Admin role has not been created. " +
                                "Error occurs while creating Admin role in primary user store.";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                }
            } else {
                String message = "Admin role can not be created in primary user store. " +
                        "Add-Admin has been set to false. " +
                        "Please pick a Role name which is exist in the primary user store as Admin Role";
                if (initialSetup) {
                    throw new UserStoreException(message);
                } else if (log.isDebugEnabled()) {
                    log.error(message);
                }
            }
        }

        if (isInternalRole) {
            if (!hybridRoleManager.isUserInRole(adminUserName, adminRoleName)) {
                try {
                    hybridRoleManager.updateHybridRoleListOfUser(adminUserName, null,
                            new String[]{adminRoleName});
                } catch (Exception e) {
                    String message = "Admin user has not been assigned to Admin role. " +
                            "Error while assignment is done";
                    if (initialSetup) {
                        throw new UserStoreException(message, e);
                    } else if (log.isDebugEnabled()) {
                        log.error(message, e);
                    }
                }
            }
            realmConfig.setAdminRoleName(UserCoreUtil.addInternalDomainName(adminRoleName));
        } else if (!isReadOnly() && writeGroupsEnabled) {
            if (!this.doCheckIsUserInRole(adminUserName, adminRoleName)) {
                if (addAdmin) {
                    try {
                        this.doUpdateRoleListOfUser(adminUserName, null,
                                new String[]{adminRoleName});
                    } catch (Exception e) {
                        String message = "Admin user has not been assigned to Admin role. " +
                                "Error while assignment is done";
                        if (initialSetup) {
                            throw new UserStoreException(message, e);
                        } else if (log.isDebugEnabled()) {
                            log.error(message, e);
                        }
                    }
                } else {
                    String message = "Admin user can not be assigned to Admin role " +
                            "Add-Admin has been set to false. Please do the assign it in user store level";
                    if (initialSetup) {
                        throw new UserStoreException(message);
                    } else if (log.isDebugEnabled()) {
                        log.error(message);
                    }
                }
            }
        }

        doInitialUserAdding();
    }

    protected void doInitialSetup() throws UserStoreException {

        systemUserRoleManager = new SystemUserRoleManager(dataSource, tenantId);
        hybridRoleManager = new HybridRoleManager(dataSource, tenantId, realmConfig, userRealm);
    }


    public boolean isExistingRole(String roleName, boolean shared) throws org.wso2.carbon.user.api.UserStoreException {
        if (shared) {
            return isExistingShareRole(roleName);
        } else {
            return isExistingRole(roleName);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void addUser(String userName, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName) throws UserStoreException {
        this.addUser(userName, credential, roleList, claims, profileName, false);
    }


    public void addInternalRole(String roleName, String[] userList,
                                org.wso2.carbon.user.api.Permission[] permission) throws UserStoreException {
        doAddInternalRole(roleName, userList, permission);
    }

    /**
     * Helper method
     *
     * @param userName     user name of the user
     * @param roleName     role of given user
     * @param currentRoles all the active roles of currently
     */
    @SuppressWarnings("unused")
    private void addToIsUserHasRole(String userName, String roleName, String[] currentRoles) {
        List<String> roles;
        if (currentRoles != null) {
            roles = new ArrayList<String>(Arrays.asList(currentRoles));
        } else {
            roles = new ArrayList<String>();
        }
        roles.add(roleName);
        addToUserRolesCache(tenantId, userName, roles.toArray(new String[roles.size()]));
    }

    //////////////////////////////////// Shared role APIs finish //////////////////////////////////////////

    /**
     * Getter method for claim manager property specifically to be used in the implementations of
     * UserOperationEventListener implementations
     *
     * @return return the claim manager
     */
    public ClaimManager getClaimManager() {
        return claimManager;
    }


    /**
     *
     *
     * @return whether the shared group enabled or not
     */
    public boolean isSharedGroupEnabled() {
        String value = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.SHARED_GROUPS_ENABLED);
        try {
            return realmConfig.isPrimary() && !isReadOnly() && TRUE_VALUE.equalsIgnoreCase(value);
        } catch (UserStoreException e) {
            log.error(e);
        }
        return false;
    }

    /**
     * Removes the shared roles relevant to the provided tenant domain
     *
     * @param sharedRoles  accept all the shared roles given
     * @param tenantDomain accept the tenant domain given
     */
    protected void filterSharedRoles(List<String> sharedRoles, String tenantDomain) {
        if (tenantDomain != null) {
            for (Iterator<String> i = sharedRoles.iterator(); i.hasNext(); ) {
                String role = i.next();
                if (role.contains(tenantDomain)) {
                    i.remove();
                }
            }
        }
    }

    /**
     * @return check whether the SCIM enabled
     */
    public boolean isSCIMEnabled() {
        String scimEnabled = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_SCIM_ENABLED);
        return scimEnabled != null && Boolean.parseBoolean(scimEnabled);
    }

    /**
     * @return the every one role name
     */
    protected String getEveryOneRoleName() {
        return realmConfig.getEveryOneRoleName();
    }

    /**
     * @return the admin role name
     */
    protected String getAdminRoleName() {
        return realmConfig.getAdminRoleName();
    }


    /**
     * @param roleName accept the role name
     * @return whether the given role name is valid
     */
    protected boolean isRoleNameValid(String roleName) {
        if (roleName == null) {
            return false;
        }

        if (roleName.length() < 1) {
            return false;
        }

        String regularExpression = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_ROLE_NAME_JAVA_REG_EX);
        if (regularExpression != null) {
            if (!isFormatCorrect(regularExpression, roleName)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param tenantID accept the active tenantID
     */
    protected void clearUserRolesCacheByTenant(int tenantID) {
        if (userRolesCache != null) {
            userRolesCache.clearCacheByTenant(tenantID);
        }
        AuthorizationCache authorizationCache = AuthorizationCache.getInstance();
        authorizationCache.clearCacheByTenant(tenantID);
    }

    /**
     * @param regularExpression accept the regular expression pattern string
     * @param attribute         accept attribute to check
     * @return if true or false respectively attribute is valid or not
     */
    private boolean isFormatCorrect(String regularExpression, String attribute) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(attribute);
        return m2.matches();
    }


    /**
     * @param claimList accept the claim list
     * @return all the claim attributes of respective claims
     * @throws UserStoreException if any exception occur
     */
    protected List<String> getMappingAttributeList(List<String> claimList)
            throws UserStoreException {
        ArrayList<String> attributeList;
        Iterator<String> claimIter;

        attributeList = new ArrayList<String>();
        if (claimList == null) {
            return attributeList;
        }
        claimIter = claimList.iterator();
        while (claimIter.hasNext()) {
            try {
                attributeList.add(claimManager.getAttributeName(claimIter.next()));
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException(e);
            }
        }
        return attributeList;
    }

    /**
     * @throws UserStoreException if error occured
     */
    protected void doInitialUserAdding() throws UserStoreException {

        String systemUser = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME);
        String systemRole = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME);

        if (!systemUserRoleManager.isExistingSystemUser(systemUser)) {
            systemUserRoleManager.addSystemUser(systemUser,
                    UserCoreUtil.getPolicyFriendlyRandomPassword(systemUser), null);
        }

        if (!systemUserRoleManager.isExistingRole(systemRole)) {
            systemUserRoleManager.addSystemRole(systemRole, new String[]{systemUser});
        }

        if (!hybridRoleManager.isExistingRole(UserCoreUtil.removeDomainFromName(realmConfig
                .getEveryOneRoleName()))) {
            hybridRoleManager.addHybridRole(
                    UserCoreUtil.removeDomainFromName(realmConfig.getEveryOneRoleName()), null);
        }
    }

    protected boolean isInitSetupDone() throws UserStoreException {

        boolean isInitialSetUp = false;
        String systemUser = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME);
        String systemRole = UserCoreUtil.removeDomainFromName(CarbonConstants.REGISTRY_ANONNYMOUS_ROLE_NAME);

        if (systemUserRoleManager.isExistingSystemUser(systemUser)) {
            isInitialSetUp = true;
        }

        if (systemUserRoleManager.isExistingRole(systemRole)) {
            isInitialSetUp = true;
        }

        return isInitialSetUp;
    }

    /**
     * @return the domain name of user
     */
    protected String getMyDomainName() {
        return UserCoreUtil.getDomainName(realmConfig);
    }

    public void deletePersistedDomain(String domain) throws UserStoreException {
        if (domain != null) {
            if (log.isDebugEnabled()) {
                log.debug("Deleting persisted domain " + domain);
            }
            UserCoreUtil.deletePersistedDomain(domain, this.tenantId, dataSource);
        }
    }

    public void updatePersistedDomain(String oldDomain, String newDomain) throws UserStoreException {
        if (oldDomain != null && newDomain != null) {
            // Checks for the newDomain exists already
            // Traverse through realm configuration chain since USM chain doesn't contains the disabled USMs
            RealmConfiguration realmConfigTmp = this.getRealmConfiguration();
            while (realmConfigTmp != null) {
                String domainName = realmConfigTmp.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                if (newDomain.equalsIgnoreCase(domainName)) {
                    throw new UserStoreException("Cannot update persisted domain name " + oldDomain + " into " + newDomain + ". New domain name already in use");
                }
                realmConfigTmp = realmConfigTmp.getSecondaryRealmConfig();
            }

            if (log.isDebugEnabled()) {
                log.debug("Renaming persisted domain " + oldDomain + " to " + newDomain);
            }
            UserCoreUtil.updatePersistedDomain(oldDomain, newDomain, this.tenantId, dataSource);

        }
    }

    /**
     * Checks whether the role is a shared role or not
     *
     * @param roleName     given role name
     * @param roleNameBase role name base
     * @return whether the role is shared or not
     */
    public boolean isSharedRole(String roleName, String roleNameBase) {

        // Only checks the shared groups are enabled
        return isSharedGroupEnabled();
    }

    /**
     * Checks whether the provided role name belongs to the logged in tenant.
     * This check is done using the domain name which is appended at the end of
     * the role name
     *
     * @param roleName given role name
     * @return whether the role is belong to logged int tenant or not
     */
    protected boolean isOwnRole(String roleName) {
        return true;
    }

    public void addRole(String roleName, String[] userList,
                        org.wso2.carbon.user.api.Permission[] permissions)
            throws org.wso2.carbon.user.api.UserStoreException {
        addRole(roleName, userList, permissions, false);

    }

    public static void setDBDataSource(DataSource source) {

        dataSource = source;
    }

    public boolean isOthersSharedRole(String roleName) {
        return false;
    }


    public HybridRoleManager getInternalRoleManager() {
        return hybridRoleManager;
    }


}
