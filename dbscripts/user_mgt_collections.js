// Function to handle auto-increment IDs
db.system.js.save(
    {
        _id: "getNextSequence",
        value : function(name) {
            var ret = db.COUNTERS.findAndModify(
                {
                    query: { _id: name },
                    update: { $inc: { seq: 1 } },
                    new: true
                }
            );
            return ret.seq;
        }
    }
);

// Above function will be stored in the system.js script
// We need to load the server scripts before using it
db.loadServerScripts();


// #####################################
//  USER MANAGEMENT RELATED COLLECTIONS
// #####################################

db.COUNTERS.insert({

    _id: "UM_TENANT",

    seq: 0

});
db.UM_TENANT.insert({
    UM_ID: getNextSequence("UM_TENANT"),
    UM_DOMAIN_NAME: "",
    UM_EMAIL: "",
    UM_ACTIVE: false,
    UM_CREATED_DATE: Timestamp(),
    UM_USER_CONFIG: BinData(5,"test")
});
db.UM_TENANT.createIndex({UM_ID: 16},{unique: true});
db.UM_TENANT.createIndex({UM_DOMAIN_NAME: 5},{unique: true});


db.COUNTERS.insert({

    _id: "UM_DOMAIN",

    seq: 0

});
db.UM_DOMAIN.insert({
    UM_DOMAIN_ID: getNextSequence("UM_DOMAIN"),
    UM_DOMAIN_NAME: "",
    UM_TENANT_ID: 0
});
db.UM_DOMAIN.createIndex({UM_DOMAIN_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_USER",

    seq: 0

});
db.UM_USER.insert({
     UM_ID: getNextSequence("UM_USER"), 
     UM_USER_NAME: "", 
     UM_USER_PASSWORD: "",
     UM_SALT_VALUE: "",
     UM_REQUIRE_CHANGE: false,
     UM_CHANGED_TIME: Timestamp(),
     UM_TENANT_ID: 0
});
db.UM_USER.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_USER.createIndex({UM_USER_NAME: 5,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_SYSTEM_USER",

    seq: 0

});
db.UM_SYSTEM_USER.insert({
     UM_ID: getNextSequence("UM_SYSTEM_USER"), 
     UM_USER_NAME: "", 
     UM_USER_PASSWORD: "",
     UM_SALT_VALUE: "",
     UM_REQUIRE_CHANGE: false,
     UM_CHANGED_TIME: Timestamp(),
     UM_TENANT_ID: 0
});
db.UM_SYSTEM_USER.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SYSTEM_USER.createIndex({UM_USER_NAME: 5,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_ROLE",

    seq: 0

});
db.UM_ROLE.insert({
     UM_ID: getNextSequence("UM_SYSTEM_USER"), 
     UM_ROLE_NAME: "",
     UM_TENANT_ID: 0,
     UM_SHARED_ROLE: false
});
db.UM_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_ROLE.createIndex({UM_ROLE_NAME: 5,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_MODULE",

    seq: 0

});
db.UM_MODULE.insert({
    UM_ID: getNextSequence("UM_MODULE"),
    UM_MODULE_NAME: ""
});
db.UM_MODULE.createIndex({UM_ID: 16},{unique: true});
db.UM_MODULE.createIndex({UM_MODULE_NAME: 5},{unique: true});


db.UM_MODULE_ACTIONS.insert({
   UM_ACTION: "ACT",
   UM_MODULE_ID: 1
});
db.UM_MODULE_ACTIONS.createIndex({UM_ACTION: 5,UM_MODULE_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_PERMISSION",

    seq: 0

});
db.UM_PERMISSION.insert({
    UM_ID : getNextSequence("UM_PERMISSION"), 
    UM_RESOURCE_ID: "", 
    UM_ACTION: "", 
    UM_TENANT_ID: 0, 
    UM_MODULE_ID: 0
});
db.UM_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_PERMISSION.createIndex({UM_RESOURCE_ID: 5,UM_ACTION: 5,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_ROLE_PERMISSION",

    seq: 0

});
db.UM_ROLE_PERMISSION.insert({
    UM_ID: getNextSequence("UM_ROLE_PERMISSION"), 
    UM_PERMISSION_ID: 1, 
    UM_ROLE_NAME: "",
    UM_IS_ALLOWED: 0, 
    UM_TENANT_ID: 0,
    UM_DOMAIN_ID : 1
});
db.UM_ROLE_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_ROLE_PERMISSION.createIndex({UM_PERMISSION_ID: 16,UM_ROLE_NAME: 5,UM_TENANT_ID: 16,UM_DOMAIN_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_USER_PERMISSION",

    seq: 0

});
db.UM_USER_PERMISSION.insert({
    UM_ID: getNextSequence("UM_USER_PERMISSION"), 
    UM_PERMISSION_ID: 1, 
    UM_USER_NAME: "",
    UM_IS_ALLOWED: 0,          
    UM_TENANT_ID: 0
});
db.UM_USER_PERMISSION.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_USER_ROLE",

    seq: 0

});
db.UM_USER_ROLE.insert({
    UM_ID: getNextSequence("UM_USER_ROLE"), 
    UM_ROLE_ID: 1, 
    UM_USER_ID: 1,
    UM_TENANT_ID: 0
});
db.UM_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_USER_ROLE.createIndex({UM_USER_ID: 16,UM_ROLE_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.UM_SHARED_USER_ROLE.insert({
    UM_ROLE_ID: 1,
    UM_USER_ID: 1,
    UM_USER_TENANT_ID: 0,
    UM_ROLE_TENANT_ID: 0   
});
db.UM_SHARED_USER_ROLE.createIndex({UM_USER_ID: 16,UM_ROLE_ID: 16,UM_USER_TENANT_ID: 16,UM_ROLE_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_ACCOUNT_MAPPING",

    seq: 0

});
db.UM_ACCOUNT_MAPPING.insert({
    UM_ID: getNextSequence("UM_ACCOUNT_MAPPING"),
    UM_USER_NAME: "",
    UM_TENANT_ID: 0,
    UM_USER_STORE_DOMAIN: "",
    UM_ACC_LINK_ID: 0
});
db.UM_ACCOUNT_MAPPING.createIndex({UM_ID: 16},{unique: true});
db.UM_ACCOUNT_MAPPING.createIndex({UM_USER_NAME: 5,UM_TENANT_ID: 16,UM_USER_STORE_DOMAIN: 5,UM_ACC_LINK_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_USER_ATTRIBUTE",

    seq: 0

});
db.UM_USER_ATTRIBUTE.insert({
    
        UM_ID: getNextSequence("UM_USER_ATTRIBUTE"), 
        UM_ATTR_NAME: "", 
        UM_ATTR_VALUE: "", 
        UM_PROFILE_ID: "", 
        UM_USER_ID: 1, 
        UM_TENANT_ID: 0
});
db.UM_USER_ATTRIBUTE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_USER_ATTRIBUTE.createIndex({UM_USER_ID: 16});


db.COUNTERS.insert({

    _id: "UM_DIALECT",

    seq: 0

});
db.UM_DIALECT.insert({
        UM_ID: getNextSequence("UM_DIALECT"), 
        UM_DIALECT_URI: "", 
        UM_TENANT_ID: 0
});
db.UM_DIALECT.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_DIALECT.createIndex({UM_DIALECT_URI: 5,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_CLAIM",

    seq: 0

});
db.UM_CLAIM.insert({
        UM_ID: getNextSequence("UM_CLAIM"), 
        UM_DIALECT_ID: 1, 
        UM_CLAIM_URI: "", 
        UM_DISPLAY_TAG: "", 
        UM_DESCRIPTION: "", 
        UM_MAPPED_ATTRIBUTE_DOMAIN: "",
        UM_MAPPED_ATTRIBUTE: "", 
        UM_REG_EX: "", 
        UM_SUPPORTED: 0, 
        UM_REQUIRED: 0, 
        UM_DISPLAY_ORDER: 1,
	UM_CHECKED_ATTRIBUTE: 1,
        UM_READ_ONLY: 1,
        UM_TENANT_ID: 0
});
db.UM_CLAIM.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_CLAIM.createIndex({UM_CLAIM_URI: 5,UM_DIALECT_ID: 16,UM_TENANT_ID: 16,UM_MAPPED_ATTRIBUTE_DOMAIN: 5},{unique: true});


db.COUNTERS.insert({

    _id: "UM_PROFILE_CONFIG",

    seq: 0

});
db.UM_PROFILE_CONFIG.insert({
    UM_ID : getNextSequence("UM_PROFILE_CONFIG"), 
    UM_DIALECT_ID: 1, 
    UM_PROFILE_NAME: "", 
    UM_TENANT_ID: 0 
});
db.UM_PROFILE_CONFIG.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_CLAIM_BEHAVIOR",

    seq: 0

});
db.UM_CLAIM_BEHAVIOR.insert({
    UM_ID : getNextSequence("UM_CLAIM_BEHAVIOR"),
    UM_PROFILE_ID: 1,
    UM_CLAIM_ID: 1,
    UM_BEHAVIOUR: 0,
    UM_TENANT_ID: 0
});
db.UM_CLAIM_BEHAVIOR.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_HYBRID_ROLE",

    seq: 0

});
db.UM_HYBRID_ROLE.insert({
   UM_ID: getNextSequence("UM_HYBRID_ROLE"),
   UM_ROLE_NAME: "",
   UM_TENANT_ID: 0
});
db.UM_HYBRID_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_HYBRID_USER_ROLE",

    seq: 0

});
db.UM_HYBRID_USER_ROLE.insert({
    UM_ID: getNextSequence("UM_HYBRID_USER_ROLE"),
    UM_USER_NAME: "",
    UM_ROLE_ID: 1,
    UM_TENANT_ID: 0,
    UM_DOMAIN_ID: 1
});
db.UM_HYBRID_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_HYBRID_USER_ROLE.createIndex({UM_USER_NAME: 5,UM_ROLE_ID: 16,UM_TENANT_ID: 16,UM_DOMAIN_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_SYSTEM_ROLE",

    seq: 0

});
db.UM_SYSTEM_ROLE.insert({
    UM_ID: getNextSequence("UM_SYSTEM_ROLE"),
    UM_ROLE_NAME: "",
    UM_TENANT_ID: 0
});
db.UM_SYSTEM_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SYSTEM_ROLE.createIndex({UM_ROLE_NAME: 5,UM_TENANT_ID: 16});


db.COUNTERS.insert({

    _id: "UM_SYSTEM_USER_ROLE",

    seq: 0

});
db.UM_SYSTEM_USER_ROLE.insert({
   UM_ID: getNextSequence("UM_SYSTEM_USER_ROLE"),
   UM_USER_NAME: "",
   UM_ROLE_ID: 1,
   UM_TENANT_ID: 0 
});
db.UM_SYSTEM_USER_ROLE.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
db.UM_SYSTEM_USER_ROLE.createIndex({UM_USER_NAME: 5,UM_ROLE_ID: 16,UM_TENANT_ID: 16},{unique: true});


db.COUNTERS.insert({

    _id: "UM_HYBRID_REMEMBER_ME",

    seq: 0

});
db.UM_HYBRID_REMEMBER_ME.insert({
   UM_ID: getNextSequence("UM_HYBRID_REMEMBER_ME"),
   UM_USER_NAME: "",
   UM_COOKIE_VALUE: "",
   UM_CREATED_TIME: Timestamp(),
   UM_TENANT_ID: 0
});
db.UM_HYBRID_REMEMBER_ME.createIndex({UM_ID: 16,UM_TENANT_ID: 16},{unique: true});
