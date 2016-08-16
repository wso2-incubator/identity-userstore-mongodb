package org.wso2.carbon.identity.user.store.mongodb.userstoremanager.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.user.store.mongodb.userstoremanager.MongoDBUserStoreManager;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.DefaultRealmService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tracker.UserStoreManagerRegistry;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;


/**
 * @scr.component name="mongodb.userstoremanager.dscomponent" immediate=true
 */
@SuppressWarnings({"unused", "JavaDoc"})
public class MongoDBUserStoreDSComponent {

    private static final Log log = LogFactory.getLog(MongoDBUserStoreDSComponent.class);

    protected void activate(ComponentContext cc) throws Exception {

        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext
                .getThreadLocalCarbonContext();
        carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
        carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        UserStoreManager userStoreManager = new MongoDBUserStoreManager();
        RealmService service = new DefaultRealmService(cc.getBundleContext());
        MongoDBUserStoreManager.setDBDataSource(DatabaseUtil.getRealmDataSource(service.getBootstrapRealmConfiguration()));
        cc.getBundleContext().registerService(UserStoreManager.class.getName(), userStoreManager, null);
        log.info("MongoDB User Store bundle activated successfully..");
        UserStoreManagerRegistry.init(cc.getBundleContext());
        System.out.println("Mongo Started");
    }

    @SuppressWarnings({"RedundantThrows", "UnusedParameters"})
    protected void deactivate(ComponentContext cc) throws Exception {
        System.out.println("MongoDB Bundle Shutting down");
        if (log.isDebugEnabled()) {
            log.debug("MongoDB User Store Manager is deactivated ");
        }
    }

}
