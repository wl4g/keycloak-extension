package org.keycloak.social.wecom;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

@SuppressWarnings("serial")
public class DingtalkProviderConfig extends OAuth2IdentityProviderConfig {

    public DingtalkProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public DingtalkProviderConfig() {
    }

    public String getAgentId() {
        return getConfig().get("agentId");
    }

    public void setAgentId(String agentId) {
        getConfig().put("agentId", agentId);
    }

    public String getQrcodeAuthorizationUrl() {
        return getConfig().get("qrcodeAuthorizationUrl");
    }

    public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
        getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
    }
}
