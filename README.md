# Keycloak extensions

- Keycloak the collection of enterprise-level extension plugins, supporting such as Identity social Provider WeCom/dingtalk, cloudiam theme etc...

## Quick Start

- [Keycloak for Dingtalk](social-dingtalk/README.md)
- [Keycloak for WeCom](social-wecom/README.md)
- [Keycloak for CloudIam theme](theme-cloudiam/README.md)

## Development Guide

```bash
git clone https://github.com/wl4g/keycloak-extension.git
cd keycloak-extension
mvn clean package -DskipTests -P '!gpg'
```

```bash
cd keycloak-extension/wecom
docker build -t keycloak-extension-wecom:19.0.1 .
```

- Browser view `http://localhost`

Create WeCom Provider:
![create_wecom_provider](images/create_wecom_provider.jpg)

Input WeCom Info:
![create_wecom_provider](images/info_setting.jpg)


