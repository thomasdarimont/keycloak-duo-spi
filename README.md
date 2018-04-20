# keycloak-duo-spi

Provides an authentication execution for keycloak that presents a Duo iframe, to be used after primary authentication.

## Build

```
$ mvn clean install
```

## Install

(assumes keycloak is installed to `/opt/keycloak`)
```
$ cp target/keycloak-duo-spi-jar-with-dependencies.jar /opt/keycloak/standalone/deployments/
$ cp src/main/duo-mfa.ftl /opt/keycloak/themes/base/login/duo-mfa.ftl
# restart keycloak
```
## Configure

You need to add Duo as a trusted frame-able source to the Keycloak Content Security Policy.

Since you can't modify the default Authentication Flows, make a copy of Browser. Add `Duo MFA` as an execution under `Browser Forms`.

