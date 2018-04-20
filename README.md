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
Content-Security-Policy: `frame-src https://*.duosecurity.com/ 'self'; ...`
![csp-example](https://user-images.githubusercontent.com/1660470/39064509-9e92117a-4483-11e8-94e8-dbe00e3afddb.png)

Since you can't modify the default Authentication Flows, make a copy of Browser. Add `Duo MFA` as an execution under `Browser Forms`.
![flow-example](https://user-images.githubusercontent.com/1660470/39064512-9eaf9bf0-4483-11e8-947d-529578a1c44d.png)

When you hit `Config` you can enter your Duo ikey, skey, and apihost (get these from duo.com by adding a *Web SDK* app). 

Then make sure to bind your Copy of Browser flow to the Browser Flow (on the Bindings tab).
