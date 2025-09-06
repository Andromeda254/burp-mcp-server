# Local Libraries Directory

This directory contains JAR files that are not available in public Maven repositories.

## Files

- `montoya-api.jar` - BurpSuite Montoya API (version 0.9.25)
  - Downloaded from: https://repo1.maven.org/maven2/net/portswigger/burp/extender/montoya-api/0.9.25/montoya-api-0.9.25.jar
  - Required for BurpSuite extension development and integration
  - This is the latest version available on Maven Central

## Setup

To download the required JAR files:

```bash
# Download Montoya API (latest version from Maven Central)
curl -L -o libs/montoya-api.jar https://repo1.maven.org/maven2/net/portswigger/burp/extender/montoya-api/0.9.25/montoya-api-0.9.25.jar
```

These files are referenced in `build.gradle` using:

```gradle
implementation files('libs/montoya-api.jar')
```
