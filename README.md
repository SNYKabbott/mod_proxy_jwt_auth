mod_proxy_jwt_auth
===================

Apache2 module which passes a Json Web Token as a Bearer authorization header to a proxied server, optionally mapping request environment variables to JWT claims.
This module is intended to allow Apache to authenticate itself to a backend application when acting as a reverse proxy.

Supported algorithms : HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

More on JWT : https://jwt.io/

Quickstart
----------

NOTE: The following commands must be run from the repo directory, require Docker and docker-compose, and leave Docker images on the host.

### Compile libjwt and mod_proxy_jwt_auth, package into RPMs (available at ./RPMS), and run the test suite:

```bash
./build.sh
```

Use
---

Send a JWT to the proxied "target" app with ENV vars TEST_VAR_1 and TEST_VAR_2 mapped to JWT claims testvar1 and testvar2:

```
<Location />
  SetEnv TEST_VAR_1 OneValue
  SetEnv TEST_VAR_2 TwoValue

  ProxyJwtAuthEnabled On
  ProxyJwtAuthClaimMap TEST_VAR_1 testvar1
  ProxyJwtAuthClaimMap TEST_VAR_2 testvar2

  AuthType None
  Require all granted
  ProxyPass http://target
</Location>
```

Settings
--------

### ProxyJwtAuthEnabled directive
**Description:** Enable mod_proxy_jwt_auth  
**Syntax:** ProxyJwtAuthEnabled On  
**Context:** server config, virtual host, directory  

Enables the module, off by default.

### ProxyJwtAuthAllowMissing directive
**Description:** Enable missing env var tolerance  
**Syntax:** ProxyJwtAuthAllowMissing On  
**Context:** server config, virtual host, directory  

Enables tolerance for missing env vars, off by default.
By default if a mapped request env var is not present the server will return a 500 to the client.
When this is enabled the server will add the claim to the JWT with an empty string for the value.

### ProxyJwtAuthClaimMap directive
**Description:** Add a request env var ID to JWT claim ID map  
**Syntax:** ProxyJwtAuthClaimMap [env var key] [JWT claim key]  
**Context:** server config, virtual host, directory  

This directive maps request env vars to JWT claims.
If no mappings are defined the JWT will only contain default timing claims.
Mappings are additive, and cannot be unset.

### ProxyJwtAuthTokenAlgorithm directive
**Description:** Set JWT token algorithm  
**Syntax:** ProxyJwtAuthTokenAlgorithm [algorithm]  
**Context:** server config, virtual host, directory  

Sets the JWT token signature algorithm, default NONE

### ProxyJwtAuthTokenAlgorithmKeyPath
**Description:** File path to the JWT token algorithm key file  
**Syntax:** ProxyJwtAuthTokenAlgorithmKeyPath [key filesystem path]  
**Context:** server config, virtual host, directory  

Sets the path to the key file to use for signing keys.
Only valid with algorithms that require a key.

### ProxyJwtAuthTokenDuration
**Description:** Token duration in seconds  
**Syntax:** ProxyJwtAuthTokenDuration [Seconds integer]  
**Context:** server config, virtual host, directory  

Sets the token duration in seconds.
After [duration] seconds the token will expire and no longer be valid.
Default duration is 30 seconds.
Note that bad values the duration will be 0 seconds and the token will immediately expire.

### ProxyJwtAuthHeaderName
**Description:** Set the HTTP Header name used  
**Syntax:** ProxyJwtAuthTokenDuration [Header Name]  
**Context:** server config, virtual host, directory  

Sets the HTTP header name used to pass the bearer token, default `Authorization`
