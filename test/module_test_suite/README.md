mod_proxy_jwt_auth Functional Test Suite
========================================

This container runs functional tests against mod_proxy_jwt_auth.  It:

- Contains a binary which writes out a test httpd config and test keys
- Contains a rspec test suite which runs functional tests against mod_proxy_jwt_auth

The rspec suite is intended to be run against a Apache2 instance running the generated httpd config which is proxying an app which returns request data as JSON.
See docker-compose.test.yml in the repo root for container linking details.
