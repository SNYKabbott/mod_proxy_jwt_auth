#!/bin/bash
# Test: Run the test suite
# NOTE: This does not clean up Docker images
# WARNING: Must be run from the repo dir

docker-compose -f docker-compose.test.yml build || exit 1
docker-compose -f docker-compose.test.yml run test_suite bundle exec rspec -fd
rv=$?
# Always run the down & rm steps to clean up
docker-compose -f docker-compose.test.yml down
docker-compose -f docker-compose.test.yml rm -fv
exit $rv
