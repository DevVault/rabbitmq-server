#!/usr/bin/env bash

SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TEST_CASES_PATH=/multi-oauth
PROFILES="devkeycloak prodkeycloak "

source $SCRIPT/../../bin/suite_template $@
runWith devkeycloak prodkeycloak
