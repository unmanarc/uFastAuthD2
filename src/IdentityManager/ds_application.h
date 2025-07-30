#pragma once

#include "json/value.h"
#include <stdint.h>
#include <string>

struct ApplicationDetails
{
    ApplicationDetails() {}
    std::string applicationName;
    std::string appCreator;
    std::string description;
};
struct ApplicationTokenProperties
{
    std::string appName;
    uint32_t tempMFATokenTimeout;
    uint32_t sessionInactivityTimeout;
    std::string tokenType;
    bool allowRefreshTokenRenovation;
    bool includeApplicationPermissions;
    bool includeBasicAccountInfo;
    bool maintainRevocationAndLogoutInfo;
    Json::Value tokensConfiguration;
};
struct ApplicationPermissionDetails
{
    ApplicationPermissionDetails() {}
    std::string permissionId;
    std::string description;
};
