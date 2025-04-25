#pragma once

#include <string>
#include <stdint.h>

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
    uint32_t accessTokenTimeout;
    uint32_t tempMFATokenTimeout;
    uint32_t sessionInactivityTimeout;
    std::string tokenType;
    //std::string accessTokenSigningKey;
    bool includeApplicationPermissionsInToken;
    bool includeBasicUserInfoInToken;
    bool maintainRevocationAndLogoutInfo;
};
struct ApplicationPermissionDetails
{
    ApplicationPermissionDetails() {}
    std::string permissionId;
    std::string description;
};
