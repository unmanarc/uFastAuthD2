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
    uint32_t refreshTokenTimeout;
    uint32_t tempMFATokenTimeout;
    uint32_t sessionInactivityTimeout;
    std::string tokenType;
    bool allowRefreshTokenRenovation;
    //std::string accessTokenSigningKey;
    bool includeApplicationPermissions;
    bool includeBasicAccountInfo;
    bool maintainRevocationAndLogoutInfo;
};
struct ApplicationPermissionDetails
{
    ApplicationPermissionDetails() {}
    std::string permissionId;
    std::string description;
};
