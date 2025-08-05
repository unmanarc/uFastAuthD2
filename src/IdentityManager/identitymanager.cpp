#include "identitymanager.h"
#include "IdentityManager/ds_application.h"
#include <memory>

using namespace Mantids30;
using namespace Mantids30::DataFormat;

IdentityManager::IdentityManager() {}

IdentityManager::~IdentityManager()
{
    if (accounts)
        delete accounts;
    if (roles)
        delete roles;
    if (applications)
        delete applications;
    if (authController)
        delete authController;
}

bool IdentityManager::validateAccountForNewAccess(const std::string &accountName, const std::string &appName, Reason &reason, bool checkValidAppAccount)
{
    // First, check if the account is disabled, unconfirmed, or expired.

    AccountFlags accountFlags = accounts->getAccountFlags(accountName);

    if (!accountFlags.enabled)
    {
        reason = Reason::REASON_DISABLED_ACCOUNT;
        return false;
    }
    else if (!accountFlags.confirmed)
    {
        reason = Reason::REASON_UNCONFIRMED_ACCOUNT;
        return false;
    }
    else if (accounts->isAccountExpired(accountName))
    {
        reason = Reason::REASON_EXPIRED_ACCOUNT;
        return false;
    }

    // If checkValidAppAccount is true, check if the account is valid for the specified application.
    if (checkValidAppAccount && !applications->validateApplicationAccount(appName, accountName))
    {
        reason = Reason::REASON_BAD_ACCOUNT;
        return false;
    }

    // If all checks pass, the account is valid for refreshing the token.
    return true;
}

bool IdentityManager::initializeAdminAccountWithPassword(const std::string &accountName, std::string *adminPW, const uint32_t &schemeId, bool *alreadyExist)
{
    bool r = true;
    if (!accounts->doesAccountExist(accountName))
    {
        r = r && accounts->createAdminAccount(accountName);
        r = r && authController->setAccountPasswordOnScheme(accountName, adminPW, schemeId);
        *alreadyExist = false;
    }
    else
    {
        *alreadyExist = true;
    }
    return r;
}

bool IdentityManager::initializeApplicationWithScheme(const std::string &appName, const std::string &appDescription, const uint32_t &schemeId, const std::string &owner, bool *alreadyExist)
{
    bool r = true;

    if (!applications->doesApplicationExist(appName))
    {
        r = r && applications->addApplication(appName, appDescription, Mantids30::Helpers::Random::createRandomString(32), owner);
        r = r && applications->setApplicationWebLoginCallbackURI(appName, "https://iamadmin.localhost:9443/auth/api/v1/callback"); // Redirection callback URI
        r = r && applications->addWebLoginRedirectURIToApplication(appName, "https://iamadmin.localhost:9443/");                   // Allowed redirects.
        r = r && applications->addWebLoginOriginURLToApplication(appName, "https://iamadmin.localhost:9443");                      // Origin (eg. retokenization)
        r = r && applications->setApplicationActivities(appName, {{"LOGIN", {.description = "Main Login", .parentActivity = ""}}});
        r = r && authController->addAuthenticationSchemesToApplicationActivity(appName, "LOGIN", schemeId);
        r = r && authController->setApplicationActivityDefaultScheme(appName, "LOGIN", schemeId);
        *alreadyExist = false;
    }
    else
    {
        *alreadyExist = true;
    }

    return r;
}

bool IdentityManager::Accounts::createAdminAccount(const std::string &accountName)
{
    AccountFlags accountFlags;
    accountFlags.confirmed = true;
    accountFlags.enabled = true;
    accountFlags.admin = true;
    accountFlags.blocked = false;

    if (!addAccount(accountName, 0, accountFlags))
    {
        return false;
    }
    return true;
}

std::shared_ptr<JWT> IdentityManager::Applications::getAppJWTValidator(const std::string &appName)
{
    // Obtain data from the DB:
    auto tokenProperties = getWebLoginJWTConfigFromApplication(appName);
    std::string validationKey = getWebLoginJWTValidationKeyForApplication(appName);

    if (tokenProperties.appName != appName)
    {
        // Failed to load token properties.
        return nullptr;
    }

    if (validationKey.empty())
    {
        // Failed to load validation Key.
        return nullptr;
    }

    // Validate the JWT Algorithm....
    if (!JWT::isAlgorithmSupported(tokenProperties.tokenType))
    {
        // Failed to validate the algorithm type.
        return nullptr;
    }

    // Setup the JWT validator:
    auto algorithmDetails = JWT::AlgorithmDetails(tokenProperties.tokenType.c_str());
    std::shared_ptr<JWT> jwtValidator = std::make_shared<JWT>(algorithmDetails.algorithm);

    if (algorithmDetails.isUsingHMAC)
    {
        jwtValidator->setSharedSecret(validationKey);
    }
    else
    {
        jwtValidator->setPublicSecret(validationKey);
    }

    return jwtValidator;
}

std::shared_ptr<JWT> IdentityManager::Applications::getAppJWTSigner(const std::string &appName)
{
    // Obtain data from the DB:
    ApplicationTokenProperties tokenProperties = getWebLoginJWTConfigFromApplication(appName);
    std::string validationKey = getWebLoginJWTValidationKeyForApplication(appName);
    std::string signingKey = getWebLoginJWTSigningKeyForApplication(appName);

    if (tokenProperties.appName == appName && !validationKey.empty() && !signingKey.empty())
    {
        // Validate the JWT....
        JWT::AlgorithmDetails algorithmDetails = JWT::AlgorithmDetails(tokenProperties.tokenType.c_str());
        std::shared_ptr<JWT> jwtSigner = std::make_shared<JWT>(algorithmDetails.algorithm);

        if (algorithmDetails.isUsingHMAC)
        {
            jwtSigner->setSharedSecret(signingKey);
        }
        else
        {
            jwtSigner->setPrivateSecret(signingKey);
            jwtSigner->setPublicSecret(validationKey);
        }

        return jwtSigner;
    }

    return nullptr;
}
