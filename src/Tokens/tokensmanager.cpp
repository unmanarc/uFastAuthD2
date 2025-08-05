#include "tokensmanager.h"

#include "IdentityManager/identitymanager.h"
#include "globals.h"

using namespace Mantids30;
using namespace Mantids30::Network::Protocols;
using namespace API::RESTful;

void TokensManager::configureAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName,
                                         const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    std::string tokenId = Mantids30::Helpers::Random::createRandomString(16);
    accessToken.setSubject(jwtAccountName);
    accessToken.setIssuedAt(time(nullptr));
    time_t expectedExpirationTime = time(nullptr) + JSON_ASUINT64(tokenProperties.tokensConfiguration["accessToken"], "timeout", 300);
    time_t accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

    if (accountExpirationTime == 0 || accountExpirationTime >= expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        accessToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        accessToken.setExpirationTime(accountExpirationTime);
    }

    accessToken.setNotBefore(time(nullptr) - 30);
    accessToken.addClaim("sessionInactivityTimeout", tokenProperties.sessionInactivityTimeout);
    accessToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    accessToken.setJwtId(tokenId);
    accessToken.addClaim("parentTokenId", refreshTokenId);
    accessToken.addClaim("app", appName);
    //accessToken.addClaim( "tokensConfig", tokenProperties.tokensConfiguration["accessToken"] );

    // Get the user permissions if needed for this application...
    if (tokenProperties.includeApplicationPermissions)
    {
        auto x = identityManager->authController->getAccountUsableApplicationPermissions(jwtAccountName);
        for (const auto &i : x)
        {
            if (i.appName == appName)
            {
                accessToken.addPermission(i.permissionId);
            }
        }
    }
    // Get the user basic info if needed for this application...
    if (tokenProperties.includeBasicAccountInfo)
    {
        accessToken.addClaim("accountInfo", identityManager->accounts->getAccountDetails(jwtAccountName).toJSON());
    }

    if (identityManager->accounts->getAccountFlags(jwtAccountName).admin)
        accessToken.addClaim("isAdmin", true);
}

void TokensManager::configureRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, const std::string &refreshTokenId, const std::string &jwtAccountName, const std::string &appName,
                                          const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    refreshToken.setSubject(jwtAccountName);
    refreshToken.setIssuedAt(time(nullptr));
    //refreshToken.addClaim( "tokensConfig", tokenProperties.tokensConfiguration["refreshToken"] );

    auto expectedExpirationTime = time(nullptr) + JSON_ASUINT64(tokenProperties.tokensConfiguration["refreshToken"], "timeout", 2592000);
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(jwtAccountName);

    if (accountExpirationTime == 0 || accountExpirationTime >= expectedExpirationTime)
    {
        // We can safely use the expected token expiration time
        refreshToken.setExpirationTime(expectedExpirationTime);
    }
    else
    {
        // The account expires before, so the tokens need to expire before:
        refreshToken.setExpirationTime(accountExpirationTime);
    }

    refreshToken.setNotBefore(time(nullptr) - 30);
    refreshToken.addClaim("slotIds", Mantids30::Helpers::setToJSON(slotIds));
    refreshToken.setJwtId(refreshTokenId);
    refreshToken.addClaim("app", appName);
    refreshToken.addClaim("type", "refresher");
}

void TokensManager::setIAMAccessTokenCookie(APIReturn &response, const RequestParameters &request, const Mantids30::DataFormat::JWT::Token &intermediateToken,
    const Mantids30::DataFormat::JWT::Token &currentAccessToken, bool keepAuthenticated, const time_t & currentIntermediateTokenExpirationTime)
{
    IdentityManager *identityManager = Globals::getIdentityManager();
    Mantids30::DataFormat::JWT::Token accessToken;
    std::string accountName = JSON_ASSTRING_D(intermediateToken.getClaim("preAuthUser"), "");
    auto accountExpirationTime = identityManager->accounts->getAccountExpirationTime(accountName);
    time_t expectedRefresherTokenTimeoutTime = safeAdd(time(nullptr), Globals::getConfig()->get<time_t>("WebLoginService.IAMTokenTimeout", 2592000));

    if (!keepAuthenticated)
    {
        expectedRefresherTokenTimeoutTime = currentIntermediateTokenExpirationTime;
    }

    Json::Value combinedSlotIds;
    std::set<uint32_t> uniqueSlotIds = Mantids30::Helpers::jsonToUInt32Set(currentAccessToken.getClaim("slotIds"));
    std::set<uint32_t> intermediateSlotIds = Mantids30::Helpers::jsonToUInt32Set(intermediateToken.getClaim("slotIds"));

    // MIX in unique.
    for (const auto &i : intermediateSlotIds)
        uniqueSlotIds.insert(i);

    // Add all unique slot IDs to the JSON array
    combinedSlotIds = Mantids30::Helpers::setToJSON(uniqueSlotIds);

    std::set<std::string> uniqueAuthApps = Mantids30::Helpers::jsonToStringSet(currentAccessToken.getClaim("apps"));

    uniqueAuthApps.insert(intermediateToken.getClaim("app").asString());

    accessToken.setSubject(accountName);
    accessToken.setIssuedAt(time(nullptr));
    accessToken.setExpirationTime(accountExpirationTime == 0 ? expectedRefresherTokenTimeoutTime :       // Token does not expire.
                                      std::min(accountExpirationTime, expectedRefresherTokenTimeoutTime) // Token expires, take the min time between two...
    );
    accessToken.setNotBefore(time(nullptr) - 30);
    accessToken.addClaim("slotIds", combinedSlotIds);
    accessToken.addClaim("type", "IAM");
    accessToken.addClaim("app", "IAM");
    accessToken.addClaim("apps", Mantids30::Helpers::setToJSON(uniqueAuthApps));
    accessToken.addClaim("keepAuthenticated", keepAuthenticated);

    accessToken.setJwtId(Mantids30::Helpers::Random::createRandomString(16));

    std::string sAuthToken = request.jwtSigner->signFromToken(accessToken, false);

    // Keep the auth refresher token here:
    response.cookiesMap["AccessToken"] = HTTP::Headers::Cookie();
    response.cookiesMap["AccessToken"].setExpiration(accessToken.getExpirationTime());
    response.cookiesMap["AccessToken"].secure = true;
    response.cookiesMap["AccessToken"].httpOnly = true;
    response.cookiesMap["AccessToken"].value = sAuthToken;

    Json::Value authenticationPublicData;
    authenticationPublicData["exp"] = std::to_string(accessToken.getExpirationTime());
    authenticationPublicData["subject"] = accountName;
    authenticationPublicData["slotIds"] = combinedSlotIds;
    //authenticationPublicData["apps"] = accountName;

    // TODO: account data?
    if (keepAuthenticated)
    {
        response.cookiesMap["loggedIn"] = HTTP::Headers::Cookie();
        response.cookiesMap["loggedIn"].setExpiration(accessToken.getExpirationTime());
        response.cookiesMap["loggedIn"].secure = true;
        response.cookiesMap["loggedIn"].httpOnly = false;
        response.cookiesMap["loggedIn"].path = "/";
        response.cookiesMap["loggedIn"].value = Helpers::Encoders::encodeToBase64(authenticationPublicData.toStyledString());
    }
}
