#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

#include <optional>

// This template is for FastRPC
class WebSessionAuthHandler_AuthMethods
{
public:
    using MethodsHandler = Mantids30::API::RESTful::MethodsHandler;
    using APIReturn = Mantids30::API::APIReturn;
    using RequestParameters = Mantids30::API::RESTful::RequestParameters;
    using HTTPv1_Base = Mantids30::Network::Protocols::HTTP::HTTPv1_Base;
    using ClientDetails = Mantids30::Sessions::ClientDetails;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The MethodsHandler to which the authentication methods will be added.
    */
    static void addMethods(std::shared_ptr<MethodsHandler> methods);

    // Remote triggered:
    static void refreshAccessToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void refreshRefresherToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void appLogout(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

private:
    static bool validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static std::optional<Mantids30::DataFormat::JWT::Token> loadJWTAccessTokenFromPOST(APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void setupAccessTokenCookies(APIReturn &response, Mantids30::DataFormat::JWT::Token accessToken, const ApplicationTokenProperties &tokenProps);
    static void setupRefreshTokenCookies(APIReturn &response, Mantids30::DataFormat::JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps);

    static json getAccountDetails(IdentityManager *identityManager, const std::string &accountName);

    static void configureAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &jwtAccountName,
                                     const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds);

    static void configureRefreshToken(Mantids30::DataFormat::JWT::Token &refreshToken, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &jwtAccountName,
                                      const std::string &appName, const ApplicationTokenProperties &tokenProperties, const std::set<uint32_t> &slotIds);

    static std::string signApplicationToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
};
