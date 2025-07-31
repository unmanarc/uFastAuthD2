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
    using JWT = Mantids30::DataFormat::JWT;

    /**
    * @brief Adds the available login authentication methods as server functions.
    * @param methods The MethodsHandler to which the authentication methods will be added.
    */
    static void addMethods(std::shared_ptr<MethodsHandler> methods);

    // Remote triggered:
    static void refreshAccessToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    //static void refreshRefresherToken(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void appLogout(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void callback(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

private:
    static bool validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static std::optional<JWT::Token> loadJWTAccessTokenFromPOST(APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void setupAccessTokenCookies(APIReturn &response, JWT::Token accessToken, const ApplicationTokenProperties &tokenProps);
    static void setupRefreshTokenCookies(APIReturn &response, JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps);
/*    static void setupAccessTokenCookies(APIReturn &response, std::string accessToken, const time_t & timeout);
    static void setupRefreshTokenCookies(APIReturn &response, std::string refreshToken, const time_t & timeout);*/

    static void setupCookie(APIReturn &response, const std::string &name, time_t expirationTime, bool secure, const std::string &path, bool httpOnly, const std::string &value);
    static void setupMaxAgeCookie(APIReturn &response, const std::string &name, time_t expirationTime);

    static json getAccountDetails(IdentityManager *identityManager, const std::string &accountName);

    static std::string signApplicationToken(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
};
