#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

#include <regex>

// This template is for FastRPC
class WebLogin_AuthMethods
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

    /**
     * @brief handleLoginDynamicRequest Handle dynamic requests per app.
     * @param appName
     * @param request
     * @param response
     * @return
     */
    static Mantids30::Network::Protocols::HTTP::Status::Codes handleLoginDynamicRequest(const std::string &appName, HTTPv1_Base::Request *request, HTTPv1_Base::Response *response,
                                                                                        std::shared_ptr<void>);

private:
    enum OriginSource
    {
        USING_HEADER_ORIGIN,
        USING_HEADER_REFERER
    };

    ////////////////
    // EXPOSED FUNCTIONS:

    static void preAuthorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void authorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &clientDetails);

    static void token(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void logout(void *, APIReturn &response, const RequestParameters &, ClientDetails &);

    static void changeCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listCredentials(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void accountCredentialPublicData(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void registerAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    ////////////////


    static bool retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;


    // TOKEN HELPERS:
    static bool token_validateRedirectUri(IdentityManager *identityManager, const std::string &app, const std::string &redirectURI, const std::string &user, const std::string &ipAddress);
    static bool token_createAndSignJWTs(IdentityManager *identityManager, const JWT::Token *jwtToken, const std::string &app, const std::string &user, const std::string &redirectURI, APIReturn &response);
    static bool token_validateJwtClaims(const JWT::Token* jwtToken, const std::string& user, const std::string& ipAddress);
    static bool token_validateAuthenticationScheme(IdentityManager* identityManager, const JWT::Token* jwtToken,
                                             const std::string& app, const std::string& activity, uint32_t schemeId,
                                             const std::string& user, const std::string& ipAddress);
    static std::string token_signApplicationJWT(JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
    static bool token_validateAppAuthorization(IdentityManager* identityManager, const JWT::Token* jwtToken,
                                         const std::string& app, const std::string& user, const std::string& ipAddress);

    // TODO:
    /*    static APIReturn initiatePasswordReset(void* context, const RequestParameters& inputParameters);
    static APIReturn confirmPasswordReset(void* context, const RequestParameters& inputParameters);
*/
};
