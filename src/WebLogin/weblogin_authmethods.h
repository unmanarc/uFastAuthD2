#pragma once

#include "IdentityManager/identitymanager.h"
#include <Mantids30/API_RESTful/methodshandler.h>
#include <Mantids30/Helpers/json.h>
#include <Mantids30/Protocol_HTTP/httpv1_base.h>

#include <optional>
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
    static bool validateAPIKey(const std::string &app, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static std::optional<Mantids30::DataFormat::JWT::Token> loadJWTAccessTokenFromPOST(APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void token(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void preAuthorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void authorize(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &clientDetails);
    static void logout(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void changeCredential(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void listCredentials(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void accountCredentialPublicData(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);
    static void registerAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &authClientDetails);

    static void setupAccessTokenCookies(APIReturn &response, Mantids30::DataFormat::JWT::Token accessToken, const ApplicationTokenProperties &tokenProps);
    static void setupRefreshTokenCookies(APIReturn &response, Mantids30::DataFormat::JWT::Token refreshToken, const ApplicationTokenProperties &tokenProps);

    static std::set<uint32_t> getSlotIdsFromJSON(const json &input);
    static json getJSONFromSlotIds(const std::set<uint32_t> &input);
    static bool areAllSlotIdsAuthenticated(const std::set<uint32_t> &currentAuthenticatedSlotIds, const std::map<uint32_t, std::string> &getAccountAuthenticationSlotsUsedForLogin);

    static bool validateAccountForNewToken(IdentityManager *identityManager, const std::string &jwtAccountName, Reason &reason, const std::string &appName, bool checkValidAppAccount);

    static std::string signApplicationToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties);
    //static std::optional<std::string> retrieveAndValidateAccessTokenFromInputData(RequestParameters &request);

    enum OriginSource
    {
        USING_HEADER_ORIGIN,
        USING_HEADER_REFERER
    };

    static bool retrieveAndValidateAppOrigin(HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;

    static Mantids30::Network::Protocols::HTTP::Status::Codes retokenizeUsingJS(HTTPv1_Base::Response *response, const std::string &url);

    // TODO:
    /*    static APIReturn initiatePasswordReset(void* context, const RequestParameters& inputParameters);
    static APIReturn confirmPasswordReset(void* context, const RequestParameters& inputParameters);
*/
};
