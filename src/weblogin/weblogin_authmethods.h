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

    /**
     * @brief addMethods Add selected/reduced/filtered set of login authentication methods as server functions to the fastrpc connection for remote web applications
     * @param auth authentication manager (with full access to the authentication interface)
     * @param fastRPC RPC engine to expose the methods
     */
    static void addMethods(std::shared_ptr<MethodsHandler> methods);

    static Mantids30::Network::Protocols::HTTP::Status::eRetCode handleDynamicRequest(const std::string &appName, Mantids30::Network::Protocols::HTTP::HTTPv1_Base::Request *request, Mantids30::Network::Protocols::HTTP::HTTPv1_Base::Response *response);

private:
    static void preAuthorize(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void authorize(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request,  Mantids30::Sessions::ClientDetails &clientDetails);
    static void token(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void logout(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void refreshAccessToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void refreshRefresherToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void tempMFAToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void changeCredential(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void listCredentials(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void accountCredentialPublicData(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);
    static void registerAccount(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails);

    // TODO:
    /*    static APIReturn initiatePasswordReset(void* context, const RequestParameters& inputParameters);
    static APIReturn confirmPasswordReset(void* context, const RequestParameters& inputParameters);
*/

private:
    static std::set<uint32_t> getSlotIdsFromJSON(const json &input);
    static json getJSONFromSlotIds(const std::set<uint32_t> &input);
    static bool areAllSlotIdsAuthenticated(const std::set<uint32_t> &currentAuthenticatedSlotIds, const std::map<uint32_t, std::string> &getAccountAuthenticationSlotsUsedForLogin);

    static json getAccountDetails(IdentityManager *identityManager, const std::string &userId);


    static void configureAccessToken(Mantids30::DataFormat::JWT::Token &accessToken,
                                     IdentityManager *identityManager,
                                     const std::string &refreshTokenId,
                                     const std::string &jwtUserId,
                                     const std::string &appName,
                                     const ApplicationTokenProperties &tokenProperties,
                                     const std::set<uint32_t> &slotIds);

    static void configureRefresherToken(APIReturn &apiRet, const RequestParameters &inputParameters, IdentityManager *identityManager, const std::string &refreshTokenId, const std::string &userId, const std::set<uint32_t> &currentAuthenticatedSlotIds);

    static bool validateAccountForNewToken(IdentityManager *identityManager, const std::string &jwtUserId, Reason &reason, const std::string &appName, bool checkValidAppAccount);

    static std::string signAccessToken(Mantids30::DataFormat::JWT::Token &accessToken, const ApplicationTokenProperties &tokenProperties, const std::string &appName);
    
    
    static bool retrieveAndValidateAccessTokenFromInputData(const Mantids30::API::RESTful::RequestParameters & request, std::string &appName);

    enum OriginSource
    {
        USING_HEADER_ORIGIN,
        USING_HEADER_REFERER
    };

    static bool retrieveAndValidateAppOrigin(Mantids30::Network::Protocols::HTTP::HTTPv1_Base::Request *request, const std::string &appName, const OriginSource &originSource);
    static std::regex originPattern;



};
