#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols::HTTP;


/**
 * @brief Refreshes an access token based on a provided refresh token (JWT).
 *
 * This function handles the logic for refreshing an access token. It validates the incoming
 * refresh token, retrieves necessary data from the database, and generates a new access token.
 *
 * **HTTP Layer Usage:**
 *
 * 1.  **Request Method:** POST
 * 2.  **Endpoint:**  `/refresh_token` (or similar, as defined by your API)
 * 3.  **Request Body:**  A JSON object containing the `accessToken` (the refresh token) and potentially other relevant data.
 *     Example:
 *     ```json
 *     {
 *       "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *     }
 *     ```
 * 4.  **Headers:** Standard HTTP headers, including `Content-Type: application/json`.
 * 5.  **Response:**
 *     *   **Success (200 OK):** A JSON object containing the new `accessToken` and its `expires_in` value (in seconds).
 *         ```json
 *         {
 *           "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *           "expiresIn": 3600
 *         }
 *         ```
 *     *   **Failure (401 Unauthorized):**  A JSON object with an error message indicating the reason for the failure (e.g., invalid token, unauthorized account).
 *
 * **Function Logic:**
 *
 * 1.  **Token Validation:**  The function first validates the incoming `accessToken` (refresh token) by decoding it and verifying its signature against the stored validation key for the associated application.
 * 2.  **Database Retrieval:**  If the token is valid, it retrieves application-specific configuration data (e.g., token type, validation key) from the database.
 * 3.  **Account Validation:** It validates the account associated with the token to ensure it's authorized to request a new token.
 * 4.  **New Token Generation:**  If all validations pass, it generates a new access token with a fresh expiration time.
 * 5.  **Response Construction:**  Finally, it constructs a JSON response containing the new access token and its expiration time.
 *
 * @param context A void pointer for potential context data (not used in this implementation).
 * @param response The API response object to populate with the result.
 * @param request The API request object containing the input data.
 * @param authClientDetails Client details for authentication and logging.
 */

void WebLogin_AuthMethods::refreshAccessToken(void *context, APIReturn &response, const Mantids30::API::RESTful::RequestParameters &request, Mantids30::Sessions::ClientDetails &authClientDetails)
{
    // INPUT DATA:
    std::string appName;
    // JWT Info.
    if (retrieveAndValidateAccessTokenFromInputData(request, appName) && retrieveAndValidateAppOrigin(request.clientRequest, appName,USING_HEADER_ORIGIN))
    {
        DataFormat::JWT::Token newAccessToken;
        IdentityManager *identityManager = Globals::getIdentityManager();
        std::string jwtUserId = request.jwtToken->getSubject();
        std::set<uint32_t> currentAuthenticatedSlotIds = getSlotIdsFromJSON(request.jwtToken->getClaim("slotIds"));

        Reason reason = REASON_INTERNAL_ERROR;
        if (!validateAccountForNewToken(identityManager, jwtUserId, reason, appName, true))
        {
            // This token is not available for retrieving app tokens...
            LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_WARN, "The account '%s' can't refresh the access token for the application '%s'.", jwtUserId.c_str(), appName.c_str());

            response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(reason), getReasonText(reason));
            return;
        }

        // DB Info:
        auto tokenProperties = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(appName);

        if (!DataFormat::JWT::isAlgorithmSupported(tokenProperties.tokenType))
        {
            // This token is not available for retrieving app tokens...
           LOG_APP->log2(__func__, jwtUserId, authClientDetails.ipAddress, Logs::LEVEL_CRITICAL, "The application '%s' is configured with an unsupported or invalid signing algorithm.", appName.c_str());

            reason = REASON_INTERNAL_ERROR;
            response.setError(Status::S_401_UNAUTHORIZED,"AUTH_ERR_" + std::to_string(reason), getReasonText(reason));
            return;
        }

        // The token is valid here...
        // TODO: invalidar todos los tokens viejos que su parent sea este refresher...

        configureAccessToken(newAccessToken, identityManager, request.jwtToken->getJwtId(), jwtUserId, appName, tokenProperties, currentAuthenticatedSlotIds);

        (*response.outputPayload())["accessToken"] = signAccessToken(newAccessToken, tokenProperties, appName);
        (*response.outputPayload())["expiresIn"] = (Json::UInt64) (newAccessToken.getExpirationTime() - time(nullptr));


        return;
    }

    response.setError( Status::S_401_UNAUTHORIZED,"unauthorized", "Invalid Access Token");
    return;
}

bool WebLogin_AuthMethods::retrieveAndValidateAccessTokenFromInputData(const Mantids30::API::RESTful::RequestParameters & request, std::string &appName)
{
    appName = "";
    std::string accessTokenString = JSON_ASSTRING(*request.inputJSON, "accessToken", "");
    DataFormat::JWT::Token accessToken;

    // Decode the payload without validating the token itself...
    if (DataFormat::JWT::decodeNoVerify(accessTokenString, &accessToken))
    {
        // Get the claimed APP without validating the token
        std::string tAppName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");

        // Obtain data from the DB:
        auto tokenProperties = Globals::getIdentityManager()->applications->getWebLoginJWTConfigFromApplication(tAppName);
        std::string validationKey = Globals::getIdentityManager()->applications->getWebLoginJWTValidationKeyForApplication(tAppName);

        // Validate the JWT....
        auto algorithmDetails = DataFormat::JWT::AlgorithmDetails(tokenProperties.tokenType.c_str());
        DataFormat::JWT jwtValidator(algorithmDetails.algorithm);
        if (algorithmDetails.isUsingHMAC)
            jwtValidator.setSharedSecret(validationKey);
        else
            jwtValidator.setPublicSecret(validationKey);

        if (jwtValidator.verify(accessTokenString, &accessToken))
        {
            appName = JSON_ASSTRING_D(accessToken.getClaim("app"), "");
            return true;
        }
    }
    return false;
}
