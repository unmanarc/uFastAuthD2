#include "weblogin_authmethods.h"

#include "../globals.h"

using namespace Mantids30;
using namespace Program;
using namespace API::RESTful;
using namespace Network::Protocols;

/*
 * TODO:
 *
    mmmm , the registration should be at the application or at the IAM? in this case, seems to be at the IAM, and then, the app should be linked to the account.
    and...    captchas or something? how do we do?

    When self-registering, you must come with the sponsored app right? and immediatly link the app with the user I think...
    anything else?

*/

void WebLogin_AuthMethods::registerAccount(void *context, APIReturn &response, const RequestParameters &request, ClientDetails &clientDetails)
{
    IdentityManager *identityManager = Globals::getIdentityManager();

    auto config = Globals::getConfig();
    bool bAllowSelfRegistration = config->get<bool>("WebLoginService.Registration.AllowSelfRegistration", false);
    bool bAutoConfirmAccount = config->get<bool>("WebLoginService.Registration.AutoConfirm", false);

    AccountFlags accountFlags;
    accountFlags.confirmed = bAutoConfirmAccount;
    accountFlags.enabled = false;
    accountFlags.admin = false;
    accountFlags.blocked = false;

    // TODO: what application? by now is a non-application enabled account
    // maybe "a button to request access to the application?"

    bool success = false;
    bool create = false;

    if (bAllowSelfRegistration)
    {
        create = true;
    }
    else
    {
        // TODO: in the future, the app admin can create users for the app?
        // Only admins can create.
        if (request.jwtToken->isAdmin())
        {
            create = true;
        }
        else
        {
            response.setError(HTTP::Status::S_401_UNAUTHORIZED, "unauthorized", "Insufficient permissions");
            return;
        }
    }

    std::string accountToCreate = JSON_ASSTRING((*request.inputJSON)["accountDetails"], "accountName", "");

    if (create)
    {
        success = identityManager->accounts->addAccount(accountToCreate, JSON_ASUINT64(*request.inputJSON, "expiration", 0), accountFlags, request.jwtToken->getSubject());
    }

    if (!success)
    {
        response.setError(HTTP::Status::S_500_INTERNAL_SERVER_ERROR, "internal_error", "Failed to create the account");
    }

    LOG_APP->log2(__func__, request.jwtToken->getSubject(), clientDetails.ipAddress, success ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                  !success ? "Failed to create account '%s'" : "Account '%s' created.", accountToCreate.c_str());

    // Set the credential:
    std::string newPass = JSON_ASSTRING(*request.inputJSON, "newPass", "");

    // TODO: mejorar el nivel de log...

    if (!newPass.empty() && success)
    {
        bool r = false;
        uint32_t applicationRoleDefaultSSOLogin = identityManager->authController->getApplicationActivityDefaultScheme("IAM", "LOGIN");

        // Not any scheme to the default
        if (applicationRoleDefaultSSOLogin != UINT32_MAX)
        {
            auto authSlots = identityManager->authController->listAuthenticationSlotsUsedByScheme(applicationRoleDefaultSSOLogin);
            if (!authSlots.empty())
            {
                // not a password...
                if (authSlots.begin()->details.isTextPasswordFunction())
                {
                    auto credentialData = identityManager->authController->createNewCredential(authSlots.begin()->slotId, newPass, true);
                    r = identityManager->authController->changeCredential(accountToCreate, credentialData, authSlots.begin()->slotId);
                }
            }
        }

        LOG_APP->log2(__func__, request.jwtToken->getSubject(), clientDetails.ipAddress, r ? Logs::LEVEL_SECURITY_ALERT : Logs::LEVEL_INFO,
                      !r ? "Failed to change initial password on account '%s'" : "Initial password for account '%s' changed.", accountToCreate.c_str());
    }
}

// TODO: llenar los details del user.

/*AccountCreationDetails getAccountDetails;
        getAccountDetails.description = JSON_ASSTRING((*request.inputJSON)["getAccountDetails"], "description", "");
        getAccountDetails.email = JSON_ASSTRING((*request.inputJSON)["getAccountDetails"], "email", "");
        getAccountDetails.extraData = JSON_ASSTRING((*request.inputJSON)["getAccountDetails"], "extraData", "");
        getAccountDetails.givenName = JSON_ASSTRING((*request.inputJSON)["getAccountDetails"], "givenName", "");
        getAccountDetails.lastName = JSON_ASSTRING((*request.inputJSON)["getAccountDetails"], "lastName", "");*/
