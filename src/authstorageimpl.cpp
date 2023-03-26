#include "authstorageimpl.h"
#include "globals.h"
#include "config.h"

#include <sys/stat.h>

#include <Mantids29/Program_Logs/applog.h>

#include <boost/algorithm/string/case_conv.hpp>

#include <Mantids29/DB_SQLite3/sqlconnector_sqlite3.h>
#include <Mantids29/Helpers/random.h>
#include <Mantids29/Helpers/crypto.h>

#include "defs.h"

#ifdef WIN32
#include <windows.h>
#endif

using namespace AUTHSERVER::AUTH;
using namespace AUTHSERVER;

using namespace Mantids29::Database;
using namespace Mantids29::Program;
using namespace Mantids29;

AuthStorageImpl::AuthStorageImpl()
{

}

bool AuthStorageImpl::createAuth()
{
    std::string sDriverName = Globals::getConfig_main()->get<std::string>("Auth.Driver","");

    Authentication::Manager_DB * authManager = nullptr;

    if (boost::to_lower_copy(sDriverName) == "sqlite3")
    {
        std::string dbFilePath = Globals::getConfig_main()->get<std::string>("Auth.File","");
        SQLConnector_SQLite3 * sqlConnector = new SQLConnector_SQLite3;
        if (!sqlConnector->connect(dbFilePath))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error, Failed to open/create SQLite3 file: '%s'", dbFilePath.c_str());
            return false;
        }

        authManager = new Authentication::Manager_DB(sqlConnector);
    }
    /*    else if (boost::to_lower_copy(driver) == "postgresql")
    {
        // TODO:
        return false;
    }
    else if (boost::to_lower_copy(driver) == "mariadb")
    {
        // TODO:
        return false;
    }*/
    else
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error, Authentication driver '%s' not implemented", sDriverName.c_str());
    }

    if (!authManager)
        return false;

    if (!authManager->initScheme())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error (Driver: %s), Unknown error during database scheme initialization.", sDriverName.c_str());
        return false;
    }


    // Check for admin accounts:
    if ( authManager->accountExist("admin") && !authManager->isAccountSuperUser("admin") )
    {
        // This account should be marked as superuser.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Admin account exist but is not super user, change this by hand.");
    }
    else if ( authManager->accountExist("admin") && authManager->isAccountExpired("admin") )
    {
        // This account should not expire.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Admin account exist but is expired, change this by hand.");
    }
    else if ( authManager->accountExist("admin") && authManager->isAccountDisabled("admin") )
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Admin account exist but is disabled, change this by hand.");
    }
    else if ( authManager->accountExist("admin") && !authManager->isAccountConfirmed("admin") )
    {
        // This account should not be disabled.
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Admin account exist but is not confirmed, change this by hand.");
    }
    else if (!authManager->accountExist("admin"))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Super User Account does not exist. Creating 'admin' account.");

        std::string sInitPW;

        if (!createAdmin(authManager,&sInitPW))
            return false;

        if (!createPassFile(sInitPW))
            return false;
    }


    if (Globals::getResetAdminPasswd())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Password marked to be reseted...");

        std::string sInitPW;

        if (!resetAdminPwd(authManager,&sInitPW))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_ERR, "Password not resetted (Maybe the admin account is not admin)...");
            return false;
        }
        if (!createPassFile(sInitPW))
            return false;
    }

    if (!createApp(authManager))
        return false;

    Globals::setAuthManager(authManager);

    return true;
}

bool AuthStorageImpl::createPassFile(const std::string & sInitPW)
{

#ifndef WIN32
    std::string initPassOutFile = "/tmp/syspwd-" +Mantids29::Helpers::Random::createRandomString(8) ;
#else
    char tempPath[MAX_PATH+1];
    GetTempPathA(MAX_PATH,tempPath);
    std::string initPassOutFile = tempPath + "\\syspwd-" +Mantids29::Helpers::Random::createRandomString(8) + ".txt";
#endif
    std::ofstream ofstr(initPassOutFile);
    if (ofstr.fail())
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to save the password account.");
        return false;
    }
#ifndef WIN32
    if (chmod(initPassOutFile.c_str(),0600)!=0)
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Failed to chmod the password file (be careful with this file and content).");
    }
#else
    LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Initial password was saved without special owner read-only privileges (be careful).");
#endif
    ofstr << sInitPW;
    ofstr.close();
    LOG_APP->log0(__func__,Logs::LEVEL_INFO, "File '%s' created with the super-user password. Login and change it immediatly", initPassOutFile.c_str());
    return true;
}

bool AuthStorageImpl::createAdmin(Authentication::Manager_DB *authManager,std::string *sInitPW)
{
    *sInitPW = Mantids29::Helpers::Random::createRandomString(16);

    Authentication::Secret secretData;
    secretData.hash = Helpers::Crypto::calcSHA256(*sInitPW);
    secretData.passwordFunction = Authentication::FN_SHA256;
    secretData.forceExpiration = true; // Expired (to be changed on the first login).

    Mantids29::Authentication::AccountDetailsWExtraData accountDetails;
    accountDetails.description = "Auto-generated Superuser Account";
    accountDetails.email = "";
    accountDetails.extraData = "";
    accountDetails.givenName = "";
    accountDetails.lastName = "";

    Mantids29::Authentication::AccountBasicAttributes accountAttribs;
    accountAttribs.confirmed = true;
    accountAttribs.enabled = true;
    accountAttribs.superuser = true;

    if (!authManager->accountAdd(   "admin",
                                    secretData,
                                    accountDetails,
                                    0, // Expiration (don't expire)
                                    accountAttribs))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to create admin account.");
        return false;
    }

    return true;
}

bool AuthStorageImpl::resetAdminPwd(Mantids29::Authentication::Manager_DB *authManager, std::string *sInitPW)
{
    *sInitPW = Mantids29::Helpers::Random::createRandomString(16);

    Authentication::Secret secretData;
    secretData.hash = Helpers::Crypto::calcSHA256(*sInitPW);
    secretData.passwordFunction = Authentication::FN_SHA256;
    secretData.forceExpiration = true; // Expired (to be changed on the first login).

    return authManager->accountChangeSecret("admin", secretData);
}

bool AuthStorageImpl::createApp(Authentication::Manager_DB *authManager)
{
    if (!authManager->applicationExist(DB_APPNAME))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Application '%s' does not exist, creating it.", DB_APPNAME);

        if (!authManager->applicationAdd(DB_APPNAME,PROJECT_DESCRIPTION, Mantids29::Helpers::Random::createRandomString(32) ,"admin"))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to create the application '%s'.",DB_APPNAME);
            return false;
        }
    }

    std::list<std::pair<Mantids29::Authentication::ApplicationAttribute,std::string>> appAttributes =
    {
        {{DB_APPNAME,"DIRREAD"},"Directory Read Attribute"},
        {{DB_APPNAME,"DIRWRITE"},"Directory Write Attribute"},
    };

    for ( auto & attrib : appAttributes )
    {
        if (!authManager->attribExist(attrib.first))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Attribute '%s' does not exist, creating it.", attrib.first.attribName.c_str());

            if (!authManager->attribAdd(attrib.first,attrib.second))
            {
                LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to create the attrib '%s'.", attrib.first.attribName.c_str());
                return false;
            }
        }
    }

    if (!authManager->applicationValidateAccount(DB_APPNAME,"admin"))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Setting up 'admin' user as application '%s' user.", DB_APPNAME);

        if (!authManager->applicationAccountAdd(DB_APPNAME,"admin"))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to set the 'admin' account as application '%s' user.", DB_APPNAME);
            return false;
        }
    }

    if (!authManager->applicationValidateOwner(DB_APPNAME,"admin"))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_WARN, "Setting up 'admin' user as application '%s' owner.", DB_APPNAME);

        if (!authManager->applicationOwnerAdd(DB_APPNAME,"admin"))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Failed to set the 'admin' account as application '%s' owner.", DB_APPNAME);
            return false;
        }
    }

    return true;
}
