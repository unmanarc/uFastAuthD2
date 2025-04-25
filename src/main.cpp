#include <Mantids30/Program_Service/application.h>
#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Program_Logs/loglevels.h>
#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Helpers/file.h>

#include "webadmin/webadmin_serverimpl.h"
#include "weblogin/weblogin_serverimpl.h"

#include "authstorageimpl.h"

#include "globals.h"
#include "config.h"

#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>

using namespace Mantids30::Program;

class Main : public Application
{
public:

    void _shutdown()
    {
        // TODO:
        // - imagen de login (como el usuario peude validar que esta en el sitio correcto)
        // - tarjeta de coordenadas?
        // - mensaje enviado y en espera
        // - token refresher
        // - 2fa temporal para operaciones especiales.
        // - paginas como archivos?
    }

    int _start(int , char *[], Arguments::GlobalArguments *globalArguments)
    {
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        // start program.
        LOG_APP->log(__func__, "","", Logs::LEVEL_INFO, 2048, "Starting... (Build date %s %s), PID: %" PRIi32,__DATE__, __TIME__, getpid());
        LOG_APP->log0(__func__,Logs::LEVEL_INFO, "Using config dir: %s", configDir.c_str());

        // TODO: for MySQL/PostgreSQL Authenticator, how reconnect takes place?
        // Initiate the authenticator
        if (!AuthStorageImpl::createAuth())
        {
            _exit(-3);
        }

        // Dir Web Admin:
        if (!WebAdmin_ServerImpl::createService())
        {
            _exit(-5);
        }

        // Web Login:
        if (!WebLogin_ServerImpl::createService())
        {
            _exit(-6);
        }

        LOG_APP->log0(__func__,Logs::LEVEL_INFO,  (globalArguments->getDaemonName() + " initialized with PID: %d").c_str(), getpid());

        return 0;
    }

    void _initvars(int , char *[], Arguments::GlobalArguments * globalArguments)
    {
        // init variables (pre-config):
        globalArguments->setInifiniteWaitAtEnd(true);

        globalArguments->softwareLicense = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.en.html)";
        globalArguments->softwareDescription = PROJECT_DESCRIPTION;
        globalArguments->addAuthor({"Aarón Mizrachi","aaron@unmanarc.com"});
        globalArguments->setVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        globalArguments->addCommandLineOption("Service Options", 'c', "config-dir" , "Configuration directory"  , "/etc/ufastauthd2", Mantids30::Memory::Abstract::Var::TYPE_STRING );
        globalArguments->addCommandLineOption("Recovery Options", 'r', "resetadmpw" , "Reset Administrator Password"  , "false", Mantids30::Memory::Abstract::Var::TYPE_BOOL );
    }

    bool _config(int , char *argv[], Arguments::GlobalArguments * globalArguments)
    {
        // process config:
        unsigned int logMode = Logs::MODE_STANDARD;

        Mantids30::Network::Sockets::Socket_TLS::prepareTLS();

        Logs::AppLog initLog(Logs::MODE_STANDARD);
        initLog.enableAttributeNameLogging = false;
        initLog.enableDateLogging = true;
        initLog.enableAttributeNameLogging = false;
        initLog.enableEmptyFieldLogging = true;
        initLog.enableColorLogging = true;
        initLog.fieldSeparator = ",";
        initLog.moduleFieldMinWidth = 26;

        Globals::setResetAdminPasswd(globalArguments->getCommandLineOptionBooleanValue("resetadmpw"));

        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        initLog.log0(__func__,Logs::LEVEL_INFO, "Loading configuration: %s", (configDir + "/config.ini").c_str());

        boost::property_tree::ptree pConfig;

        if (access(configDir.c_str(),R_OK))
        {
            initLog.log0(__func__,Logs::LEVEL_CRITICAL, "Missing configuration dir: %s", configDir.c_str());
            return false;
        }

        chdir(configDir.c_str());

        bool isConfigFileInsecure;
        if ( !Mantids30::Helpers::File::isSensitiveConfigPermissionInsecure("config.ini", &isConfigFileInsecure) )
        {
            initLog.log0(__func__,Logs::LEVEL_WARN, "The configuration file 'config.ini' is inaccessible, loading defaults...");
        }
        else
        {
            if ( isConfigFileInsecure )
            {
                initLog.log0(__func__,Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'config.ini' file are currently not set to 0600. This may leave your API key exposed to potential security threats. To mitigate this risk, we are changing the permissions of the file to ensure that your API key remains secure. Please ensure that you take necessary precautions to protect your API key and update any affected applications or services as necessary.");

                if ( Mantids30::Helpers::File::fixSensitiveConfigPermission("config.ini"))
                {
                    initLog.log0(__func__,Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'config.ini' has been changed to 0600.");
                }
                else
                {
                    initLog.log0(__func__,Logs::LEVEL_CRITICAL, "The permissions of the 'config.ini' file can't be changed.");
                    return false;
                }
            }

            boost::property_tree::ini_parser::read_ini("config.ini",pConfig);
        }

        *(Globals::getConfig()) = pConfig;

        if ( pConfig.get<bool>("Logs.ToSyslog",true) ) logMode|=Logs::MODE_SYSLOG;

        Globals::setAppLog(new Logs::AppLog(logMode));
        LOG_APP->setDebug(Globals::getConfig()->get<bool>("Logs.Debug",false));
        LOG_APP->enableDateLogging = pConfig.get<bool>("Logs.ShowDate",true);
        LOG_APP->enableColorLogging = pConfig.get<bool>("Logs.ShowColors",true);
        LOG_APP->enableAttributeNameLogging = false;
        LOG_APP->enableEmptyFieldLogging = true;
        LOG_APP->fieldSeparator = ",";
        LOG_APP->moduleFieldMinWidth = 26;
        LOG_APP->enableAttributeNameLogging = false;

        Globals::setRPCLog(new Logs::RPCLog(logMode));
        LOG_RPC->setDebug(Globals::getConfig()->get<bool>("Logs.Debug",false));
        LOG_RPC->enableColorLogging=pConfig.get<bool>("Logs.ShowColors",true);
        LOG_RPC->enableDateLogging=pConfig.get<bool>("Logs.ShowDate",true);
        LOG_RPC->enableEmptyFieldLogging=true;
        LOG_RPC->enableDomainLogging=false;
        LOG_RPC->enableModuleLogging=false;
        LOG_RPC->moduleFieldMinWidth=26;
        LOG_RPC->enableAttributeNameLogging=false;
        LOG_RPC->fieldSeparator=",";

        return true;
    }
};

int main(int argc, char *argv[])
{
    Main * main = new Main;
    return StartApplication(argc,argv,main);
}

