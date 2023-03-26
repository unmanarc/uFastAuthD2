#include <Mantids29/Program_Service/application.h>
#include <Mantids29/Net_Sockets/socket_tls.h>
#include <Mantids29/Program_Logs/loglevels.h>
#include <Mantids29/Memory/a_bool.h>
#include <Mantids29/Helpers/file.h>


#include "loginrpcserverimpl.h"
#include "webserverimpl.h"
#include "authstorageimpl.h"

#include "globals.h"
#include "config.h"

#include <sys/types.h>

#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>


using namespace AUTHSERVER;

using namespace Mantids29::Program;

class Main : public Application
{
public:

    void _shutdown()
    {
    }

    int _start(int , char *[], Arguments::GlobalArguments *globalArguments)
    {
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        // start program.
        LOG_APP->log(__func__, "","", Logs::LEVEL_INFO, 2048, "Starting... (Build date %s %s), PID: %" PRIi32,__DATE__, __TIME__, getpid());
        LOG_APP->log0(__func__,Logs::LEVEL_INFO, "Using config dir: %s", configDir.c_str());

        // TODO: for MySQL Authenticator, how reconnect takes place?
        // Initiate the authenticator
        if (!AUTHSERVER::AUTH::AuthStorageImpl::createAuth())
        {
            _exit(-3);
        }

        // Initiate the RPC Listener
        if (!AUTHSERVER::RPC::LoginRPCServerImpl::createRPCListenerCAB())
        {
            _exit(-2);
        }

        // Initiate the RPC Listener
        if (!AUTHSERVER::RPC::LoginRPCServerImpl::createRPCListenerPAB())
        {
            _exit(-4);
        }

        // Initiate the web server
        /*if (!AUTHSERVER::WEB::WebServerImpl::createWebServer())
        {
            _exit(-1);
        }*/

        // Initiate the web services
        if (!AUTHSERVER::WEB::WebServerImpl::createWebService())
        {
            _exit(-1);
        }

        LOG_APP->log0(__func__,Logs::LEVEL_INFO,  (globalArguments->getDaemonName() + " initialized with PID: %d").c_str(), getpid());

        return 0;
    }

    void _initvars(int , char *[], Arguments::GlobalArguments * globalArguments)
    {
        // init variables (pre-config):
        globalArguments->setInifiniteWaitAtEnd(true);

        globalArguments->m_softwareLicense = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.en.html)";
        globalArguments->m_softwareDescription = PROJECT_DESCRIPTION;
        globalArguments->addAuthor({"Aarón Mizrachi","aaron@unmanarc.com"});
        globalArguments->setVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        globalArguments->addCommandLineOption("Service Options", 'c', "config-dir" , "Configuration directory"  , "/etc/ufastauthd2", Mantids29::Memory::Abstract::Var::TYPE_STRING );
        globalArguments->addCommandLineOption("Recovery Options", 'r', "resetadmpw" , "Reset Administrator Password"  , "false", Mantids29::Memory::Abstract::Var::TYPE_BOOL );
    }

    bool _config(int , char *argv[], Arguments::GlobalArguments * globalArguments)
    {
        // process config:
        unsigned int logMode = Logs::MODE_STANDARD;

        Mantids29::Network::Sockets::Socket_TLS::prepareTLS();

        Logs::AppLog initLog(Logs::MODE_STANDARD);
        initLog.m_printAttributeName = false;
        initLog.m_printDate = true;
        initLog.m_printAttributeName = false;
        initLog.m_printEmptyFields = true;
        initLog.m_useColors = true;
        initLog.m_logFieldSeparator = ",";
        initLog.m_minModuleFieldWidth = 26;

        Globals::setResetAdminPasswd(
                    ((Mantids29::Memory::Abstract::BOOL *)globalArguments->getCommandLineOptionValue("resetadmpw"))->getValue()
                );

        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        initLog.log0(__func__,Logs::LEVEL_INFO, "Loading configuration: %s", (configDir + "/config.ini").c_str());

        boost::property_tree::ptree config_main;

        if (access(configDir.c_str(),R_OK))
        {
            initLog.log0(__func__,Logs::LEVEL_CRITICAL, "Missing configuration dir: %s", configDir.c_str());
            return false;
        }

        chdir(configDir.c_str());

        bool isConfigFileInsecure;
        if ( !Mantids29::Helpers::File::isSensitiveConfigPermissionInsecure("config.ini", &isConfigFileInsecure) )
        {
            initLog.log0(__func__,Logs::LEVEL_WARN, "The configuration file 'config.ini' is inaccessible, loading defaults...");
        }
        else
        {
            if ( isConfigFileInsecure )
            {
                initLog.log0(__func__,Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'config.ini' file are currently not set to 0600. This may leave your API key exposed to potential security threats. To mitigate this risk, we are changing the permissions of the file to ensure that your API key remains secure. Please ensure that you take necessary precautions to protect your API key and update any affected applications or services as necessary.");

                if ( Mantids29::Helpers::File::fixSensitiveConfigPermission("config.ini"))
                {
                    initLog.log0(__func__,Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'config.ini' has been changed to 0600.");
                }
                else
                {
                    initLog.log0(__func__,Logs::LEVEL_CRITICAL, "The permissions of the 'config.ini' file can't be changed.");
                    return false;
                }
            }

            boost::property_tree::ini_parser::read_ini("config.ini",config_main);
        }

        *(Globals::getConfig_main()) = config_main;

        if ( config_main.get<bool>("Logs.ToSyslog",true) ) logMode|=Logs::MODE_SYSLOG;

        Globals::setAppLog(new Logs::AppLog(logMode));
        LOG_APP->setDebug(Globals::getConfig_main()->get<bool>("Logs.Debug",false));
        LOG_APP->m_printDate = config_main.get<bool>("Logs.ShowDate",true);
        LOG_APP->m_useColors = config_main.get<bool>("Logs.ShowColors",true);
        LOG_APP->m_printAttributeName = false;
        LOG_APP->m_printEmptyFields = true;
        LOG_APP->m_logFieldSeparator = ",";
        LOG_APP->m_minModuleFieldWidth = 26;
        LOG_APP->m_printAttributeName = false;


        Globals::setRPCLog(new Logs::RPCLog(logMode));
        LOG_RPC->setDebug(Globals::getConfig_main()->get<bool>("Logs.Debug",false));
        LOG_RPC->m_useColors=config_main.get<bool>("Logs.ShowColors",true);
        LOG_RPC->m_printDate=config_main.get<bool>("Logs.ShowDate",true);
        LOG_RPC->m_printEmptyFields=true;
        LOG_RPC->m_disableDomain=true;
        LOG_RPC->m_disableModule=true;
        LOG_RPC->m_minModuleFieldWidth=26;
        LOG_RPC->m_printAttributeName=false;
        LOG_RPC->m_logFieldSeparator=",";

        return true;
    }
};

int main(int argc, char *argv[])
{
    Main * main = new Main;
    return StartApplication(argc,argv,main);
}

