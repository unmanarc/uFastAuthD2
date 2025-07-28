#include <Mantids30/Config_Builder/program_logs.h>
#include <Mantids30/Helpers/file.h>
#include <Mantids30/Memory/a_bool.h>
#include <Mantids30/Net_Sockets/socket_tls.h>
#include <Mantids30/Program_Service/application.h>

#include "WebAdmin/webadmin_serverimpl.h"
#include "WebLogin/weblogin_serverimpl.h"
#include "WebSessionAuthHandler/websessionauthhandler_serverimpl.h"

#include "RPC1LoginServer2/fastrpcimpl.h"
#include "RPC1LoginServer2/rpc1loginserver2impl.h"

#include "authstorageimpl.h"

#include "config.h"
#include "globals.h"

#include <sys/types.h>

#include <dirent.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/property_tree/info_parser.hpp>

using namespace Mantids30;

class Main : public Program::Application
{
public:
    void _initvars(int, char *[], Program::Arguments::GlobalArguments *globalArguments)
    {
        // init variables (pre-config):
        globalArguments->setInifiniteWaitAtEnd(true);

        globalArguments->softwareLicense = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.en.html)";
        globalArguments->softwareDescription = PROJECT_DESCRIPTION;
        globalArguments->addAuthor({"Aarón Mizrachi", "aaron@unmanarc.com"});
        globalArguments->setVersion(atoi(PROJECT_VER_MAJOR), atoi(PROJECT_VER_MINOR), atoi(PROJECT_VER_PATCH), "a");

        globalArguments->addCommandLineOption("Service Options", 'c', "config-dir", "Configuration directory", "/etc/ufastauthd2", Memory::Abstract::Var::TYPE_STRING);
        globalArguments->addCommandLineOption("Recovery Options", 'r', "resetadmpw", "Reset Administrator Password", "false", Memory::Abstract::Var::TYPE_BOOL);
    }

    bool _config(int, char *argv[], Program::Arguments::GlobalArguments *globalArguments)
    {
        // process config:
        auto initLog = Program::Config::Logs::createInitLog();
        unsigned int logMode = Program::Logs::MODE_STANDARD;
        boost::property_tree::ptree pConfig;

        Network::Sockets::Socket_TLS::prepareTLS();

        Globals::setResetAdminPasswd(globalArguments->getCommandLineOptionBooleanValue("resetadmpw"));
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        initLog->log0(__func__, Program::Logs::LEVEL_INFO, "Loading configuration: %s", (configDir + "/ufastauthd2.conf").c_str());

        if (access(configDir.c_str(), R_OK))
        {
            initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL, "Missing configuration dir: %s", configDir.c_str());
            return false;
        }

        chdir(configDir.c_str());

        bool isConfigFileInsecure = true;
        if (!Helpers::File::isSensitiveConfigPermissionInsecure("ufastauthd2.conf", &isConfigFileInsecure))
        {
            initLog->log0(__func__, Program::Logs::LEVEL_WARN, "The configuration 'ufastauthd2.conf' file is inaccessible, loading defaults...");
        }
        else
        {
            if (isConfigFileInsecure)
            {
                initLog->log0(__func__, Program::Logs::LEVEL_SECURITY_ALERT,
                              "The permissions of the 'ufastauthd2.conf' file are currently not set to 0600. This may leave your API key exposed to potential security threats. To mitigate this risk, "
                              "we are changing the permissions of the file to ensure that your API key remains secure. Please ensure that you take necessary precautions to protect your API key and "
                              "update any affected applications or services as necessary.");

                if (Helpers::File::fixSensitiveConfigPermission("ufastauthd2.conf"))
                {
                    initLog->log0(__func__, Program::Logs::LEVEL_SECURITY_ALERT, "The permissions of the 'ufastauthd2.conf' file has been changed to 0600.");
                }
                else
                {
                    initLog->log0(__func__, Program::Logs::LEVEL_CRITICAL, "The permissions of the 'ufastauthd2.conf' file can't be changed.");
                    return false;
                }
            }

            boost::property_tree::info_parser::read_info("ufastauthd2.conf", pConfig);
        }

        *(Globals::getConfig()) = pConfig;

        Globals::setAppLog(Program::Config::Logs::createAppLog(Globals::getConfig()));
        Globals::setRPCLog(Program::Config::Logs::createRPCLog(Globals::getConfig()));

        return true;
    }

    int _start(int, char *[], Program::Arguments::GlobalArguments *globalArguments)
    {
        std::string configDir = globalArguments->getCommandLineOptionValue("config-dir")->toString();

        // start program.
        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, "Starting... (Build date %s %s), PID: %" PRIi32, __DATE__, __TIME__, getpid());
        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, "Using config dir: %s", configDir.c_str());

        // TODO: for MySQL/PostgreSQL Authenticator, how reconnect takes place?
        // Initiate the authenticator
        if (!AuthStorageImpl::createAuth())
        {
            _exit(-3);
        }

        /*
        // Creates the FastRPC Implementation
        Globals::setFastRPC(new FastRPCImpl); */

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

        // Web Login:
        if (!WebSessionAuthHandler_ServerImpl::createService())
        {
            _exit(-7);
        }
        /*// Initiate the RPC Listener
        if (!RPC1LoginServer2Impl::createRPCListenerCAB())
        {
            _exit(-2);
        }
        // Initiate the RPC Listener
        if (!RPC1LoginServer2Impl::createRPCListenerPAB())
        {
            _exit(-4);
        }*/

        LOG_APP->log0(__func__, Program::Logs::LEVEL_INFO, (globalArguments->getDaemonName() + " initialized with PID: %" PRIi32).c_str(), getpid());

        return 0;
    }

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
};

int main(int argc, char *argv[])
{
    Main *main = new Main;
    return StartApplication(argc, argv, main);
}
