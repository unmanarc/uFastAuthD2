#include "loginrpcserverimpl.h"

#include <inttypes.h>

#include <Mantids29/Net_Sockets/socket_tls.h>
#include <Mantids29/Net_Sockets/acceptor_multithreaded.h>
#include <Mantids29/Net_Sockets/streams_cryptochallenge.h>
#include <Mantids29/Program_Logs/applog.h>
#include <memory>

#include "globals.h"
//#include "defs.h"
#include "loginauthmethods.h"

using namespace AUTHSERVER::RPC;

using namespace Mantids29::Program;
using namespace Mantids29::RPC;
using namespace Mantids29;

LoginRPCServerImpl::LoginRPCServerImpl()
{
}

bool LoginRPCServerImpl::callbackOnRPCConnect(void *, Mantids29::Network::Sockets::Socket_Stream_Base *sock, const char * remoteAddr, bool secure)
{
    Network::Sockets::NetStreams::CryptoChallenge cstream(sock);

    std::string appName = sock->readStringEx<uint16_t>();
    std::string appKey = Globals::getAuthManager()->applicationKey(appName);

    std::string rpcClientKey = appName + "." + Mantids29::Helpers::Random::createRandomString(8);

    LOG_APP->log0(__func__,Logs::LEVEL_INFO, "Incomming %sRPC connection from %s (ID: %s)", secure?"secure ":"", remoteAddr, rpcClientKey.c_str());

    if (cstream.mutualChallengeResponseSHA256Auth(appKey,true) == std::make_pair(true,true))
    {
        LOG_APP->log0(__func__,Logs::LEVEL_INFO,
                      "%sRPC client '%s' authenticated to application: '%s'",
                      secure?"secure ":"", rpcClientKey.c_str(), appName.c_str());

        if (Globals::getFastRPC()->processConnection(sock,rpcClientKey,{nullptr,nullptr})==-2)
        {
            LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Client %s Already Connected, giving up from %s.", rpcClientKey.c_str(), remoteAddr);
        }
    }
    else
    {
        LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Client %s bad API Application Key, giving up from %s.", rpcClientKey.c_str(), remoteAddr);
    }


    LOG_APP->log0(__func__,Logs::LEVEL_INFO, "Connection %sRPC from %s (ID: %s) has been closed.", secure?"secure ":"", remoteAddr, rpcClientKey.c_str());
    return true;
}

bool LoginRPCServerImpl::createRPCListenerCAB()
{
    if (Globals::getConfig_main()->get<bool>("LoginRPCServerCAB.Enabled",true))
    {
        auto sockRPCListen = std::make_shared<Mantids29::Network::Sockets::Socket_TLS>();

        // Set the SO default security level:
        sockRPCListen->keys.setSecurityLevel(-1);

        uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("LoginRPCServerCAB.ListenPort",30301);
        std::string listenAddr = Globals::getConfig_main()->get<std::string>("LoginRPCServerCAB.ListenAddr","0.0.0.0");

        if (!sockRPCListen->keys.loadPublicKeyFromPEMFile( Globals::getConfig_main()->get<std::string>("LoginRPCServerCAB.CertFile","snakeoil.crt").c_str() ))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Login RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Public Key");
            return false;
        }
        if (!sockRPCListen->keys.loadPrivateKeyFromPEMFile( Globals::getConfig_main()->get<std::string>("LoginRPCServerCAB.KeyFile","snakeoil.key").c_str() ))
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting Login RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, "Bad TLS RPC Server Private Key");
            return false;
        }

        Globals::setFastRPC(new FastRPCImpl);

        // Set RPC Methods.
        Mantids29::RPC::Templates::LoginAuth::AddLoginAuthMethods(
                    Globals::getAuthManager(),
                    Globals::getFastRPC());

        // Init the server:
        auto multiThreadedAcceptor = std::make_shared<Network::Sockets::Acceptors::MultiThreaded>();
        multiThreadedAcceptor->setMaxConcurrentClients( Globals::getConfig_main()->get<uint16_t>("LoginRPCServerCAB.MaxClients",512) );
        multiThreadedAcceptor->setCallbackOnConnect(callbackOnRPCConnect,nullptr);

        if (sockRPCListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("LoginRPCServerCAB.ipv6",false) ))
        {
            multiThreadedAcceptor->setAcceptorSocket(sockRPCListen);
            multiThreadedAcceptor->startThreaded(multiThreadedAcceptor);
            LOG_APP->log0(__func__,Logs::LEVEL_INFO,  "Accepting RPC clients @%s:%" PRIu16 " via TLS", listenAddr.c_str(), listenPort);
            return true;
        }
        else
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockRPCListen->getLastError().c_str());
            return false;
        }
    }
    return true;
}

bool cbPSK(void * data,const std::string & id, std::string * psk)
{
    *psk = AUTHSERVER::Globals::getAuthManager()->applicationKey(id);
    return !psk->empty();
}

bool LoginRPCServerImpl::createRPCListenerPAB()
{
    if (Globals::getConfig_main()->get<bool>("LoginRPCServerPAB.Enabled",true))
    {
        auto sockRPCListen = std::make_shared<Mantids29::Network::Sockets::Socket_TLS>();

        // Configure default
        sockRPCListen->keys.setPSK();
        sockRPCListen->keys.getPSKServerWallet()->setPSKCallback(&cbPSK,nullptr);

        uint16_t listenPort = Globals::getConfig_main()->get<uint16_t>("LoginRPCServerPAB.ListenPort",30302);
        std::string listenAddr = Globals::getConfig_main()->get<std::string>("LoginRPCServerPAB.ListenAddr","0.0.0.0");

        Globals::setFastRPC(new FastRPCImpl);

        // Set RPC Methods.
        Mantids29::RPC::Templates::LoginAuth::AddLoginAuthMethods(
                    Globals::getAuthManager(),
                    Globals::getFastRPC());

        // Init the server:
        auto multiThreadedAcceptor = std::make_shared<Network::Sockets::Acceptors::MultiThreaded>();
        multiThreadedAcceptor->setMaxConcurrentClients( Globals::getConfig_main()->get<uint16_t>("LoginRPCServerPAB.MaxClients",512) );
        multiThreadedAcceptor->setCallbackOnConnect(callbackOnRPCConnect,nullptr);

        if (sockRPCListen->listenOn(listenPort ,listenAddr.c_str(), !Globals::getConfig_main()->get<bool>("LoginRPCServerPAB.ipv6",false) ))
        {
            multiThreadedAcceptor->setAcceptorSocket(sockRPCListen);
            multiThreadedAcceptor->startThreaded(multiThreadedAcceptor);
            LOG_APP->log0(__func__,Logs::LEVEL_INFO,  "Accepting API KEY RPC clients @%s:%" PRIu16 " via TLS", listenAddr.c_str(), listenPort);
            return true;
        }
        else
        {
            LOG_APP->log0(__func__,Logs::LEVEL_CRITICAL, "Error starting API KEY RPC Server @%s:%" PRIu16 ": %s", listenAddr.c_str(), listenPort, sockRPCListen->getLastError().c_str());
            return false;
        }
    }
    return true;
}


void FastRPCImpl::eventUnexpectedAnswerReceived(FastRPC1::Connection *, const std::string &)
{
    LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Error - Unexpected Answer");
}

void FastRPCImpl::eventFullQueueDrop(FastRPC1::ThreadParameters *)
{
    LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Error - Event Queue Full");
}

void FastRPCImpl::eventRemotePeerDisconnected(const std::string &, const std::string &, const json &)
{
    LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Error - Remote Peer Disconnected");
}

void FastRPCImpl::eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &)
{
    LOG_APP->log0(__func__,Logs::LEVEL_ERR, "RPC Error - Remote Execution Timed Out");

}
