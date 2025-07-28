#include "fastrpcimpl.h"
#include "../globals.h"

using namespace Mantids30::Program;

void FastRPCImpl::eventUnexpectedAnswerReceived(Connection *, const std::string &)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Error - Unexpected Answer");
}

void FastRPCImpl::eventFullQueueDrop(ThreadParameters *)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Error - Event Queue Full");
}

void FastRPCImpl::eventRemotePeerDisconnected(const std::string &, const std::string &, const json &)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Error - Remote Peer Disconnected");
}

void FastRPCImpl::eventRemoteExecutionTimedOut(const std::string &, const std::string &, const json &)
{
    LOG_APP->log0(__func__, Logs::LEVEL_ERR, "RPC Error - Remote Execution Timed Out");
}
