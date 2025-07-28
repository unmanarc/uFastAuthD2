#include "logindirectorymanager.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits.h>

LoginDirectoryManager::LoginDirectoryManager(const std::string &directoryPath)
    : path(directoryPath)
{
    if (path.back() != '/')
    {
        path += '/';
    }
}

LoginDirectoryManager::ErrorCode LoginDirectoryManager::writeFile(const std::string &appName, const std::string &htmlContent)
{
    std::string filePath;
    ErrorCode errorCode = validatePath(appName, filePath);

    if (errorCode != ErrorCode::SUCCESS)
    {
        return errorCode;
    }

    std::ofstream outFile(filePath);

    if (!outFile)
    {
        return ErrorCode::FILE_OPEN_ERROR;
    }

    outFile << htmlContent;
    outFile.close();
    return ErrorCode::SUCCESS;
}

LoginDirectoryManager::ErrorCode LoginDirectoryManager::retrieveFile(const std::string &appName, std::string &htmlContent)
{
    std::string filePath;
    ErrorCode errorCode = validatePath(appName, filePath);

    if (errorCode != ErrorCode::SUCCESS)
    {
        return errorCode;
    }

    std::ifstream inFile(filePath);

    if (!inFile)
    {
        return ErrorCode::FILE_OPEN_ERROR;
    }

    htmlContent.assign((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

    inFile.close();
    return ErrorCode::SUCCESS;
}

std::string LoginDirectoryManager::getErrorMessage(ErrorCode errorCode)
{
    switch (errorCode)
    {
    case LoginDirectoryManager::ErrorCode::SUCCESS:
        return "Success";
    case LoginDirectoryManager::ErrorCode::PATH_RESOLUTION_ERROR:
        return "Path resolution error";
    case LoginDirectoryManager::ErrorCode::FILE_OPEN_ERROR:
        return "File open error";
    case LoginDirectoryManager::ErrorCode::DIRECTORY_TRAVERSAL_DETECTED:
        return "Directory traversal detected";
    default:
        return "Unknown error";
    }
}

LoginDirectoryManager::ErrorCode LoginDirectoryManager::validatePath(const std::string &appName, std::string &filePath)
{
    std::string tentativePath = path + appName + ".html";
    char realPathBuffer[PATH_MAX];

    if (realpath(tentativePath.c_str(), realPathBuffer) == nullptr)
    {
        return ErrorCode::PATH_RESOLUTION_ERROR;
    }

    std::string realPath(realPathBuffer);
    if (realPath.compare(0, path.length(), path) != 0)
    {
        return ErrorCode::DIRECTORY_TRAVERSAL_DETECTED;
    }

    filePath = realPath;
    return ErrorCode::SUCCESS;
}
