#pragma once

#include <string>

class LoginDirectoryManager
{
public:
    enum class ErrorCode
    {
        SUCCESS,
        PATH_RESOLUTION_ERROR,
        FILE_OPEN_ERROR,
        DIRECTORY_TRAVERSAL_DETECTED
    };

    LoginDirectoryManager(const std::string& directoryPath);

    ErrorCode writeFile(const std::string& appName, const std::string& htmlContent);
    ErrorCode retrieveFile(const std::string& appName, std::string& htmlContent);

    static std::string getErrorMessage(ErrorCode errorCode);

private:
    std::string path;

    ErrorCode validatePath(const std::string& appName, std::string& filePath);
};
