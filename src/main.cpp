#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr DWORD kSecurityInfo =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

enum class ExitCode : int {
    Success = 0,
    BadArgs = 1,
    PrivilegeError = 2,
    WindowsError = 3,
    BackupError = 4,
};

enum class Command {
    Status,
    Unlock,
    Restore,
};

struct Options {
    Command command{};
    std::wstring path;
    std::wstring backupDir;
    bool recursive = false;
    bool forceSystem = false;
    bool interactiveMenu = false;
};

struct Target {
    std::wstring path;
    bool isDirectory = false;
};

struct BackupRecord {
    std::wstring path;
    std::string type;
    std::wstring sddl;
};

struct OperationResult {
    bool ok = false;
    ExitCode code = ExitCode::WindowsError;
};

struct LocalMemory {
    HLOCAL ptr = nullptr;

    LocalMemory() = default;
    explicit LocalMemory(HLOCAL value) : ptr(value) {}
    ~LocalMemory() {
        if (ptr != nullptr) {
            LocalFree(ptr);
        }
    }

    LocalMemory(const LocalMemory&) = delete;
    LocalMemory& operator=(const LocalMemory&) = delete;

    void reset(HLOCAL value = nullptr) {
        if (ptr != nullptr) {
            LocalFree(ptr);
        }
        ptr = value;
    }
};

struct Handle {
    HANDLE value = nullptr;

    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    bool valid() const {
        return value != nullptr && value != INVALID_HANDLE_VALUE;
    }
};

struct FindHandle {
    HANDLE value = INVALID_HANDLE_VALUE;

    FindHandle() = default;
    explicit FindHandle(HANDLE handle) : value(handle) {}
    ~FindHandle() {
        if (valid()) {
            FindClose(value);
        }
    }

    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;

    bool valid() const {
        return value != INVALID_HANDLE_VALUE;
    }
};

std::string ToUtf8(const std::wstring& input) {
    if (input.empty()) {
        return {};
    }

    int size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        size = WideCharToMultiByte(
            CP_UTF8, 0, input.data(), static_cast<int>(input.size()),
            nullptr, 0, nullptr, nullptr);
    }
    if (size <= 0) {
        return {};
    }

    std::string output(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()),
        output.data(), size, nullptr, nullptr);
    return output;
}

std::wstring FromUtf8(const std::string& input) {
    if (input.empty()) {
        return {};
    }

    int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
        nullptr, 0);
    if (size <= 0) {
        size = MultiByteToWideChar(
            CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    }
    if (size <= 0) {
        return {};
    }

    std::wstring output(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, input.data(), static_cast<int>(input.size()), output.data(), size);
    return output;
}

void Print(const std::string& message) {
    std::cout << message << '\n';
}

void PrintError(const std::string& message) {
    std::cerr << message << '\n';
}

std::string TrimRight(std::string value) {
    while (!value.empty()) {
        unsigned char ch = static_cast<unsigned char>(value.back());
        if (std::isspace(ch) == 0) {
            break;
        }
        value.pop_back();
    }
    return value;
}

std::string WindowsErrorMessage(DWORD error) {
    LPWSTR buffer = nullptr;
    DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    LocalMemory memory(reinterpret_cast<HLOCAL>(buffer));

    if (length == 0 || buffer == nullptr) {
        return "Windows error " + std::to_string(error);
    }

    return TrimRight(ToUtf8(std::wstring(buffer, length))) + " (" + std::to_string(error) + ")";
}

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return value;
}

bool StartsWith(std::wstring_view value, std::wstring_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool IsSlash(wchar_t ch) {
    return ch == L'\\' || ch == L'/';
}

bool IsDriveRoot(const std::wstring& path) {
    return path.size() == 3 && path[1] == L':' && IsSlash(path[2]);
}

std::wstring TrimTrailingSlashes(std::wstring path) {
    while (path.size() > 1 && IsSlash(path.back()) && !IsDriveRoot(path)) {
        path.pop_back();
    }
    return path;
}

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
    if (left.empty()) {
        return right;
    }
    if (IsSlash(left.back())) {
        return left + right;
    }
    return left + L"\\" + right;
}

std::wstring RemoveExtendedPathPrefix(const std::wstring& path) {
    if (StartsWith(path, L"\\\\?\\UNC\\")) {
        return L"\\\\" + path.substr(8);
    }
    if (StartsWith(path, L"\\\\?\\")) {
        return path.substr(4);
    }
    return path;
}

std::optional<std::wstring> NormalizePath(const std::wstring& input, std::string& error) {
    DWORD required = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (required == 0) {
        error = WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }

    std::wstring buffer(required, L'\0');
    DWORD written = GetFullPathNameW(input.c_str(), required, buffer.data(), nullptr);
    if (written == 0 || written >= required) {
        error = WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }

    buffer.resize(written);
    buffer = RemoveExtendedPathPrefix(buffer);
    return TrimTrailingSlashes(buffer);
}

std::wstring ApiPath(const std::wstring& path) {
    if (StartsWith(path, L"\\\\?\\")) {
        return path;
    }
    if (StartsWith(path, L"\\\\")) {
        return L"\\\\?\\UNC\\" + path.substr(2);
    }
    return L"\\\\?\\" + path;
}

DWORD GetAttributes(const std::wstring& path) {
    std::wstring apiPath = ApiPath(path);
    return GetFileAttributesW(apiPath.c_str());
}

std::optional<DWORD> GetExistingAttributes(const std::wstring& path, std::string& error) {
    DWORD attributes = GetAttributes(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        error = WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }
    return attributes;
}

bool IsReparsePoint(DWORD attributes) {
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool IsDirectory(DWORD attributes) {
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool FileExists(const std::wstring& path) {
    DWORD attributes = GetAttributes(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !IsDirectory(attributes);
}

std::string CommandName(Command command) {
    switch (command) {
    case Command::Status:
        return "status";
    case Command::Unlock:
        return "unlock";
    case Command::Restore:
        return "restore";
    }
    return "unknown";
}

std::optional<Command> ParseCommandName(const std::wstring& value) {
    std::wstring command = ToLower(value);
    if (command == L"status") {
        return Command::Status;
    }
    if (command == L"unlock") {
        return Command::Unlock;
    }
    if (command == L"restore") {
        return Command::Restore;
    }
    return std::nullopt;
}

std::string TargetTypeName(bool isDirectory) {
    return isDirectory ? "directory" : "file";
}

void PrintUsage() {
    Print("Usage:");
    Print("  AntiTrusted.exe <path>");
    Print("  AntiTrusted.exe status <path> [--recursive] [--backup-dir <dir>]");
    Print("  AntiTrusted.exe unlock <path> [--recursive] [--backup-dir <dir>] [--force-system]");
    Print("  AntiTrusted.exe restore <path> [--recursive] [--backup-dir <dir>] [--force-system]");
}

std::optional<Options> ParseArgs(int argc, wchar_t* argv[], std::string& error) {
    if (argc < 2) {
        error = "Not enough arguments.";
        return std::nullopt;
    }

    Options options;
    if (argc == 2) {
        if (ParseCommandName(argv[1])) {
            error = "Command requires a path: " + ToUtf8(argv[1]);
            return std::nullopt;
        }

        options.interactiveMenu = true;
        options.path = argv[1];
        return options;
    }

    std::optional<Command> command = ParseCommandName(argv[1]);
    if (!command) {
        error = "Unknown command: " + ToUtf8(argv[1]);
        return std::nullopt;
    }

    options.command = *command;
    options.path = argv[2];

    for (int i = 3; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--recursive") {
            options.recursive = true;
        } else if (arg == L"--force-system") {
            options.forceSystem = true;
        } else if (arg == L"--backup-dir") {
            if (i + 1 >= argc) {
                error = "--backup-dir requires a directory path.";
                return std::nullopt;
            }
            options.backupDir = argv[++i];
        } else {
            error = "Unknown argument: " + ToUtf8(arg);
            return std::nullopt;
        }
    }

    return options;
}

std::wstring GetEnvironmentValue(const wchar_t* name) {
    DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }

    std::wstring value(required, L'\0');
    DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0 || written >= required) {
        return {};
    }
    value.resize(written);
    return value;
}

std::wstring DefaultBackupDir() {
    std::wstring programData = GetEnvironmentValue(L"ProgramData");
    if (programData.empty()) {
        programData = L"C:\\ProgramData";
    }
    return JoinPath(JoinPath(programData, L"AntiTrusted"), L"backups");
}

bool SameOrChildPath(const std::wstring& path, const std::wstring& root) {
    if (root.empty()) {
        return false;
    }

    std::wstring lowerPath = ToLower(TrimTrailingSlashes(path));
    std::wstring lowerRoot = ToLower(TrimTrailingSlashes(root));
    if (lowerPath == lowerRoot) {
        return true;
    }
    if (!IsSlash(lowerRoot.back())) {
        lowerRoot.push_back(L'\\');
    }
    return StartsWith(lowerPath, lowerRoot);
}

bool IsProtectedSystemPath(const std::wstring& normalizedPath) {
    const wchar_t* envVars[] = {
        L"WINDIR",
        L"ProgramFiles",
        L"ProgramFiles(x86)",
    };

    for (const wchar_t* envVar : envVars) {
        std::wstring value = GetEnvironmentValue(envVar);
        if (value.empty()) {
            continue;
        }

        std::string error;
        std::optional<std::wstring> normalizedRoot = NormalizePath(value, error);
        if (normalizedRoot && SameOrChildPath(normalizedPath, *normalizedRoot)) {
            return true;
        }
    }

    return false;
}

bool IsElevated() {
    Handle token;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        return false;
    }
    token.value = rawToken;

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size)) {
        return false;
    }

    return elevation.TokenIsElevated != 0;
}

bool EnablePrivilege(const wchar_t* privilegeName, std::string& error) {
    Handle token;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        error = "OpenProcessToken failed: " + WindowsErrorMessage(GetLastError());
        return false;
    }
    token.value = rawToken;

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &privileges.Privileges[0].Luid)) {
        error = "LookupPrivilegeValue failed for " + ToUtf8(privilegeName) + ": " +
                WindowsErrorMessage(GetLastError());
        return false;
    }

    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token.value, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        error = "AdjustTokenPrivileges failed for " + ToUtf8(privilegeName) + ": " +
                WindowsErrorMessage(GetLastError());
        return false;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        error = "Privilege is not available in this token: " + ToUtf8(privilegeName);
        return false;
    }

    return true;
}

bool EnableRequiredPrivileges(std::string& error) {
    const wchar_t* privileges[] = {
        SE_BACKUP_NAME,
        SE_RESTORE_NAME,
        SE_TAKE_OWNERSHIP_NAME,
    };

    for (const wchar_t* privilege : privileges) {
        if (!EnablePrivilege(privilege, error)) {
            return false;
        }
    }

    return true;
}

std::optional<std::vector<BYTE>> CurrentUserSid(std::string& error) {
    Handle token;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        error = "OpenProcessToken failed: " + WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }
    token.value = rawToken;

    DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = "GetTokenInformation size query failed: " + WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token.value, TokenUser, buffer.data(), size, &size)) {
        error = "GetTokenInformation failed: " + WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }

    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    DWORD sidSize = GetLengthSid(user->User.Sid);
    std::vector<BYTE> sid(sidSize);
    if (!CopySid(sidSize, sid.data(), user->User.Sid)) {
        error = "CopySid failed: " + WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }

    return sid;
}

std::string Base64Encode(const std::vector<BYTE>& bytes) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string output;
    output.reserve(((bytes.size() + 2) / 3) * 4);

    for (size_t i = 0; i < bytes.size(); i += 3) {
        uint32_t value = static_cast<uint32_t>(bytes[i]) << 16;
        if (i + 1 < bytes.size()) {
            value |= static_cast<uint32_t>(bytes[i + 1]) << 8;
        }
        if (i + 2 < bytes.size()) {
            value |= static_cast<uint32_t>(bytes[i + 2]);
        }

        output.push_back(kTable[(value >> 18) & 0x3F]);
        output.push_back(kTable[(value >> 12) & 0x3F]);
        output.push_back(i + 1 < bytes.size() ? kTable[(value >> 6) & 0x3F] : '=');
        output.push_back(i + 2 < bytes.size() ? kTable[value & 0x3F] : '=');
    }

    return output;
}

int Base64Value(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

std::optional<std::vector<BYTE>> Base64Decode(const std::string& input) {
    std::vector<BYTE> output;
    int value = 0;
    int bits = -8;

    for (char ch : input) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            continue;
        }
        if (ch == '=') {
            break;
        }

        int decoded = Base64Value(ch);
        if (decoded < 0) {
            return std::nullopt;
        }

        value = (value << 6) | decoded;
        bits += 6;
        if (bits >= 0) {
            output.push_back(static_cast<BYTE>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }

    return output;
}

std::vector<BYTE> Utf8Bytes(const std::wstring& value) {
    std::string utf8 = ToUtf8(value);
    return std::vector<BYTE>(utf8.begin(), utf8.end());
}

std::string BytesToString(const std::vector<BYTE>& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::optional<std::string> Sha256Hex(const std::string& input, std::string& error) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider failed.";
        return std::nullopt;
    }

    DWORD objectLength = 0;
    DWORD cbData = 0;
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
        sizeof(objectLength), &cbData, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed.";
        return std::nullopt;
    }

    std::vector<BYTE> hashObject(objectLength);
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectLength, nullptr, 0, 0);
    if (status < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "BCryptCreateHash failed.";
        return std::nullopt;
    }

    status = BCryptHashData(
        hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
        static_cast<ULONG>(input.size()),
        0);
    if (status < 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "BCryptHashData failed.";
        return std::nullopt;
    }

    std::vector<BYTE> digest(32);
    status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        error = "BCryptFinishHash failed.";
        return std::nullopt;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (BYTE byte : digest) {
        hex.push_back(kHex[(byte >> 4) & 0x0F]);
        hex.push_back(kHex[byte & 0x0F]);
    }

    return hex;
}

std::optional<std::wstring> BackupFilePath(
    const std::wstring& backupDir,
    const std::wstring& normalizedPath,
    std::string& error) {
    std::string hashInput = ToUtf8(ToLower(normalizedPath));
    std::optional<std::string> hash = Sha256Hex(hashInput, error);
    if (!hash) {
        return std::nullopt;
    }

    return JoinPath(backupDir, FromUtf8(*hash + ".atbackup"));
}

bool EnsureDirectory(const std::wstring& path, std::string& error) {
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path), ec);
    if (ec) {
        error = ec.message();
        return false;
    }

    DWORD attributes = GetAttributes(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || !IsDirectory(attributes)) {
        error = "Backup directory is not available: " + ToUtf8(path);
        return false;
    }

    return true;
}

bool WriteTextFileNew(
    const std::wstring& path,
    const std::string& content,
    bool& alreadyExists,
    std::string& error) {
    alreadyExists = false;
    std::wstring apiPath = ApiPath(path);
    Handle file(CreateFileW(
        apiPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        DWORD lastError = GetLastError();
        alreadyExists = lastError == ERROR_FILE_EXISTS || lastError == ERROR_ALREADY_EXISTS;
        error = WindowsErrorMessage(lastError);
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(file.value, content.data(), static_cast<DWORD>(content.size()), &written, nullptr) ||
        written != static_cast<DWORD>(content.size())) {
        error = WindowsErrorMessage(GetLastError());
        return false;
    }

    return true;
}

bool ReadTextFile(const std::wstring& path, std::string& content, std::string& error) {
    std::wstring apiPath = ApiPath(path);
    Handle file(CreateFileW(
        apiPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        error = WindowsErrorMessage(GetLastError());
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) {
        error = "Invalid backup file size.";
        return false;
    }

    content.assign(static_cast<size_t>(size.QuadPart), '\0');
    size_t offset = 0;
    while (offset < content.size()) {
        DWORD chunkSize = static_cast<DWORD>(
            std::min<size_t>(content.size() - offset, 1024 * 1024));
        DWORD read = 0;
        if (!ReadFile(file.value, content.data() + offset, chunkSize, &read, nullptr)) {
            error = WindowsErrorMessage(GetLastError());
            return false;
        }
        if (read == 0) {
            break;
        }
        offset += read;
    }
    if (offset != content.size()) {
        error = "Backup file changed while reading.";
        return false;
    }
    return true;
}

std::string CurrentUtcTimestamp() {
    SYSTEMTIME time{};
    GetSystemTime(&time);

    char buffer[32]{};
    std::snprintf(
        buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02uZ",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return buffer;
}

std::optional<std::wstring> GetSecurityDescriptorSddl(const std::wstring& path, std::string& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    std::wstring apiPath = ApiPath(path);
    DWORD result = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT, kSecurityInfo,
        nullptr, nullptr, nullptr, nullptr, &descriptor);
    LocalMemory descriptorMemory(reinterpret_cast<HLOCAL>(descriptor));
    if (result != ERROR_SUCCESS) {
        error = WindowsErrorMessage(result);
        return std::nullopt;
    }

    LPWSTR sddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, kSecurityInfo, &sddl, nullptr)) {
        error = WindowsErrorMessage(GetLastError());
        return std::nullopt;
    }
    LocalMemory sddlMemory(reinterpret_cast<HLOCAL>(sddl));

    return std::wstring(sddl);
}

bool SaveBackupIfMissing(
    const Target& target,
    const std::wstring& backupDir,
    const std::wstring& backupPath,
    bool& created,
    std::string& error) {
    created = false;
    if (FileExists(backupPath)) {
        return true;
    }

    if (!EnsureDirectory(backupDir, error)) {
        return false;
    }

    std::optional<std::wstring> sddl = GetSecurityDescriptorSddl(target.path, error);
    if (!sddl) {
        return false;
    }

    std::ostringstream output;
    output << "version=1\n";
    output << "path=" << Base64Encode(Utf8Bytes(target.path)) << "\n";
    output << "type=" << TargetTypeName(target.isDirectory) << "\n";
    output << "created_utc=" << CurrentUtcTimestamp() << "\n";
    output << "sddl=" << Base64Encode(Utf8Bytes(*sddl)) << "\n";

    bool alreadyExists = false;
    if (!WriteTextFileNew(backupPath, output.str(), alreadyExists, error)) {
        if (alreadyExists) {
            return true;
        }
        return false;
    }

    created = true;
    return true;
}

std::map<std::string, std::string> ParseKeyValueLines(const std::string& content) {
    std::map<std::string, std::string> values;
    size_t start = 0;
    while (start <= content.size()) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) {
            end = content.size();
        }

        std::string line = content.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            size_t equals = line.find('=');
            if (equals != std::string::npos) {
                values[line.substr(0, equals)] = line.substr(equals + 1);
            }
        }

        if (end == content.size()) {
            break;
        }
        start = end + 1;
    }
    return values;
}

std::optional<std::wstring> DecodeBackupWideField(
    const std::map<std::string, std::string>& values,
    const std::string& key,
    std::string& error) {
    auto it = values.find(key);
    if (it == values.end()) {
        error = "Backup is missing field: " + key;
        return std::nullopt;
    }

    std::optional<std::vector<BYTE>> decoded = Base64Decode(it->second);
    if (!decoded) {
        error = "Backup has invalid base64 in field: " + key;
        return std::nullopt;
    }

    return FromUtf8(BytesToString(*decoded));
}

std::optional<BackupRecord> LoadBackup(const std::wstring& backupPath, std::string& error) {
    std::string content;
    if (!ReadTextFile(backupPath, content, error)) {
        return std::nullopt;
    }

    std::map<std::string, std::string> values = ParseKeyValueLines(content);
    if (values["version"] != "1") {
        error = "Unsupported backup version.";
        return std::nullopt;
    }

    auto typeIt = values.find("type");
    if (typeIt == values.end() || (typeIt->second != "file" && typeIt->second != "directory")) {
        error = "Backup has invalid object type.";
        return std::nullopt;
    }

    std::optional<std::wstring> path = DecodeBackupWideField(values, "path", error);
    if (!path) {
        return std::nullopt;
    }
    std::optional<std::wstring> sddl = DecodeBackupWideField(values, "sddl", error);
    if (!sddl) {
        return std::nullopt;
    }

    return BackupRecord{*path, typeIt->second, *sddl};
}

bool VerifyBackupMatchesTarget(const BackupRecord& backup, const Target& target, std::string& error) {
    if (ToLower(TrimTrailingSlashes(backup.path)) != ToLower(TrimTrailingSlashes(target.path))) {
        error = "Backup path mismatch. Backup is for: " + ToUtf8(backup.path);
        return false;
    }

    if (backup.type != TargetTypeName(target.isDirectory)) {
        error = "Backup type mismatch.";
        return false;
    }

    return true;
}

std::string SidToDisplayName(PSID sid) {
    DWORD nameSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, sid, nullptr, &nameSize, nullptr, &domainSize, &use);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::wstring name(nameSize, L'\0');
        std::wstring domain(domainSize, L'\0');
        if (LookupAccountSidW(
                nullptr, sid, name.data(), &nameSize, domain.data(), &domainSize, &use)) {
            name.resize(nameSize);
            domain.resize(domainSize);
            if (!domain.empty()) {
                return ToUtf8(domain + L"\\" + name);
            }
            return ToUtf8(name);
        }
    }

    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        LocalMemory sidStringMemory(reinterpret_cast<HLOCAL>(sidString));
        return ToUtf8(sidString);
    }

    return "<unknown SID>";
}

OperationResult PrintStatus(const Target& target, const std::wstring& backupDir) {
    std::string hashError;
    std::optional<std::wstring> backupPath = BackupFilePath(backupDir, target.path, hashError);
    if (!backupPath) {
        PrintError("[status] " + ToUtf8(target.path) + ": " + hashError);
        return {false, ExitCode::WindowsError};
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    std::wstring apiPath = ApiPath(target.path);
    DWORD result = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    LocalMemory descriptorMemory(reinterpret_cast<HLOCAL>(descriptor));
    if (result != ERROR_SUCCESS) {
        PrintError("[status] " + ToUtf8(target.path) + ": " + WindowsErrorMessage(result));
        return {false, ExitCode::WindowsError};
    }

    Print("[status] " + ToUtf8(target.path));
    Print("  type: " + TargetTypeName(target.isDirectory));
    Print("  owner: " + (owner != nullptr ? SidToDisplayName(owner) : std::string("<none>")));
    if (dacl != nullptr) {
        Print("  dacl_aces: " + std::to_string(dacl->AceCount));
    } else {
        Print("  dacl_aces: <null dacl>");
    }
    Print("  backup: " + std::string(FileExists(*backupPath) ? "yes" : "no"));
    return {true, ExitCode::Success};
}

bool DaclHasFullControlAceForSid(PACL dacl, PSID sid) {
    if (dacl == nullptr) {
        return false;
    }

    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace) || ace == nullptr) {
            continue;
        }

        auto* header = reinterpret_cast<ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            continue;
        }

        auto* allowed = reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace);
        PSID aceSid = reinterpret_cast<PSID>(&allowed->SidStart);
        if (EqualSid(aceSid, sid) &&
            ((allowed->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS ||
             (allowed->Mask & GENERIC_ALL) == GENERIC_ALL)) {
            return true;
        }
    }

    return false;
}

DWORD GrantCurrentUserFullControl(const Target& target, PSID currentUserSid) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL oldDacl = nullptr;
    std::wstring apiPath = ApiPath(target.path);
    DWORD result = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &oldDacl, nullptr, &descriptor);
    LocalMemory descriptorMemory(reinterpret_cast<HLOCAL>(descriptor));
    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (DaclHasFullControlAceForSid(oldDacl, currentUserSid)) {
        return ERROR_SUCCESS;
    }

    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = FILE_ALL_ACCESS;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = target.isDirectory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(currentUserSid);

    PACL newDacl = nullptr;
    result = SetEntriesInAclW(1, &access, oldDacl, &newDacl);
    LocalMemory newDaclMemory(reinterpret_cast<HLOCAL>(newDacl));
    if (result != ERROR_SUCCESS) {
        return result;
    }

    return SetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
}

OperationResult UnlockTarget(
    const Target& target,
    const std::wstring& backupDir,
    PSID currentUserSid) {
    std::string error;
    std::optional<std::wstring> backupPath = BackupFilePath(backupDir, target.path, error);
    if (!backupPath) {
        PrintError("[unlock] " + ToUtf8(target.path) + ": " + error);
        return {false, ExitCode::WindowsError};
    }

    bool created = false;
    if (!SaveBackupIfMissing(target, backupDir, *backupPath, created, error)) {
        PrintError("[unlock] " + ToUtf8(target.path) + ": cannot save backup: " + error);
        return {false, ExitCode::WindowsError};
    }

    if (!created) {
        std::optional<BackupRecord> backup = LoadBackup(*backupPath, error);
        if (!backup || !VerifyBackupMatchesTarget(*backup, target, error)) {
            PrintError("[unlock] " + ToUtf8(target.path) + ": existing backup is not valid: " + error);
            return {false, ExitCode::BackupError};
        }
    }

    std::wstring apiPath = ApiPath(target.path);
    DWORD result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        currentUserSid, nullptr, nullptr, nullptr);
    if (result != ERROR_SUCCESS) {
        PrintError("[unlock] " + ToUtf8(target.path) + ": cannot set owner: " + WindowsErrorMessage(result));
        return {false, ExitCode::WindowsError};
    }

    result = GrantCurrentUserFullControl(target, currentUserSid);
    if (result != ERROR_SUCCESS) {
        PrintError("[unlock] " + ToUtf8(target.path) + ": cannot grant full control: " +
                   WindowsErrorMessage(result));
        return {false, ExitCode::WindowsError};
    }

    Print("[unlock] " + ToUtf8(target.path) + ": ok, backup " +
          std::string(created ? "created" : "kept"));
    return {true, ExitCode::Success};
}

OperationResult RestoreTarget(const Target& target, const std::wstring& backupDir) {
    std::string error;
    std::optional<std::wstring> backupPath = BackupFilePath(backupDir, target.path, error);
    if (!backupPath) {
        PrintError("[restore] " + ToUtf8(target.path) + ": " + error);
        return {false, ExitCode::WindowsError};
    }

    if (!FileExists(*backupPath)) {
        PrintError("[restore] " + ToUtf8(target.path) + ": backup is missing");
        return {false, ExitCode::BackupError};
    }

    std::optional<BackupRecord> backup = LoadBackup(*backupPath, error);
    if (!backup || !VerifyBackupMatchesTarget(*backup, target, error)) {
        PrintError("[restore] " + ToUtf8(target.path) + ": invalid backup: " + error);
        return {false, ExitCode::BackupError};
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            backup->sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        PrintError("[restore] " + ToUtf8(target.path) + ": invalid backup SDDL: " +
                   WindowsErrorMessage(GetLastError()));
        return {false, ExitCode::BackupError};
    }
    LocalMemory descriptorMemory(reinterpret_cast<HLOCAL>(descriptor));

    PSID owner = nullptr;
    BOOL ownerDefaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &ownerDefaulted) || owner == nullptr) {
        PrintError("[restore] " + ToUtf8(target.path) + ": backup SDDL has no owner");
        return {false, ExitCode::BackupError};
    }

    PSID group = nullptr;
    BOOL groupDefaulted = FALSE;
    if (!GetSecurityDescriptorGroup(descriptor, &group, &groupDefaulted) || group == nullptr) {
        PrintError("[restore] " + ToUtf8(target.path) + ": backup SDDL has no group");
        return {false, ExitCode::BackupError};
    }

    PACL dacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl, &daclDefaulted) || !daclPresent) {
        PrintError("[restore] " + ToUtf8(target.path) + ": backup SDDL has no DACL");
        return {false, ExitCode::BackupError};
    }

    std::wstring apiPath = ApiPath(target.path);
    DWORD result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(apiPath.c_str()), SE_FILE_OBJECT, kSecurityInfo,
        owner, group, dacl, nullptr);
    if (result != ERROR_SUCCESS) {
        PrintError("[restore] " + ToUtf8(target.path) + ": " + WindowsErrorMessage(result));
        return {false, ExitCode::WindowsError};
    }

    Print("[restore] " + ToUtf8(target.path) + ": ok");
    return {true, ExitCode::Success};
}

bool IsDotOrDotDot(const wchar_t* name) {
    return wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0;
}

void CollectDirectoryChildren(
    const std::wstring& directory,
    std::vector<Target>& targets,
    std::vector<std::string>& warnings,
    std::vector<std::string>& errors) {
    std::wstring pattern = JoinPath(directory, L"*");
    std::wstring apiPattern = ApiPath(pattern);

    WIN32_FIND_DATAW data{};
    FindHandle find(FindFirstFileW(apiPattern.c_str(), &data));
    if (!find.valid()) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_NO_MORE_FILES) {
            errors.push_back("[enumerate] " + ToUtf8(directory) + ": " + WindowsErrorMessage(error));
        }
        return;
    }

    do {
        if (IsDotOrDotDot(data.cFileName)) {
            continue;
        }

        std::wstring child = JoinPath(directory, data.cFileName);
        if (IsReparsePoint(data.dwFileAttributes)) {
            warnings.push_back("[skip] reparse point: " + ToUtf8(child));
            continue;
        }

        bool isDirectory = IsDirectory(data.dwFileAttributes);
        targets.push_back(Target{child, isDirectory});
        if (isDirectory) {
            CollectDirectoryChildren(child, targets, warnings, errors);
        }
    } while (FindNextFileW(find.value, &data));

    DWORD lastError = GetLastError();
    if (lastError != ERROR_NO_MORE_FILES) {
        errors.push_back("[enumerate] " + ToUtf8(directory) + ": " + WindowsErrorMessage(lastError));
    }
}

std::optional<std::vector<Target>> CollectTargets(
    const std::wstring& inputPath,
    bool recursive,
    std::vector<std::string>& warnings,
    std::vector<std::string>& errors) {
    std::string error;
    std::optional<std::wstring> normalized = NormalizePath(inputPath, error);
    if (!normalized) {
        errors.push_back("[path] " + ToUtf8(inputPath) + ": " + error);
        return std::nullopt;
    }

    std::optional<DWORD> attributes = GetExistingAttributes(*normalized, error);
    if (!attributes) {
        errors.push_back("[path] " + ToUtf8(*normalized) + ": " + error);
        return std::nullopt;
    }

    std::vector<Target> targets;
    if (IsReparsePoint(*attributes)) {
        warnings.push_back("[skip] reparse point: " + ToUtf8(*normalized));
        return targets;
    }

    bool isDirectory = IsDirectory(*attributes);
    targets.push_back(Target{*normalized, isDirectory});
    if (recursive && isDirectory) {
        CollectDirectoryChildren(*normalized, targets, warnings, errors);
    }

    return targets;
}

ExitCode CombineExitCode(ExitCode current, ExitCode next) {
    if (current == ExitCode::BackupError || next == ExitCode::BackupError) {
        return ExitCode::BackupError;
    }
    if (current == ExitCode::WindowsError || next == ExitCode::WindowsError) {
        return ExitCode::WindowsError;
    }
    if (current == ExitCode::PrivilegeError || next == ExitCode::PrivilegeError) {
        return ExitCode::PrivilegeError;
    }
    if (current == ExitCode::BadArgs || next == ExitCode::BadArgs) {
        return ExitCode::BadArgs;
    }
    return ExitCode::Success;
}

ExitCode RunCommand(const Options& rawOptions) {
    Options options = rawOptions;

    std::string error;
    std::optional<std::wstring> normalizedBackupDir =
        NormalizePath(options.backupDir.empty() ? DefaultBackupDir() : options.backupDir, error);
    if (!normalizedBackupDir) {
        PrintError("Invalid backup directory: " + error);
        return ExitCode::BadArgs;
    }

    std::vector<std::string> warnings;
    std::vector<std::string> collectionErrors;
    std::optional<std::vector<Target>> maybeTargets =
        CollectTargets(options.path, options.recursive, warnings, collectionErrors);

    for (const std::string& warning : warnings) {
        PrintError(warning);
    }
    for (const std::string& collectionError : collectionErrors) {
        PrintError(collectionError);
    }

    if (!maybeTargets) {
        return ExitCode::WindowsError;
    }

    std::vector<Target> targets = *maybeTargets;
    if (targets.empty()) {
        return collectionErrors.empty() ? ExitCode::Success : ExitCode::WindowsError;
    }

    if (options.command != Command::Status && !options.forceSystem &&
        IsProtectedSystemPath(targets.front().path)) {
        PrintError("Refusing to modify a protected system path without --force-system: " +
                   ToUtf8(targets.front().path));
        return ExitCode::BadArgs;
    }

    if (options.command != Command::Status) {
        if (!IsElevated()) {
            PrintError("This command requires an elevated administrator token.");
            return ExitCode::PrivilegeError;
        }

        if (!EnableRequiredPrivileges(error)) {
            PrintError(error);
            return ExitCode::PrivilegeError;
        }
    }

    std::optional<std::vector<BYTE>> userSid;
    if (options.command == Command::Unlock) {
        userSid = CurrentUserSid(error);
        if (!userSid) {
            PrintError(error);
            return ExitCode::PrivilegeError;
        }
    }

    if (options.command == Command::Restore) {
        std::reverse(targets.begin(), targets.end());
    }

    ExitCode finalCode = collectionErrors.empty() ? ExitCode::Success : ExitCode::WindowsError;
    size_t okCount = 0;
    size_t failedCount = 0;

    for (const Target& target : targets) {
        OperationResult result;
        switch (options.command) {
        case Command::Status:
            result = PrintStatus(target, *normalizedBackupDir);
            break;
        case Command::Unlock:
            result = UnlockTarget(target, *normalizedBackupDir, userSid->data());
            break;
        case Command::Restore:
            result = RestoreTarget(target, *normalizedBackupDir);
            break;
        }

        if (result.ok) {
            ++okCount;
        } else {
            ++failedCount;
            finalCode = CombineExitCode(finalCode, result.code);
        }
    }

    Print("summary: command=" + CommandName(options.command) +
          " ok=" + std::to_string(okCount) +
          " failed=" + std::to_string(failedCount) +
          " backup_dir=" + ToUtf8(*normalizedBackupDir));

    return finalCode;
}

std::string Trim(std::string value) {
    size_t first = 0;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }

    size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }

    return value.substr(first, last - first);
}

std::string ReadMenuLine(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string input;
    if (!std::getline(std::cin, input)) {
        return {};
    }
    return Trim(input);
}

void WaitForMenuEnter() {
    std::cout << '\n' << "Press Enter to return to menu...";
    std::cout.flush();

    std::string ignored;
    std::getline(std::cin, ignored);
}

bool ConfirmProtectedSystemChange(const std::wstring& path) {
    PrintError("Protected system path selected:");
    PrintError("  " + ToUtf8(path));
    PrintError("Type YES to allow modifying it. Anything else cancels this action.");

    return ReadMenuLine("> ") == "YES";
}

std::optional<Options> BuildMenuAction(
    const std::string& choice,
    const std::wstring& normalizedPath,
    const std::wstring& backupDir,
    bool isDirectory) {
    Options action;
    action.path = normalizedPath;
    action.backupDir = backupDir;

    if (choice == "1") {
        action.command = Command::Status;
    } else if (choice == "2") {
        action.command = Command::Unlock;
    } else if (choice == "3") {
        action.command = Command::Restore;
    } else if (isDirectory && choice == "4") {
        action.command = Command::Status;
        action.recursive = true;
    } else if (isDirectory && choice == "5") {
        action.command = Command::Unlock;
        action.recursive = true;
    } else if (isDirectory && choice == "6") {
        action.command = Command::Restore;
        action.recursive = true;
    } else {
        return std::nullopt;
    }

    return action;
}

ExitCode RunInteractiveMenu(const Options& menuOptions) {
    std::string error;
    std::optional<std::wstring> normalizedPath = NormalizePath(menuOptions.path, error);
    if (!normalizedPath) {
        PrintError("[path] " + ToUtf8(menuOptions.path) + ": " + error);
        return ExitCode::WindowsError;
    }

    std::optional<DWORD> attributes = GetExistingAttributes(*normalizedPath, error);
    if (!attributes) {
        PrintError("[path] " + ToUtf8(*normalizedPath) + ": " + error);
        return ExitCode::WindowsError;
    }

    if (IsReparsePoint(*attributes)) {
        PrintError("[skip] reparse point: " + ToUtf8(*normalizedPath));
        return ExitCode::Success;
    }

    std::optional<std::wstring> normalizedBackupDir =
        NormalizePath(menuOptions.backupDir.empty() ? DefaultBackupDir() : menuOptions.backupDir, error);
    if (!normalizedBackupDir) {
        PrintError("Invalid backup directory: " + error);
        return ExitCode::BadArgs;
    }

    bool isDirectory = IsDirectory(*attributes);
    bool protectedSystemPath = IsProtectedSystemPath(*normalizedPath);
    ExitCode lastCode = ExitCode::Success;

    for (;;) {
        Print("");
        Print("AntiTrusted menu");
        Print("Path: " + ToUtf8(*normalizedPath));
        Print("Type: " + TargetTypeName(isDirectory));
        Print("Backup dir: " + ToUtf8(*normalizedBackupDir));
        Print("");
        Print("  1) Status");
        Print("  2) Unlock");
        Print("  3) Restore");
        if (isDirectory) {
            Print("  4) Status recursively");
            Print("  5) Unlock recursively");
            Print("  6) Restore recursively");
        }
        Print("  0) Exit");

        std::string choice = ReadMenuLine("> ");
        if (choice == "0" || choice == "q" || choice == "Q" || choice == "exit") {
            return lastCode;
        }

        std::optional<Options> action =
            BuildMenuAction(choice, *normalizedPath, *normalizedBackupDir, isDirectory);
        if (!action) {
            PrintError("Unknown menu item.");
            continue;
        }

        if (action->command != Command::Status && protectedSystemPath) {
            if (!ConfirmProtectedSystemChange(*normalizedPath)) {
                Print("Cancelled.");
                continue;
            }
            action->forceSystem = true;
        }

        Print("");
        lastCode = RunCommand(*action);
        WaitForMenuEnter();
    }
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    std::string error;
    std::optional<Options> options = ParseArgs(argc, argv, error);
    if (!options) {
        PrintError(error);
        PrintUsage();
        return static_cast<int>(ExitCode::BadArgs);
    }

    if (options->interactiveMenu) {
        return static_cast<int>(RunInteractiveMenu(*options));
    }

    return static_cast<int>(RunCommand(*options));
}
