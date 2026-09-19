// btclegacy/util/exit_codes.h
#pragma once
namespace btclegacy {
enum ExitCode : int {
    SUCCESS              = 0,
    GENERAL_ERROR        = 1,
    INVALID_ARGUMENT     = 2,
    FILE_NOT_FOUND       = 3,
    UNSUPPORTED_WALLET   = 4,
    CORRUPTED_WALLET     = 5,
    INCORRECT_PASSPHRASE = 6,
    PERMISSION_ERROR     = 7,
    MIGRATION_FAILED     = 8,
    USER_CANCELLED       = 9,
};
} // namespace btclegacy
