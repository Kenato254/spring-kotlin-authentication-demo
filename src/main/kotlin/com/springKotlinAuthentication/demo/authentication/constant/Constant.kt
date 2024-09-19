package com.springKotlinAuthentication.demo.authentication.constant


object Constant {
    const val EMAIL_REGEX = "^[a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}\$"

    // JWT Token Errors
    const val JWT_MALFORMED = "The JWT token is malformed."
    const val JWT_EXPIRED = "The JWT token has expired."
    const val JWT_UNSUPPORTED = "The JWT token type is unsupported."

    // Authentication Errors
    const val AUTH_USER_NOT_AUTHENTICATED = "User authentication required."
    const val AUTH_ACCESS_DENIED = "Access denied for this [%s]."
    const val AUTH_ACCOUNT_DISABLED = "Your account has been disabled and is not yet activated. " +
            "Please check your email for activation instructions or contact support if you believe this is a mistake."

    // General Errors
    const val ERROR_INTERNAL_SERVER = "An unexpected error occurred on the server."
    const val ERROR_BAD_REQUEST = "Invalid request or credentials."
    const val ENTITY_NOT_FOUND = "Entity not found"

    // User-Related Errors
    const val USER_NOT_FOUND = "User with this [%s] not found."
    const val USER_ALREADY_EXISTS = "A user with this [%s] already exists."
    const val PASSWORD_MISMATCH = "New password and confirmation do not match."
    const val INVALID_OLD_PASSWORD = "The old password entered is incorrect."
    const val ILLEGAL_STATE = "The operation cannot be performed due to an invalid object state."

    // Confirmation Token Errors
    const val CONFIRMATION_TOKEN_NOT_FOUND = "Confirmation token not found"
    const val CONFIRMATION_TOKEN_EXPIRED = "Confirmation token has expired"
    const val CONFIRMATION_TOKEN_ALREADY_CONFIRMED = "Confirmation token already confirmed"
}