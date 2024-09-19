package com.springKotlinAuthentication.demo.authentication

import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User


object UserUtil {
    fun userToUserResponse(
        user: User
    ): UserResponse {
        return UserResponse(
            id = user.id!!,
            firstName = user.firstName,
            lastName = user.lastName,
            dob = user.dataOfBirth.toString(),
            createdAt = user.createdAt.toString()
        )
    }

    fun tokensToLoginResponse(
        expiresIn: Long?,
        tokenType: String?,
        accessToken: String?,
        refreshToken: String?
    ): LoginResponse {
        return LoginResponse(
            accessToken ?: "No access token provided",
            tokenType ?: "No type provided",
            expiresIn ?: 0,
            refreshToken ?: "No refresh token provided"
        )
    }

    fun confirmationTokenToRegisterResponse(
        confirmationToken: ConfirmationToken
    ): RegisterResponse {
        return RegisterResponse(
            confirmationToken = confirmationToken.token
        )
    }
}