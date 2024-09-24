package com.springKotlinAuthentication.demo.authentication

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.dto.response.ConfirmationTokenResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import com.springKotlinAuthentication.demo.authentication.service.ConfirmationTokenService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import java.time.Instant


object UserUtil {
    fun userToUserResponse(
        user: User
    ): UserResponse {
        return UserResponse(
            id = user.id!!,
            firstName = user.firstName,
            lastName = user.lastName,
            dob = user.dateOfBirth.toString(),
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

    fun confirmationTokenToResponse(
        confirmationToken: ConfirmationToken
    ): ConfirmationTokenResponse {
        return ConfirmationTokenResponse(
            token = confirmationToken.token
        )
    }

    fun validateConfirmationToken(
        token: ConfirmationToken,
        userRepository: UserRepository,
        confirmationTokenService: ConfirmationTokenService

    ): User {
        if (token.expiresAt.isBefore(Instant.now())) {
            throw IllegalStateException(Constant.CONFIRMATION_TOKEN_EXPIRED)
        }

        if (token.confirmedAt != null) {
            throw IllegalStateException(Constant.CONFIRMATION_TOKEN_ALREADY_CONFIRMED)
        }

        val userId = requireNotNull(token.user.id) { "User id must not be null" }
        val user = userRepository.findById(userId)
            .orElseThrow {
                UsernameNotFoundException(
                    String.format(Constant.USER_NOT_FOUND, token.user.id)
                )
            }

        if (!user.enabled) {
            user.enabled = true
            userRepository.save(user)
        }

        token.confirmedAt = Instant.now()
        confirmationTokenService.saveConfirmationToken(token)

        return user
    }
}