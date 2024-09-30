package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.UserUtil
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.ConfirmationTokenResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UnauthenticatedUserException
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UserAlreadyExistsException
import com.springKotlinAuthentication.demo.authentication.jwt.service.JwtService
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import org.springframework.data.domain.Sort
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.*

@Service
class AuthenticationServiceImpl(
    private val jwtService: JwtService,
    private val userRepository: UserRepository,
    private val authenticationManager: AuthenticationManager,
    private val customUserDetailService: CustomUserDetailService,
    private val confirmationTokenService: ConfirmationTokenService
) : AuthenticationService {

    @Transactional
    override fun registerUser(request: RegisterRequest): ConfirmationTokenResponse {
        val email = requireNotNull(request.email) { "Email must not be null" }
        if (userRepository.emailExists(email)) {
            throw UserAlreadyExistsException(
                String.format(Constant.USER_ALREADY_EXISTS, email)
            )
        }

        requireNotNull(request.password) { "Password must not be null" }
        val passwordHash = User.encryptPassword(request.password)

        val user = userRepository.save(
            User(
                email = email,
                password = passwordHash,
                firstName = requireNotNull(request.firstName) { "First name must not be null" },
                lastName = requireNotNull(request.lastName) { "Last name must not be null" },
                dateOfBirth = requireNotNull(request.dateOfBirth) { "Date of birth must not be null" }
            )
        )

        val confirmationToken = ConfirmationToken(
            token = UUID.randomUUID().toString(),
            user = user,
            expiresAt = Instant.now().plus(10, ChronoUnit.MINUTES),
        )
        val savedConfirmationToken =
            confirmationTokenService.saveConfirmationToken(confirmationToken)

        // Send Email
        return UserUtil.confirmationTokenToResponse(
            savedConfirmationToken
        )
    }

    @Transactional
    override fun loginUser(request: LoginRequest): LoginResponse {
        if (
            !userRepository.emailExists(
                requireNotNull(request.email) { "Email must not be null" })
        ) {
            throw UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, request.email))
        }
        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(request.email, request.password)
        )

        if (!authentication.isAuthenticated) {
            throw UnauthenticatedUserException(Constant.AUTHENTICATION_FAILED)
        }

        val principal = authentication.principal as org.springframework.security.core.userdetails.User
        val user = userRepository.findByEmail(principal.username)
            ?: throw UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, principal.username))

        val claims = mapOf("roles" to user.role)
        val accessToken = jwtService.generateToken(claims, user)
        val expiresIn = jwtService.expiresIn
        val tokenType = jwtService.tokenType
        val refreshToken = jwtService.generateRefreshToken(claims, user)
            ?: throw IllegalStateException(Constant.ILLEGAL_STATE)

        jwtService.saveRefreshToken(user, refreshToken)
        return UserUtil.tokensToLoginResponse(expiresIn, tokenType, accessToken, refreshToken)
    }

    @Transactional
    override fun confirmUser(confirmationToken: String) {
        val token = confirmationTokenService.getConfirmationByToken(confirmationToken)
        UserUtil.validateConfirmationToken(
            token,
            userRepository,
            confirmationTokenService
        )
    }

    override fun forgotPassword(request: ResetPasswordRequest): ConfirmationTokenResponse {
        val user = userRepository.findByEmail(
            requireNotNull(request.email) { "Email must not be null" }
        ) ?: throw UsernameNotFoundException(
            String.format(Constant.USER_NOT_FOUND, request.email)
        )

        val confirmationToken = ConfirmationToken(
            token = UUID.randomUUID().toString(),
            user = user,
            expiresAt = Instant.now().plus(10, ChronoUnit.MINUTES),
        )
        val savedConfirmationToken =
            confirmationTokenService.saveConfirmationToken(confirmationToken)

        // Send Email
        return UserUtil.confirmationTokenToResponse(savedConfirmationToken)
    }

    @Transactional
    override fun resetPassword(request: PasswordRequest) {
        val token = confirmationTokenService.getConfirmationByToken(
            requireNotNull(request.token) { "Token must not be blank" }
        )
        val user = UserUtil.validateConfirmationToken(
            token,
            userRepository,
            confirmationTokenService
        )

        if (!request.isPasswordConfirmed()) {
            throw IllegalStateException(Constant.PASSWORD_MISMATCH)
        }

        user.password = requireNotNull(request.password) { "Password must not be null" }
        userRepository.save(user)
    }

    @Transactional
    override fun changePassword(request: ChangePasswordRequest) {
        val authentication = SecurityContextHolder.getContext().authentication

        if (!authentication.isAuthenticated) {
            throw UnauthenticatedUserException(Constant.AUTH_USER_NOT_AUTHENTICATED)
        }
        val principal = authentication.principal
                as org.springframework.security.core.userdetails.User

        val user = userRepository.findByEmail(principal.username)
            ?: throw UsernameNotFoundException(
                String.format(Constant.USER_NOT_FOUND, principal.username)
            )

        requireNotNull(request.oldPassword) { "Old password must not be null" }
        if (!user.checkPassword(request.oldPassword)) {
            throw IllegalStateException(Constant.INVALID_OLD_PASSWORD)
        }

        if (!request.isPasswordConfirmed()) {
            throw IllegalStateException(Constant.PASSWORD_MISMATCH)
        }

        user.password = requireNotNull(request.newPassword) { "New password must not be null" }
        userRepository.save(user)
    }

}