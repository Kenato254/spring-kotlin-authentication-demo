package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.UserUtil
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UnauthenticatedUserException
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UserAlreadyExistsException
import com.springKotlinAuthentication.demo.authentication.jwt.service.JwtService
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import jakarta.persistence.EntityNotFoundException
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

    @Transactional(readOnly = true)
    override fun readUserById(userId: UUID): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun updateUserById(userId: UUID, request: UpdateUserRequest): UserResponse {
        TODO("Not yet implemented")
    }

    @Transactional
    override fun deleteUserById(userId: UUID): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        userRepository.delete(user)
        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun registerUser(request: RegisterRequest): RegisterResponse {
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
        val savedConfirmationToken = confirmationTokenService.saveConfirmationToken(confirmationToken)

        // Send Email
        return UserUtil.confirmationTokenToRegisterResponse(
            savedConfirmationToken
        )
    }

    @Transactional
    override fun resetPassword(request: ResetPasswordRequest): UserResponse {
        TODO("Not yet implemented")
    }

    @Transactional
    override fun changePassword(accessToken: String, request: ChangePasswordRequest): UserResponse {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication?.principal !is User) {
            throw UnauthenticatedUserException(Constant.AUTH_USER_NOT_AUTHENTICATED)
        }

        val user = authentication.principal as User

        requireNotNull(request.oldPassword) { "Old password must not be null" }
        if (!user.checkPassword(request.oldPassword)) {
            throw IllegalStateException(Constant.INVALID_OLD_PASSWORD)
        }

        if (!request.isPasswordConfirmed()) {
            throw IllegalStateException(Constant.PASSWORD_MISMATCH)
        }

        user.password = requireNotNull(request.newPassword) { "New password must not be null" }

        userRepository.save(user)
        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun loginUser(request: LoginRequest): LoginResponse {
        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(request.email, request.password)
        )

        if (!authentication.isAuthenticated) {
            throw UnauthenticatedUserException(Constant.AUTHENTICATION_FAILED)
        }

        SecurityContextHolder.getContext().authentication = authentication

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

        if (token.expiresAt.isBefore(Instant.now())) {
            throw IllegalStateException(Constant.CONFIRMATION_TOKEN_EXPIRED)
        }

        if (token.confirmedAt != null) {
            throw IllegalStateException(Constant.CONFIRMATION_TOKEN_ALREADY_CONFIRMED)
        }

        val userId = requireNotNull(token.user.id) { "User id must not be null" }
        val user = userRepository.findById(userId)
            .orElseThrow {
                EntityNotFoundException(String.format(Constant.USER_NOT_FOUND, token.user.id))
            }

        if (!user.enabled) {
            user.enabled = true
            userRepository.save(user)
        }

        token.confirmedAt = Instant.now()
        confirmationTokenService.saveConfirmationToken(token)
    }

    @Transactional(readOnly = true)
    override fun getAllUsers(accessToken: String): List<UserResponse> {
        val sort = Sort.by(Sort.Direction.DESC, "createdAt")
        return userRepository.findAll(sort)
            .map { user -> UserUtil.userToUserResponse(user) }
    }

    @Transactional(readOnly = true)
    override fun listUsersByDob(dob: LocalDate): List<UserResponse> {
        return userRepository.findByDob(dob)
            .map { user -> UserUtil.userToUserResponse(user) }
    }
}