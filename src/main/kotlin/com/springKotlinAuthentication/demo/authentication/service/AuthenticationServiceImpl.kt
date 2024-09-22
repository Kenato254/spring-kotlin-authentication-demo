package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.UserUtil
import com.springKotlinAuthentication.demo.authentication.authorization.Role
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.ForbiddenAccessException
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
    override fun readUserById(userId: UUID, accessToken: String): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication?.principal !is User) {
            throw UnauthenticatedUserException(Constant.AUTH_USER_NOT_AUTHENTICATED)
        }
        val userRequesting = authentication.principal as User

        if (userRequesting != user && userRequesting.role != Role.ADMIN) {
            throw ForbiddenAccessException(
                String.format(Constant.AUTH_ACCESS_DENIED, userRequesting.email)
            )
        }
        return UserUtil.userToUserResponse(user)
    }

    override fun updateUserById(userId: UUID, request: UpdateUserRequest, accessToken: String): UserResponse {
        TODO("Not yet implemented")
    }

    override fun deleteUserById(userId: UUID, accessToken: String): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication?.principal !is User) {
            throw UnauthenticatedUserException(Constant.AUTH_USER_NOT_AUTHENTICATED)
        }
        val userRequesting = authentication.principal as User

        if (userRequesting != user && userRequesting.role != Role.ADMIN) {
            throw ForbiddenAccessException(
                String.format(Constant.AUTH_ACCESS_DENIED, userRequesting.email)
            )
        }

        userRepository.delete(user)
        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun registerUser(request: RegisterRequest): RegisterResponse {
        val email = request.email
        if (userRepository.emailExists(email!!)) {
            throw UserAlreadyExistsException(
                String.format(Constant.USER_ALREADY_EXISTS, email)
            )
        }

        val passwordHash = User.encryptPassword(request.password!!)

        val user = userRepository.save(
            User(
                email = email,
                password = passwordHash,
                firstName = request.firstName!!,
                lastName = request.lastName!!,
                dateOfBirth = request.dateOfBirth!!
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
        if (!user.checkPassword(request.oldPassword)) {
            throw IllegalStateException(Constant.INVALID_OLD_PASSWORD)
        }
        if (!request.isPasswordConfirmed()) {
            throw IllegalStateException(Constant.PASSWORD_MISMATCH)
        }
        user.password = request.newPassword

        userRepository.save(user)
        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun loginUser(request: LoginRequest): LoginResponse {
        val user =
            customUserDetailService.loadUserByUsername(request.email) as User

        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(request.email, request.password)
        )
        SecurityContextHolder.getContext().authentication = authentication

        val claims = mapOf("role" to user.role)
        val accessToken = jwtService.generateToken(claims, user)
        val expiresIn = jwtService.expiresIn
        val tokenType = jwtService.tokenType
        jwtService.revokeAllTokenByUser(user)
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

        val user = userRepository.findById(token.user.id!!)
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