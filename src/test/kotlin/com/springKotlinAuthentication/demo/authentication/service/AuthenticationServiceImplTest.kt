package com.springKotlinAuthentication.demo.authentication.service


import com.springKotlinAuthentication.demo.authentication.UserUtil
import com.springKotlinAuthentication.demo.authentication.dto.request.ChangePasswordRequest
import com.springKotlinAuthentication.demo.authentication.dto.request.LoginRequest
import com.springKotlinAuthentication.demo.authentication.dto.request.RegisterRequest
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.ConfirmationToken
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UnauthenticatedUserException
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UserAlreadyExistsException
import com.springKotlinAuthentication.demo.authentication.jwt.service.JwtService
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AuthenticationServiceImplTest {

    private lateinit var authenticationService: AuthenticationServiceImpl

    private val jwtService: JwtService = mockk()
    private val userRepository: UserRepository = mockk()
    private val authenticationManager: AuthenticationManager = mockk()
    private val customUserDetailService: CustomUserDetailService = mockk()
    private val confirmationTokenService: ConfirmationTokenService = mockk()

    @BeforeEach
    fun setUp() {
        authenticationService = AuthenticationServiceImpl(
            jwtService,
            userRepository,
            authenticationManager,
            customUserDetailService,
            confirmationTokenService
        )
    }

    @Test
    fun `readUserById should return user response when user is found and authenticated`() {
        val userId = UUID.randomUUID()
        val user = User(
            id = userId,
            email = "test@example.com",
            password = "password",
            firstName = "Test",
            lastName = "User",
            dateOfBirth = LocalDate.of(2000, 1, 1),
        )
        val userResponse = UserResponse(
            userId,
            user.firstName,
            user.lastName,
            user.dateOfBirth.toString(),
            user.createdAt.toString()
        )

        every { userRepository.findById(userId) } returns Optional.of(user)
        val authentication = mockk<Authentication> {
            every { principal } returns user
        }
        SecurityContextHolder.getContext().authentication = authentication

        val result = authenticationService.readUserById(userId, "accessToken")

        assertEquals(userResponse, result)
        verify { userRepository.findById(userId) }
    }

    @Test
    fun `readUserById should throw UnauthenticatedUserException when not authenticated`() {
        val userId = UUID.randomUUID()
        every { userRepository.findById(userId) } returns Optional.of(
            User(
                email = "test@example.com",
                password = "password",
                firstName = "Test",
                lastName = "User",
                dateOfBirth = LocalDate.of(2000, 1, 1),
            )
        )

        assertFailsWith<UnauthenticatedUserException> {
            authenticationService.readUserById(userId, "accessToken")
        }
    }

    @Test
    fun `registerUser should return confirmation token response when registration is successful`() {
        val registerRequest = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "password123",
            dateOfBirth = LocalDate.of(1990, 1, 1)
        )

        val user = User(
            email = registerRequest.email!!,
            password = User.encryptPassword(registerRequest.password!!),
            firstName = registerRequest.firstName!!,
            lastName = registerRequest.lastName!!,
            dateOfBirth = registerRequest.dateOfBirth!!
        )

        val expectedToken = "a7b39e2e-2370-414c-b6f1-d2faf06b57c6"
        mockkStatic(UUID::class)
        every { UUID.randomUUID().toString() } returns expectedToken

        val confirmationToken = ConfirmationToken(
            token = expectedToken,
            user = user,
            expiresAt = Instant.now().plus(10, ChronoUnit.MINUTES)
        )

        every { userRepository.emailExists(registerRequest.email!!) } returns false
        every { userRepository.save(any()) } returns user
        every { confirmationTokenService.saveConfirmationToken(any()) } returns confirmationToken

        val result = authenticationService.registerUser(registerRequest)

        assertEquals(expectedToken, result.confirmationToken)
        verify {
            userRepository.emailExists(registerRequest.email!!)
            userRepository.save(any())
            confirmationTokenService.saveConfirmationToken(any())
        }
    }


    @Test
    fun `registerUser should throw UserAlreadyExistsException when email already exists`() {
        val registerRequest = RegisterRequest(
            firstName = "John",
            lastName = "Doe",
            email = "john.doe@example.com",
            password = "password123",
            dateOfBirth = LocalDate.of(1990, 1, 1)
        )

        every { userRepository.emailExists(registerRequest.email!!) } returns true

        assertFailsWith<UserAlreadyExistsException> {
            authenticationService.registerUser(registerRequest)
        }
    }

    @Test
    fun `changePassword should change the password and return UserResponse when old password matches`() {
        val request = ChangePasswordRequest(
            oldPassword = "oldPassword123",
            newPassword = "newPassword123",
            confirmNewPassword = "newPassword123"
        )

        val user = mockk<User>(relaxed = true)
        every { user.checkPassword("oldPassword123") } returns true
        every { userRepository.save(user) } returns user
        every { user.password = request.newPassword } just Runs

        val authentication = mockk<Authentication> {
            every { principal } returns user
        }
        SecurityContextHolder.getContext().authentication = authentication

        val userResponse = mockk<UserResponse>()
        mockkObject(UserUtil)
        every { UserUtil.userToUserResponse(user) } returns userResponse

        val result = authenticationService.changePassword("accessToken", request)

        assertEquals(userResponse, result)
        verify { userRepository.save(user) }
    }

    @Test
    fun `changePassword should throw UnauthenticatedUserException when not authenticated`() {
        val request = ChangePasswordRequest(
            oldPassword = "oldPassword123",
            newPassword = "newPassword123",
            confirmNewPassword = "newPassword123"
        )
        val authentication = null
        SecurityContextHolder.getContext().authentication = authentication

        assertFailsWith<UnauthenticatedUserException> {
            authenticationService.changePassword("accessToken", request)
        }
    }

    @Test
    fun `changePassword should throw IllegalStateException when old password is invalid`() {
        val request = ChangePasswordRequest(
            oldPassword = "invalidPassword",
            newPassword = "newPassword123",
            confirmNewPassword = "newPassword123"
        )

        val user = mockk<User>(relaxed = true)
        every { user.checkPassword("invalidPassword") } returns false

        val authentication = mockk<Authentication> {
            every { principal } returns user
        }
        SecurityContextHolder.getContext().authentication = authentication

        assertFailsWith<IllegalStateException> {
            authenticationService.changePassword("accessToken", request)
        }
    }

    @Test
    fun `loginUser should return LoginResponse when authentication is successful`() {
        val request = LoginRequest(email = "john.doe@example.com", password = "password123")

        val user = mockk<User>(relaxed = true)
        every { customUserDetailService.loadUserByUsername(request.email) } returns user

        val authentication = mockk<Authentication>()
        every { authenticationManager.authenticate(any()) } returns authentication
        SecurityContextHolder.getContext().authentication = authentication

        val claims = mapOf("role" to user.role)
        val accessToken = "accessToken"
        val refreshToken = "refreshToken"
        every { jwtService.generateToken(claims, user) } returns accessToken
        every { jwtService.expiresIn } returns 3600
        every { jwtService.tokenType } returns "Bearer"
        every { jwtService.generateRefreshToken(claims, user) } returns refreshToken
        every { jwtService.saveRefreshToken(user, refreshToken) } just Runs
        every { jwtService.revokeAllTokenByUser(user) } just Runs

        val loginResponse = mockk<LoginResponse>()
        mockkObject(UserUtil)
        every { UserUtil.tokensToLoginResponse(3600, "Bearer", accessToken, refreshToken) } returns loginResponse

        val result = authenticationService.loginUser(request)

        assertEquals(loginResponse, result)
        verify {
            customUserDetailService.loadUserByUsername(request.email)
            authenticationManager.authenticate(any())
            jwtService.generateToken(claims, user)
            jwtService.generateRefreshToken(claims, user)
            jwtService.saveRefreshToken(user, refreshToken)
        }
    }

    @Test
    fun `loginUser should throw IllegalStateException when refreshToken is null`() {
        val request = LoginRequest(email = "john.doe@example.com", password = "password123")

        val user = mockk<User>(relaxed = true)
        every { customUserDetailService.loadUserByUsername(request.email) } returns user

        val authentication = mockk<Authentication>()
        every { authenticationManager.authenticate(any()) } returns authentication
        SecurityContextHolder.getContext().authentication = authentication

        val claims = mapOf("role" to user.role)
        every { jwtService.generateToken(claims, user) } returns "accessToken"
        every { jwtService.expiresIn } returns 3600
        every { jwtService.tokenType } returns "Bearer"
        every { jwtService.revokeAllTokenByUser(user) } just Runs
        every { jwtService.generateRefreshToken(claims, user) } returns null

        assertFailsWith<IllegalStateException> {
            authenticationService.loginUser(request)
        }
    }

    @Test
    fun `confirmUser should confirm token and enable user when token is valid and not already confirmed`() {
        val confirmationToken = mockk<ConfirmationToken>(relaxed = true)
        every { confirmationToken.expiresAt } returns Instant.now().plusSeconds(60)
        every { confirmationToken.confirmedAt } returns null

        val user = mockk<User>(relaxed = true)
        every { confirmationToken.user } returns user
        every { user.enabled } returns false
        every { userRepository.findById(user.id!!) } returns Optional.of(user)

        every { confirmationTokenService.getConfirmationByToken(any()) } returns confirmationToken
        every { userRepository.save(user) } returns user
        every { confirmationTokenService.saveConfirmationToken(confirmationToken) } returns confirmationToken

        authenticationService.confirmUser("validToken")

        verify {
            userRepository.save(user)
            confirmationTokenService.saveConfirmationToken(confirmationToken)
        }
    }

    @Test
    fun `confirmUser should throw IllegalStateException when token is expired`() {
        val confirmationToken = mockk<ConfirmationToken>(relaxed = true)
        every { confirmationToken.expiresAt } returns Instant.now().minusSeconds(60)

        every { confirmationTokenService.getConfirmationByToken(any()) } returns confirmationToken

        assertFailsWith<IllegalStateException> {
            authenticationService.confirmUser("expiredToken")
        }
    }

    @Test
    fun `confirmUser should throw IllegalStateException when token is already confirmed`() {
        val confirmationToken = mockk<ConfirmationToken>(relaxed = true)
        every { confirmationToken.confirmedAt } returns Instant.now()

        every { confirmationTokenService.getConfirmationByToken(any()) } returns confirmationToken

        assertFailsWith<IllegalStateException> {
            authenticationService.confirmUser("alreadyConfirmedToken")
        }
    }
}
