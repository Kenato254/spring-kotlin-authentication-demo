package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.entity.User
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.junit5.MockKExtension
import io.mockk.verify
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.test.context.ActiveProfiles
import java.time.LocalDate
import java.util.*
import kotlin.test.assertFailsWith

@ActiveProfiles("test")
@ExtendWith(MockKExtension::class)
class UserServiceImplTest {
    private lateinit var userService: UserService

    @MockK
    private lateinit var userRepository: UserRepository

    @BeforeEach
    fun setUp() {
        userService = UserServiceImpl(userRepository)
    }

    @Test
    fun `readUserById should return user response when user is found`() {
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
        val result = userService.readUserById(userId)

        kotlin.test.assertEquals(userResponse, result)
        verify { userRepository.findById(userId) }
    }

    @Test
    fun `readUserById should throw UsernameNotFoundException when user not found`() {
        val userId = UUID.randomUUID()
        every { userRepository.findById(userId) } returns Optional.empty()

        assertFailsWith<UsernameNotFoundException> {
            userService.readUserById(userId)
        }
    }
}