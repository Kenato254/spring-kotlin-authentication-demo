package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.ConfirmationTokenResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import java.time.LocalDate
import java.util.*

interface AuthenticationService {
    // Authentication
    fun registerUser(request: RegisterRequest): ConfirmationTokenResponse
    fun loginUser(request: LoginRequest): LoginResponse
    fun confirmUser(confirmationToken: String)
    fun forgotPassword(request: ResetPasswordRequest): ConfirmationTokenResponse
    fun resetPassword(request: PasswordRequest)
    fun changePassword(request: ChangePasswordRequest)
    // User Management
    fun readUserById(userId: UUID): UserResponse
    fun updateUserById(userId: UUID, request: UpdateUserRequest): UserResponse
    fun deleteUserById(userId: UUID): UserResponse
    fun listUsersByDob(dob: LocalDate): List<UserResponse>
    fun getAllUsers(): List<UserResponse>
}