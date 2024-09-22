package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import java.time.LocalDate
import java.util.*

interface AuthenticationService {
    fun registerUser(request: RegisterRequest): RegisterResponse
    fun loginUser(request: LoginRequest): LoginResponse
    fun confirmUser(confirmationToken: String)
    fun readUserById(userId: UUID, accessToken: String): UserResponse
    fun updateUserById(userId: UUID, request: UpdateUserRequest, accessToken: String): UserResponse
    fun deleteUserById(userId: UUID, accessToken: String): UserResponse
    fun resetPassword(request: ResetPasswordRequest): UserResponse
    fun changePassword(accessToken: String, request: ChangePasswordRequest): UserResponse
    fun listUsersByDob(dob: LocalDate): List<UserResponse>
    fun getAllUsers(accessToken: String): List<UserResponse>
}