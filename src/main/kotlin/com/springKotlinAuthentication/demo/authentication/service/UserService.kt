package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.dto.request.UpdateUserRequest
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import java.time.LocalDate
import java.util.*

interface UserService {
    fun readUserById(userId: UUID): UserResponse
    fun updateUserById(userId: UUID, request: UpdateUserRequest): UserResponse
    fun deleteUserById(userId: UUID): UserResponse
    fun listUsersByDob(dob: LocalDate): List<UserResponse>
    fun retrieveAllUsers(): List<UserResponse>
}