package com.springKotlinAuthentication.demo.authentication.dto.response

import java.util.UUID

data class UserResponse(
    val id: UUID,
    val firstName: String,
    val lastName: String,
    val dob: String,
    val createdAt: String
)
