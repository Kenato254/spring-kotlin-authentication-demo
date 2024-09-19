package com.springKotlinAuthentication.demo.authentication.dto.response

data class LoginResponse(
    val accessToken: String,
    val tokenType: String,
    val expiresIn: Long,
    val refreshToken: String,
)
