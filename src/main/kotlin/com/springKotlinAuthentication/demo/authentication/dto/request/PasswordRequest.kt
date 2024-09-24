package com.springKotlinAuthentication.demo.authentication.dto.request

import jakarta.validation.constraints.NotBlank

data class PasswordRequest(
    @field:NotBlank(message = "Token must not be blank")
    val token: String?,

    @field:NotBlank(message = "Password must not be blank")
    val password: String?,

    @field:NotBlank(message = "Confirm password must not be blank")
    val confirmPassword: String?
) {
    fun isPasswordConfirmed(): Boolean = password == confirmPassword
}
