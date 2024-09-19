package com.springKotlinAuthentication.demo.authentication.dto.request

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class LoginRequest(
    @field:Email(regexp = Constant.EMAIL_REGEX)
    @field:NotBlank(message = "Email can not be blank")
    val email: String?,

    @field:NotBlank(message = "Password can not be blank")
    val password: String?
)
