package com.springKotlinAuthentication.demo.authentication.dto.request

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class ResetPasswordRequest(
    @field:Email(regexp = Constant.EMAIL_REGEX)
    @field:NotBlank(message = "Email is must not be blank")
    val email: String?,
) {
    constructor(): this(null)
}
