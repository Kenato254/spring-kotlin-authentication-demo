package com.springKotlinAuthentication.demo.authentication.dto.request

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

data class ChangePasswordRequest(
    @field:NotBlank(message = "Old password cannot be blank")
    val oldPassword: String,

    @field:NotBlank(message = "New password cannot be blank")
    @field:Size(
        min = 8,
        max = 128,
        message = "New password must be at least {min} characters long"
    ) val newPassword: String,


    @field:NotBlank(message = "Confirm new password cannot be blank")
    @field:Size(
        min = 8,
        max = 128,
        message = "New password must be at least {min} characters long"
    ) val confirmNewPassword: String
) {
    fun isPasswordConfirmed(): Boolean = newPassword == confirmNewPassword
}
