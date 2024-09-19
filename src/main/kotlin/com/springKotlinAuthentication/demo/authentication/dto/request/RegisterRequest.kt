package com.springKotlinAuthentication.demo.authentication.dto.request

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.validators.dob.DateOfBirth
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.LocalDate

data class RegisterRequest(
    @field:NotBlank(message = "FirstName can not be blank")
    val firstName: String?,

    @field:NotBlank(message = "LastName can not be blank")
    val lastName: String?,

    @field:Email(regexp = Constant.EMAIL_REGEX)
    @field:NotBlank(message = "Email is can not be blank")
    val email: String?,

    @field:NotBlank(message = "Password can not be blank")
    @field:Size(
        min = 8,
        max = 128,
        message = "New password must be at least {min} characters long"
    ) val password: String?,

    @field:DateOfBirth
    val dateOfBirth: LocalDate?
)
