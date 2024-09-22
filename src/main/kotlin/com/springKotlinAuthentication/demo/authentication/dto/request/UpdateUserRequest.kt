package com.springKotlinAuthentication.demo.authentication.dto.request

import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.validators.dob.DateOfBirth
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.LocalDate

data class UpdateUserRequest(
    val firstName: String?,
    val lastName: String?,
    @field:Email(regexp = Constant.EMAIL_REGEX)
    val email: String?,
    val dateOfBirth: LocalDate?
)
