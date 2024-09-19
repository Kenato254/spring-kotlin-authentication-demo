package com.springKotlinAuthentication.demo.authentication.validators.dob

import jakarta.validation.ConstraintValidator
import jakarta.validation.ConstraintValidatorContext
import org.springframework.stereotype.Component
import java.time.LocalDate

open class DOBValidator : ConstraintValidator<DateOfBirth, LocalDate?> {
    private var minimumAge = 0
    private var message: String? = null


    override fun initialize(constraintAnnotation: DateOfBirth) {
        this.minimumAge = constraintAnnotation.minimumAge
        this.message = constraintAnnotation.message
    }

    override fun isValid(dateOfBirth: LocalDate?, context: ConstraintValidatorContext): Boolean {
        if (dateOfBirth == null) {
            message = "Date of birth cannot be blank or null"
            context.disableDefaultConstraintViolation()
            context.buildConstraintViolationWithTemplate(message)
                .addConstraintViolation()
            return false
        }

        val today = LocalDate.now()
        if (dateOfBirth.isAfter(today)) {
            message = "Date of birth cannot be in the future"
            context.disableDefaultConstraintViolation()
            context.buildConstraintViolationWithTemplate(message)
                .addConstraintViolation()
            return false
        }

        val age = today.year - dateOfBirth.year
        if (age < minimumAge) {
            message = "User must be at least $minimumAge years old"
            context.disableDefaultConstraintViolation()
            context.buildConstraintViolationWithTemplate(message)
                .addConstraintViolation()

            return false
        }
        return true
    }
}
