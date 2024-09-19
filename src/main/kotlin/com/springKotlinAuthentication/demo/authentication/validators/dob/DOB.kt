package com.springKotlinAuthentication.demo.authentication.validators.dob

import jakarta.validation.Constraint
import jakarta.validation.Payload
import kotlin.reflect.KClass


@MustBeDocumented
@Target(AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
@Constraint(validatedBy = [DOBValidator::class])
annotation class DateOfBirth(
    val message: String = "Invalid date of birth",
    val minimumAge: Int = 10,
    val groups: Array<KClass<*>> = [],
    val payload: Array<KClass<out Any>> = []
)
