package com.springKotlinAuthentication.demo.authentication.aop.aspects

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import jakarta.persistence.EntityNotFoundException
import org.aspectj.lang.annotation.AfterThrowing
import org.aspectj.lang.annotation.Aspect
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class JwtFilterLoggingAspect {

    private val log: Logger = LoggerFactory.getLogger(this::class.java)

    @AfterThrowing(
        pointcut = "execution(* com.springKotlinAuthentication.demo.authentication.jwt.service.filter.JwtAuthenticationFilter.doFilterInternal(..))",
        throwing = "exception"
    )
    fun logExceptions(exception: Exception) {
        when (exception) {
            is ExpiredJwtException -> log.error("Jwt token is Expired: {}", exception.message)
            is MalformedJwtException -> log.error("Jwt token is  Malformed: {}", exception.message)
            is EntityNotFoundException -> log.error("Entity not found: {}", exception.message)
            is UnsupportedJwtException -> log.error("Unsupported JWT token: {}", exception.message)
            is IllegalArgumentException -> log.error("JWT token not found: {}", exception.message)
            else -> log.error("An unexpected error occurred: {}", exception.message)
        }
    }
}
