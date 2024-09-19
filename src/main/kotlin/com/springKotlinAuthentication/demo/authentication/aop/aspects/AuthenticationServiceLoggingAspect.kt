package com.springKotlinAuthentication.demo.authentication.aop.aspects

import com.springKotlinAuthentication.demo.authentication.entity.User
import org.aspectj.lang.JoinPoint
import org.aspectj.lang.annotation.After
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Before
import org.aspectj.lang.annotation.Pointcut
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class AuthenticationServiceLoggingAspect {

    private val log = LoggerFactory.getLogger(this::class.java)

    @Pointcut(
        "execution(* com.springKotlinAuthentication.demo.authentication." +
                "service.AuthenticationService.*(..))"
    )
    fun authenticationServiceMethods() {
    }

    @Before("authenticationServiceMethods()")
    fun logBeforeMethod(joinPoint: JoinPoint) {
        val methodName = joinPoint.signature.name
        val className = joinPoint.target.javaClass.simpleName
        log.info("Executing method: \"$methodName\" in class: \"$className\"")
    }

    @After("userServiceMethods() && args(user)")
    fun logAfterMethod(joinPoint: JoinPoint, user: User) {
        val methodName = joinPoint.signature.name
        log.info("Method: \"$methodName\" executed with User entity: $user")
    }
}
