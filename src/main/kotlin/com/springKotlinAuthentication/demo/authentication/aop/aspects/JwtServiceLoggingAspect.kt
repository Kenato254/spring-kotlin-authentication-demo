package com.springKotlinAuthentication.demo.authentication.aop.aspects

import org.aspectj.lang.JoinPoint
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Before
import org.aspectj.lang.annotation.Pointcut
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class JwtServiceLoggingAspect {

    private val log = LoggerFactory.getLogger(this::class.java)

    @Pointcut(
        "execution(* com.springKotlinAuthentication." +
                "demo.authentication.jwt.service.JwtService.*(..))"
    )
    fun jwtServiceMethods() {
    }

    @Before("jwtServiceMethods()")
    fun logBeforeMethod(joinPoint: JoinPoint) {
        val methodName = joinPoint.signature.name
        val className = joinPoint.target.javaClass.simpleName
        log.info("Executing method: \"$methodName\" in class: \"$className\"")
    }
}