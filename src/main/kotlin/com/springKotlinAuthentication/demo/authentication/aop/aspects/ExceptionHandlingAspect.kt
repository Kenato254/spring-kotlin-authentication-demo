package com.springKotlinAuthentication.demo.authentication.aop.aspects

import org.aspectj.lang.JoinPoint
import org.aspectj.lang.annotation.AfterThrowing
import org.aspectj.lang.annotation.Aspect
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class ExceptionHandlingAspect {

    private val log = LoggerFactory.getLogger(this::class.java)

    @AfterThrowing(
        pointcut = "execution(* com.springKotlinAuthentication.demo.authentication.service..*(..))",
        throwing = "ex"
    )
    fun handleException(joinPoint: JoinPoint, ex: Throwable) {
        val methodName = joinPoint.signature.name
        val className = joinPoint.target.javaClass.simpleName

        log.error("Exception in class: \"$className\", method: \"$methodName\", exception: ${ex.message}", ex)
    }
}
