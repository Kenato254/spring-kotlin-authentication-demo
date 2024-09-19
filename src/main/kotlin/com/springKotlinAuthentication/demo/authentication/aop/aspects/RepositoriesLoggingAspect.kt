package com.springKotlinAuthentication.demo.authentication.aop.aspects

import com.springKotlinAuthentication.demo.authentication.aop.AopUtil
import org.aspectj.lang.JoinPoint
import org.aspectj.lang.annotation.After
import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Pointcut
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class RepositoriesLoggingAspect {

    private val log: Logger = LoggerFactory.getLogger(this::class.java)

    @Pointcut("execution(* org.springframework.data.jpa.repository.JpaRepository+.*(..))")
    fun repositoryMethod() {
    }

    @After("repositoryMethod()")
    fun afterRepositoryMethod(joinPoint: JoinPoint) {
        val args = joinPoint.args.map { arg -> AopUtil.sanitizeSensitiveData(arg) }
        log.info("Request with masked data: $args")
    }
}
