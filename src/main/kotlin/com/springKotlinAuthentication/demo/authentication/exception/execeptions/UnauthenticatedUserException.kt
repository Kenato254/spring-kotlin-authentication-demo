package com.springKotlinAuthentication.demo.authentication.exception.execeptions

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

@ResponseStatus(HttpStatus.UNAUTHORIZED)
class UnauthenticatedUserException(message: String) : RuntimeException(message)
