package com.springKotlinAuthentication.demo.authentication.exception.execeptions

import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException

class ExpiredJwtException(message: String) : ResponseStatusException(HttpStatus.UNAUTHORIZED, message)
