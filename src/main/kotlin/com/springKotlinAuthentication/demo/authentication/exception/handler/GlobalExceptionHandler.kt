package com.springKotlinAuthentication.demo.authentication.exception.handler


import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.constant.ErrorStatus
import com.springKotlinAuthentication.demo.authentication.dto.response.Api
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.ForbiddenAccessException
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UnauthenticatedUserException
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.UserAlreadyExistsException
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import jakarta.persistence.EntityNotFoundException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.servlet.resource.NoResourceFoundException

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(NoResourceFoundException::class)
    fun handleNoResourceFoundExceptions(e: NoResourceFoundException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ENTITY_NOT_FOUND,
            errorStatus = ErrorStatus.NOT_FOUND
        )
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse)
    }

    @ExceptionHandler(EntityNotFoundException::class)
    fun handleEntityNotFoundExceptions(e: EntityNotFoundException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ENTITY_NOT_FOUND,
            errorStatus = ErrorStatus.NOT_FOUND
        )
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse)
    }

    @ExceptionHandler(DisabledException::class)
    fun handleDisableAccountExceptions(e: DisabledException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = Constant.AUTH_ACCOUNT_DISABLED,
            errorStatus = ErrorStatus.FORBIDDEN
        )
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse)
    }

    @ExceptionHandler(NullPointerException::class)
    fun handleNullPointerExceptions(e: NullPointerException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ERROR_INTERNAL_SERVER,
            errorStatus = ErrorStatus.INTERNAL_SERVER_ERROR
        )
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse)
    }

    @ExceptionHandler(IllegalStateException::class)
    fun handleIllegalStateExceptions(e: IllegalStateException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ILLEGAL_STATE,
            errorStatus = ErrorStatus.BAD_REQUEST
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse)
    }

    @ExceptionHandler(UnauthenticatedUserException::class)
    fun handleUnauthenticatedUserException(e: UnauthenticatedUserException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.USER_NOT_FOUND,
            errorStatus = ErrorStatus.UNAUTHORIZED
        )
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse)
    }

    @ExceptionHandler(ForbiddenAccessException::class)
    fun handleAccessDeniedException(e: ForbiddenAccessException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.AUTH_ACCESS_DENIED,
            errorStatus = ErrorStatus.FORBIDDEN
        )
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse)
    }

    @ExceptionHandler(UserAlreadyExistsException::class)
    fun handleUserAlreadyExistsException(e: UserAlreadyExistsException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.USER_ALREADY_EXISTS,
            errorStatus = ErrorStatus.CONFLICT
        )
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse)
    }

    @ExceptionHandler(UsernameNotFoundException::class)
    fun handleUsernameNotFoundException(e: UsernameNotFoundException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.USER_NOT_FOUND,
            errorStatus = ErrorStatus.NOT_FOUND
        )
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse)
    }

    @ExceptionHandler(BadCredentialsException::class)
    fun handleBadCredentialsException(e: BadCredentialsException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ERROR_BAD_REQUEST,
            errorStatus = ErrorStatus.BAD_REQUEST
        )
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse)
    }

    @ExceptionHandler(ExpiredJwtException::class)
    fun handleExpiredJwtException(e: ExpiredJwtException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.JWT_EXPIRED,
            errorStatus = ErrorStatus.UNAUTHORIZED
        )
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse)
    }

    @ExceptionHandler(MalformedJwtException::class)
    fun handleMalformedJwtException(e: MalformedJwtException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.JWT_MALFORMED,
            errorStatus = ErrorStatus.UNAUTHORIZED
        )
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse)
    }

    @ExceptionHandler(UnsupportedJwtException::class)
    fun handleUnsupportedJwtException(e: UnsupportedJwtException): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.JWT_UNSUPPORTED,
            errorStatus = ErrorStatus.UNAUTHORIZED
        )
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse)
    }

    @ExceptionHandler(Exception::class)
    fun handleException(e: Exception): ResponseEntity<Api<Any>> {
        val errorResponse = Api.error<Any>(
            message = e.message ?: Constant.ERROR_INTERNAL_SERVER,
            errorStatus = ErrorStatus.INTERNAL_SERVER_ERROR
        )
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse)
    }
}
