package com.springKotlinAuthentication.demo.authentication.controller

import com.springKotlinAuthentication.demo.authentication.dto.request.ChangePasswordRequest
import com.springKotlinAuthentication.demo.authentication.dto.request.LoginRequest
import com.springKotlinAuthentication.demo.authentication.dto.request.RegisterRequest
import com.springKotlinAuthentication.demo.authentication.dto.request.ResetPasswordRequest
import com.springKotlinAuthentication.demo.authentication.dto.response.Api
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.service.AuthenticationService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.responses.ApiResponse
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.FieldError
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.*
import java.util.*

@RestController
@RequestMapping("auth")
class AuthenticationController(
    private val authenticationService: AuthenticationService
) {

    @Operation(summary = "Register a user")
    @ApiResponse(responseCode = "201", description = "Register successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "409", description = "Conflict")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("register")
    fun register(
        @RequestBody @Validated request: RegisterRequest
    ): ResponseEntity<Api<RegisterResponse>> {
        val token = authenticationService.registerUser(request)
        val response = Api.ok(token, "Register successful")
        return ResponseEntity.status(HttpStatus.CREATED).body(response)
    }

    @Operation(summary = "Read a user", description = "Reads user by a provided id")
    @ApiResponse(responseCode = "200", description = "Read user successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @GetMapping("users/{id}/user")
    fun readUserById(
        @PathVariable id: UUID,
        @RequestHeader("Authorization") accessToken: String
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.readUserById(id, accessToken)
        val response = Api.ok(userResponse, "Read user successful")
        return ResponseEntity.ok(response)
    }

    @Operation(summary = "Login a user")
    @ApiResponse(responseCode = "202", description = "Login successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("login")
    fun login(
        @RequestBody @Validated request: LoginRequest
    ): ResponseEntity<Api<LoginResponse>> {
        val userResponse = authenticationService.loginUser(request)
        val successResponse = Api.ok(userResponse, "Login successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(successResponse)
    }

    @Operation(summary = "Confirm/Enable user account")
    @ApiResponse(responseCode = "202", description = "Confirm account successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User or Token not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @GetMapping("confirm")
    fun confirm(
        @RequestParam("token") token: String
    ): ResponseEntity<Api<Unit>> {
        val confirmed = authenticationService.confirmUser(token)
        val successResponse = Api.ok(confirmed, "Confirm account successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(successResponse)
    }

    @Operation(summary = "Reset password", description = "Sends a password reset token to the user's email")
    @ApiResponse(responseCode = "202", description = "Password reset successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("reset")
    fun reset(
        @RequestBody @Validated request: ResetPasswordRequest
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.resetPassword(request)
        val response = Api.ok(userResponse, "Reset token sent successfully")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response)
    }

    @Operation(summary = "Change password", description = "Changes the user's password using the provided token")
    @ApiResponse(responseCode = "202", description = "Password change successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("change")
    fun change(
        @RequestHeader("Authorization") token: String,
        @RequestBody @Validated request: ChangePasswordRequest
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.changePassword(token, request)
        val response = Api.ok(userResponse, "Password change successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response)
    }

    @Operation(summary = "List all users")
    @ApiResponse(responseCode = "200", description = "List users successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "403", description = "Unauthorized")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @GetMapping("users")
    fun getAllUsers(
        @RequestHeader("Authorization") accessToken: String
    ): ResponseEntity<Api<List<UserResponse>>> {
        val userResponses = authenticationService.getAllUsers(accessToken)
        val response = Api.ok(userResponses, "List of users")
        return ResponseEntity.ok(response)
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleValidationExceptions(
        ex: MethodArgumentNotValidException
    ): Map<String, String?> {
        val errors: MutableMap<String, String?> = HashMap()
        ex.bindingResult.allErrors.forEach { error ->
            val fieldName = (error as FieldError).field
            val errorMessage = error.defaultMessage
            errors[fieldName] = errorMessage
        }
        return errors
    }
}
