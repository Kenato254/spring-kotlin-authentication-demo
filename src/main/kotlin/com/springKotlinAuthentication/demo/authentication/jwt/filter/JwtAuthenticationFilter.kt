package com.springKotlinAuthentication.demo.authentication.jwt.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.constant.ErrorStatus
import com.springKotlinAuthentication.demo.authentication.dto.response.Api
import com.springKotlinAuthentication.demo.authentication.exception.execeptions.ExpiredJwtException
import com.springKotlinAuthentication.demo.authentication.jwt.service.JwtService
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private var jwtService: JwtService,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    companion object {
        private val EXCLUDED_PATHS: List<String> = mutableListOf(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/validate-token/**",

            "/actuator/**",

            "/api/v2/api-docs",
            "/api/v3/api-docs",
            "/api/v3/api-docs/**",
            "/api/swagger-resources",
            "/api/swagger-resources/**",
            "/api/configuration/ui",
            "/api/configuration/security",
            "/api/swagger-ui/**",
            "/api/webjars/**",
            "/api/swagger-ui.html"
        )
    }

    private val pathMatcher = AntPathMatcher()

    private fun isExcluded(requestURI: String): Boolean {
        return EXCLUDED_PATHS.stream().anyMatch { path: String? ->
            pathMatcher.match(
                path!!, requestURI
            )
        }
    }

    private fun servletErrorResponseManager(
        message: String,
        response: HttpServletResponse,
        errorStatus: ErrorStatus = ErrorStatus.UNAUTHORIZED
    ) {
        val errorResponse = Api.error<Error>(
            message,
            errorStatus
        )
        val jsonResponse = objectMapper.writeValueAsString(errorResponse)
        response.contentType = "application/json"
        response.status = if (errorStatus != ErrorStatus.NOT_FOUND) HttpServletResponse.SC_UNAUTHORIZED
        else HttpServletResponse.SC_NOT_FOUND
        response.writer.write(jsonResponse)
        response.writer.flush()
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val requestURI = request.requestURI

        if (isExcluded(requestURI)) {
            filterChain.doFilter(request, response)
            return
        }

        try {
            val userDetails = jwtService.extractUserDetailFromRequest(request).first
            if (SecurityContextHolder.getContext().authentication == null) {
                val authentication = UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.authorities
                )
                authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authentication
            }
        } catch (ex: ExpiredJwtException) {
            servletErrorResponseManager(Constant.JWT_EXPIRED, response)
            return
        } catch (e: MalformedJwtException) {
            servletErrorResponseManager(Constant.JWT_MALFORMED, response)
            return
        } catch (e: UsernameNotFoundException) {
            servletErrorResponseManager(Constant.USER_NOT_FOUND, response, ErrorStatus.NOT_FOUND)
            return
        } catch (e: UnsupportedJwtException) {
            servletErrorResponseManager(Constant.JWT_UNSUPPORTED, response)
            return
        } catch (e: IllegalArgumentException) {
            servletErrorResponseManager(Constant.JWT_MALFORMED, response)
            return
        }
        filterChain.doFilter(request, response)
    }
}