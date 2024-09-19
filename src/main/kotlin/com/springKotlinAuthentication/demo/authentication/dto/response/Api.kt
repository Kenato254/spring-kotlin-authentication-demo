package com.springKotlinAuthentication.demo.authentication.dto.response

import com.springKotlinAuthentication.demo.authentication.constant.ErrorStatus

data class Api<T>(
    val ok: Boolean,
    val data: T? = null,
    val message: String,
    val errorStatus: ErrorStatus? = null
) {
    companion object {
        fun <T> ok(data: T?, message: String = "Operation successful"): Api<T> {
            return Api(
                ok = true,
                data = data,
                message = message
            )
        }

        fun <T> error(message: String, errorStatus: ErrorStatus): Api<T> {
            return Api(
                ok = false,
                data = null,
                message = message,
                errorStatus = errorStatus
            )
        }
    }
}
