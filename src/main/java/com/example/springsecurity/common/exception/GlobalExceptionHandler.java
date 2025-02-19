package com.example.springsecurity.common.exception;

import com.example.springsecurity.common.BaseErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<BaseErrorResponse> handleBaseException(BaseException exception) {
        return ResponseEntity
            .status(exception.getCode())
            .body(new BaseErrorResponse(exception.getMessage()));
    }
}
