package com.example.springsecurity.common.exception;

import org.springframework.http.HttpStatus;

public class DuplicateEmailException extends BaseException {

    public DuplicateEmailException(String message) {
        super(HttpStatus.CONFLICT.value(), message);
    }
}