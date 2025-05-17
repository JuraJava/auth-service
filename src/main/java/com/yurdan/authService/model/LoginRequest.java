package com.yurdan.authService.model;

//TODO избавиться от звездочек. Использовать только прямые импорты.
import lombok.*;

@Getter
@Setter
public  class LoginRequest {

    private  String email;
    private  String password;

}
