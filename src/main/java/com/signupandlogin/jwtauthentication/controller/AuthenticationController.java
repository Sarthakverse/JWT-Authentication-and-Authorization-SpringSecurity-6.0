package com.signupandlogin.jwtauthentication.controller;

import com.signupandlogin.jwtauthentication.payload.request.*;
import com.signupandlogin.jwtauthentication.payload.response.AuthenticationResponse;
import com.signupandlogin.jwtauthentication.service.AuthenticationService;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController // Rest controller is used to create restful web services
@RequestMapping("api/v1/auth") // this annotation is used to map the request to the specific url
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    ResponseEntity<AuthenticationResponse> register(@RequestBody @Valid RegisterRequest registerRequest) throws MessagingException {

        AuthenticationResponse response = authenticationService.register(registerRequest);

        if(response.getMessage().equals("User already exists"))
        {
            return new ResponseEntity<>(response,HttpStatus.CONFLICT);
        }

        else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }


    }

    @PostMapping("/verify")
    ResponseEntity<AuthenticationResponse> verify(@RequestBody @Valid VerifyRequest verifyRequest){
        AuthenticationResponse response = authenticationService.verifyOtp(verifyRequest);
        if(response.getMessage().equals("OTP not found"))
        {
            return new ResponseEntity<>(response,HttpStatus.NOT_FOUND);
        }
        else if(response.getMessage().equals("Incorrect Otp entered"))
        {
            return new ResponseEntity<>(response,HttpStatus.BAD_REQUEST);
        }
        else if(response.getMessage().equals("Otp has been expired"))
        {
            return new ResponseEntity<>(response,HttpStatus.BAD_REQUEST);
        }
        else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }

    }

    @PostMapping("/login")
    ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid LoginRequest loginRequest){
        AuthenticationResponse response = authenticationService.login(loginRequest);
        if ("user not verified".equals(response.getMessage())) {
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        } else if ("User not registered".equals(response.getMessage())) {
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        } else if ("Invalid username or password".equals(response.getMessage())) {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }else{
            return new ResponseEntity<>(response,HttpStatus.ACCEPTED);
        }

    }

    @PostMapping("/resendOtp")
    ResponseEntity<AuthenticationResponse> resendOTP(@RequestBody ResendOtpRequest resendOtpRequest) throws MessagingException {
        AuthenticationResponse response = authenticationService.resendOtp(resendOtpRequest);
        if("Wait fo 1 minute to send otp again".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.BAD_REQUEST);
        }
        else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }
    }

    @PostMapping("/forgotPassword")
    ResponseEntity<AuthenticationResponse> forgotPass(@RequestBody ForgotPasswordRequest forgotPasswordRequest) throws MessagingException {
        AuthenticationResponse response = authenticationService.forgotPassword(forgotPasswordRequest);
        if("user does not exist with email address".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.NOT_FOUND);
        }
        else if ("user not verified".equals(response.getMessage())) {
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);

        } else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }
    }

    @PostMapping("/forgotPasswordVerify")
    ResponseEntity<AuthenticationResponse> forgotPassVerify(@RequestBody ForgotPasswordVerifyRequest forgotPasswordVerifyRequest){
        AuthenticationResponse response = authenticationService.forgotPasswordVerify(forgotPasswordVerifyRequest);
        if("otp not found".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.NOT_FOUND);
        }
        else if("Incorrect Otp entered".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.BAD_REQUEST);
        }
        else if("Otp has been expired".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.BAD_REQUEST);
        }
        else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }
    }

    @PostMapping("/resetPassword")
    ResponseEntity<AuthenticationResponse> resetPassword(@RequestBody @Valid ResetPasswordRequest resetPasswordRequest){
        AuthenticationResponse response = authenticationService.resetPassword(resetPasswordRequest);
        if("user does not exist with email address".equals(response.getMessage()))
        {
            return new ResponseEntity<>(response,HttpStatus.NOT_FOUND);
        }
        else
        {
            return new ResponseEntity<>(response,HttpStatus.OK);
        }
    }
}
