package com.signupandlogin.jwtauthentication.service;

import com.signupandlogin.jwtauthentication.entity.Otp;
import com.signupandlogin.jwtauthentication.entity.User;
import com.signupandlogin.jwtauthentication.payload.request.*;
import com.signupandlogin.jwtauthentication.payload.response.AuthenticationResponse;
import com.signupandlogin.jwtauthentication.repository.OtpRepository;
import com.signupandlogin.jwtauthentication.repository.UserRepository;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final OtpService otpService;
    private final OtpRepository otpRepository;
    private final EmailService emailService;
    private static final int OTP_EXPIRATION_MIN = 2;



    public AuthenticationResponse register(RegisterRequest registerRequest) throws MessagingException {

        LocalDateTime OtpExpiryTime = LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MIN);
        User user = new User();

        if(userRepository.findByEmail(registerRequest.getEmail()).isEmpty()){
            user = User.builder()
                    .firstName(registerRequest.getFirstName())
                    .lastName(registerRequest.getLastName())
                    .email(registerRequest.getEmail())
                    .password(passwordEncoder.encode(registerRequest.getPassword()))
                    .isVerified(false)
                    .role(registerRequest.getRole())
                    .build();
        }
        else
        {
            user = userRepository.findByEmail(registerRequest.getEmail()).orElseThrow();
            if(user.getIsVerified())
            {
                return AuthenticationResponse
                        .builder()
                        .message("User already exists")
                        .build();
            }
            user.setFirstName(registerRequest.getFirstName());
            user.setLastName(registerRequest.getLastName());
            user.setEmail(registerRequest.getEmail());
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setRole(registerRequest.getRole());
            user.setIsVerified(false);
        }

        String OTPForEmailing = otpService.generateOtp();
        Otp otp = new Otp();
        otp.setEmail(user.getEmail());
        otp.setOtp(OTPForEmailing);
        otp.setExpiryTime(OtpExpiryTime);
        otpRepository.save(otp);

        emailService.sendOtpOnEmail(registerRequest.getEmail(),OTPForEmailing);

        userRepository.save(user);

        return AuthenticationResponse.builder()
                .message("Check email for OTP")
                .build();

    }

    public AuthenticationResponse verifyOtp(VerifyRequest verifyRequest){

        if(otpRepository.findByEmail(verifyRequest.getEmail()).isEmpty()){
            return AuthenticationResponse.builder()
                    .message("OTP not found")
                    .build();
        }

        String otp = otpService.getOtpByEmail(verifyRequest.getEmail());

        if(!(verifyRequest.getOtp().equals(otp)))
        {
            return AuthenticationResponse
                    .builder()
                    .message("Incorrect Otp entered")
                    .build();
        }

        var otpUser = otpRepository.findByEmail(verifyRequest.getEmail()).orElseThrow();
        if(LocalDateTime.now().isAfter(otpUser.getExpiryTime())){
            otpRepository.delete(otpUser);
            return AuthenticationResponse
                    .builder()
                    .message("Otp has been expired")
                    .build();

        }

        User user = userRepository.findByEmail(verifyRequest.getEmail()).orElseThrow();
        user.setIsVerified(true);
        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        otpRepository.delete(otpUser);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .message("User registered successfully")
                .build();

    }

    public AuthenticationResponse login(LoginRequest loginRequest){

        var userOptional = userRepository.findByEmail(loginRequest.getEmail());
        if(userOptional.isEmpty()){
            return AuthenticationResponse
                    .builder()
                    .message("User not registered")
                    .build();
        }
        var user = userOptional.get();
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken( loginRequest.getEmail(),loginRequest.getPassword()) );
        }catch(Exception e ){
            return AuthenticationResponse
                    .builder()
                    .message("Invalid username or password")
                    .build();
        }

        if(!user.getIsVerified()){
            return AuthenticationResponse
                    .builder()
                    .message("user not verified")
                    .build();
        }

        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .message("logged in successfully")
                .build();
    }

    public AuthenticationResponse resendOtp(ResendOtpRequest resendOtpRequest) throws MessagingException {
        LocalDateTime otpExpiryTime = LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MIN);

        Otp previousOtp = otpRepository.findByEmail(resendOtpRequest.getEmail()).orElse(null);
        if(previousOtp!=null && LocalDateTime.now().isBefore(previousOtp.getExpiryTime().minusMinutes(1))){
            return AuthenticationResponse
                    .builder()
                    .message("Wait fo 1 minute to send otp again")
                    .build();
        }
        String OTPForEmailing = otpService.generateOtp();
        Otp otp = new Otp();
        otp.setEmail(resendOtpRequest.getEmail());
        otp.setOtp(OTPForEmailing);
        otp.setExpiryTime(otpExpiryTime);
        otpRepository.save(otp);

        emailService.sendOtpOnEmail(resendOtpRequest.getEmail(),OTPForEmailing);
        return AuthenticationResponse
                .builder()
                .message("otp has been sent again")
                .build();

    }
    public AuthenticationResponse forgotPassword(ForgotPasswordRequest forgotPasswordRequest) throws MessagingException {
       User user = userRepository.findByEmail(forgotPasswordRequest.getEmail()).orElse(null);
       if(user == null)
       {
           return AuthenticationResponse
                   .builder()
                   .message("user does not exist with email address")
                   .build();
       }
       else
       {
           if(!user.getIsVerified())
           {
               return AuthenticationResponse
                       .builder()
                       .message("user not verified")
                       .build();
           }
           Otp otp = new Otp();
           String OTPForEmailing = otpService.generateOtp();

           otp.setEmail(forgotPasswordRequest.getEmail());
           otp.setExpiryTime(LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MIN));
           otp.setOtp(OTPForEmailing);
           otpRepository.save(otp);
           emailService.sendOtpOnEmail(forgotPasswordRequest.getEmail(),OTPForEmailing);
           return AuthenticationResponse
                   .builder()
                   .message("otp has been sent on email")
                   .build();

       }
    }


    public AuthenticationResponse forgotPasswordVerify(ForgotPasswordVerifyRequest forgotPasswordVerifyRequest)
    {
        var otp = otpRepository.findByEmail(forgotPasswordVerifyRequest.getEmail()).orElse(null);
        if(otp == null)
        {
            return AuthenticationResponse
                    .builder()
                    .message("otp not found")
                    .build();
        }
        else
        {
            if(LocalDateTime.now().isAfter(otp.getExpiryTime()))
            {
                otpRepository.delete(otp);
                return AuthenticationResponse
                        .builder()
                        .message("otp has been expired")
                        .build();
            }
            else
            {
                if(otp.getOtp().equals(forgotPasswordVerifyRequest.getOtp()))
                {
                    otpRepository.delete(otp);
                    return AuthenticationResponse
                            .builder()
                            .message("otp verified successfully")
                            .build();
                }
                else
                {
                    return AuthenticationResponse
                            .builder()
                            .message("incorrect otp entered")
                            .build();
                }
            }
        }
    }

    public AuthenticationResponse resetPassword(ResetPasswordRequest resetPasswordRequest)
    {
        User user  = userRepository.findByEmail(resetPasswordRequest.getEmail()).orElse(null);
        if(user == null)
        {
            return AuthenticationResponse
                    .builder()
                    .message("user does not exist with email address")
                    .build();
        }
        else
        {
            user.setPassword(passwordEncoder.encode(resetPasswordRequest.getNewPassword()));
            userRepository.save(user);
            return AuthenticationResponse
                    .builder()
                    .message("password reset successfully")
                    .build();
        }
    }


}
