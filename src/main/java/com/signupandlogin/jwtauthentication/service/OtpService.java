package com.signupandlogin.jwtauthentication.service;

import com.signupandlogin.jwtauthentication.entity.Otp;
import com.signupandlogin.jwtauthentication.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService {
    private final OtpRepository otpRepository;
    private static final String CHARACTERS = "123456789";
    private static final int OTP_LENGTH = 6;

    public String generateOtp(){
        StringBuilder otp = new StringBuilder();
        Random random = new Random();
        for(int i=0;i<OTP_LENGTH;i++){
            otp.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return otp.toString();
    }

    public String getOtpByEmail(String email){
        Otp otp = otpRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("OTP not found for email: "+email));
        return otp.getOtp();
    }


}
