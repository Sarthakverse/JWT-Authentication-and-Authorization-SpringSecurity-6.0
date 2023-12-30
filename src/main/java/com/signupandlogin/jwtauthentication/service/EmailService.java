package com.signupandlogin.jwtauthentication.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;

    public void sendOtpOnEmail(String toEmail , String otp) throws MessagingException {
//        SimpleMailMessage message = new SimpleMailMessage();
//        message.setFrom("JodhpurHackathon.app@gmail.com");
//        message.setTo(toEmail);
//        message.setSubject("OTP for verification ");
//        message.setText("Your OTP is: "+otp);
//        javaMailSender.send(message);

        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message,true);

        helper.setFrom("JodhpurHackathon.app@gmail.com");
        helper.setTo(toEmail);
        helper.setSubject("OTP for verification");

        String htmlContent = "<html><body>"
                + "<h2>Your OTP is:</h2>"
                + "<p>" + otp + "</p>"
                + "<img src='cid:logo'>"
                + "</body></html>";
        helper.setText(htmlContent, true);
        helper.addInline("logo", new ClassPathResource("static/beluga.jpeg"));
        javaMailSender.send(message);
    }
}
