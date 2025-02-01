package com.example.springsecurity.service;

import static com.example.springsecurity.util.RandomCodeGeneratorUtil.generateRandomNumber;

import com.example.springsecurity.repository.RedisRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;


@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    private static final int NUMBER_CODE_LENGTH = 6;

    private final SpringTemplateEngine templateEngine;
    private final JavaMailSender mailSender;
    private final RedisRepository redisRepository;

    // 1. 인증번호 받기 버튼을 누른다.
    // 2. 인증번호를 생성하고 redis에 저장한다.
    // 3. redis에 저장된 번호를 보낸다.
    public void sendVerificationEmail(String mail) {
        // 랜덤번호 생성
        int numberCode = generateRandomNumber(NUMBER_CODE_LENGTH);
        // 레디스에 저장
        redisRepository.setValues(mail, String.valueOf(numberCode), Duration.ofMinutes(3));

        MimeMessage message = mailSender.createMimeMessage();
        Map<String, String> map = new HashMap<>();
        map.put("code", String.valueOf(numberCode));

        try {
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(message, false, "UTF-8");
            mimeMessageHelper.setTo(mail); // 메일 수신자
            mimeMessageHelper.setSubject("이메일 인증"); // 메일 제목
            mimeMessageHelper.setText(setContext(map), true); // 메일 본문 내용, HTML 여부
            mailSender.send(message);

            log.info("Successfully created mail");
        } catch (MessagingException e) {
            log.error("Failed to create mail: {}", e.getMessage());
        } catch (MailException e) {
            log.error("Failed to send mail: {}", e.getMessage());
        }
    }

    private String setContext(Map<String, String> map) {
        Context context = new Context();
        map.forEach(context::setVariable);
        return templateEngine.process("mail", context);
    }

    public boolean validateEmailAuthCode(String mail, String code) {
        return redisRepository.getValues(mail).equals(code);
    }
}
