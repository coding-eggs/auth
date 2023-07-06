package com.coding.auth.controller;

import com.coding.auth.utils.RandomCodeVerifier;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@RestController
public class CallbackController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/callback")
    public void callback(String code) {

//        MultiValueMap<String,String> map = new LinkedMultiValueMap<>();
//        map.add("grant_type","urn:ietf:params:oauth:grant-type:custom_code");
//        map.add("code",code);
//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.setBasicAuth("messaging-client", "123456");
//
//
//        httpHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);
//        HttpEntity<MultiValueMap<String,String>> httpEntity = new HttpEntity<>(map,httpHeaders);
//        Object jwt = restTemplate.exchange("http://127.0.0.1:8080/oauth2/token", HttpMethod.POST,httpEntity, Object.class).getBody();
//
//
//        System.out.println(jwt.toString());
        System.out.println(code);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        String codeVerifier = RandomCodeVerifier.getCodeVerifier();
        System.out.println("code verifier: " + codeVerifier);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));

        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);


        System.out.println("code challenge: " + codeChallenge);
        System.out.println(Instant.now().plus(1, TimeUnit.DAYS.toChronoUnit()));

    }

}
