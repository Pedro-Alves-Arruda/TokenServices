package io.github.pedro_alves_arruda.TokenServices.Service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;

@Service
public class TokenServices {

    public String generateToken(Integer duracao, Map<String, String> clains, String appName, String email, String secret){

        Algorithm algorithm = Algorithm.HMAC256(secret);

        try{
            JWTCreator.Builder jwt = JWT.create()
                    .withIssuer(appName)
                    .withSubject(email)
                    .withExpiresAt(LocalDateTime.now().plusMinutes(duracao).toInstant(ZoneOffset.of("-03:00")));


            for(Map.Entry<String, String> claim: clains.entrySet()){
                jwt.withClaim(claim.getKey(), claim.getValue());
            }

            return jwt.sign(algorithm);


        }catch (JWTCreationException ex){
            throw new RuntimeException(ex.getMessage());
        }

    }

    public String recoverToken(String token, String nameApp, String secret){
        Algorithm algorithm = Algorithm.HMAC256(secret);

        try{
            return JWT.require(algorithm)
                    .withIssuer(nameApp)
                    .build()
                    .verify(token)
                    .getSubject();
        }catch (JWTCreationException ex){
            throw new RuntimeException(ex.getMessage());
        }
    }


}
