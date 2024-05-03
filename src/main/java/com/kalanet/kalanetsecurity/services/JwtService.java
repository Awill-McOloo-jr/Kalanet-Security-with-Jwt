package com.kalanet.kalanetsecurity.services;

import com.kalanet.kalanetsecurity.model.Client;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String secretKey = "RwWltSbPqHov2w0boORoG489u2dkpo0OXfv4PNP7FiGdYYUQ81YOceq7xr7man4G";

    //1.Create Token.
    public String createToken(Client client) {
        return Jwts.builder()
                .subject(client.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 10*60*1000))
                .signWith(signingKey())
                .compact();
    }

    //2.Create signing key
    private SecretKey signingKey() {
        byte [] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //3.Extract All claims from payload
    public Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    //4.Extract a single payload from token
    public <T> T getSingleClaim (String token, Function<Claims, T> resolver) {
        Claims claims = getAllClaims(token);
        return resolver.apply(claims);

    }

    //5.Extract username from token
    public String getUsernameClaim(String token){
        return getSingleClaim(token, Claims::getSubject);
    }

    //6.Extract expiration time from token
    public Date getExpiration(String token) {
        return getSingleClaim(token, Claims::getExpiration);
    }

    //7.Check if token is expired
    public boolean isExpired(String token) {
        return getExpiration(token).before(new Date());
    }

    //8.Check if token is valid
    public boolean isValid(String token, UserDetails userDetails) {
        String username = getUsernameClaim(token);
        return username.equals(userDetails.getUsername());
    }
}
