package dev.ducku.myauthorizationserver;

import dev.ducku.myauthorizationserver.config.RsaKeyProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class MyAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(MyAuthorizationServerApplication.class, args);
    }

}
