package com.rafaelrahn.springsecuritycourse;

import com.rafaelrahn.springsecuritycourse.jwt.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfig.class)
public class SpringsecuritycourseApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecuritycourseApplication.class, args);
	}

}
