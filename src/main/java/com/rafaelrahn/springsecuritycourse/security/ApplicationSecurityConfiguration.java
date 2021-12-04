package com.rafaelrahn.springsecuritycourse.security;

import com.rafaelrahn.springsecuritycourse.auth.ApplicationUserService;
import com.rafaelrahn.springsecuritycourse.jwt.JwtConfig;
import com.rafaelrahn.springsecuritycourse.jwt.JwtTokenVerifierFilter;
import com.rafaelrahn.springsecuritycourse.jwt.JwtUserNameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.crypto.SecretKey;

import static com.rafaelrahn.springsecuritycourse.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // for method annotation @PreAuthorize()
public class ApplicationSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfiguration(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUserNameAndPasswordAuthenticationFilter(authenticationManager(), secretKey, jwtConfig))
                .addFilterAfter(new JwtTokenVerifierFilter(secretKey, jwtConfig), JwtUserNameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/js/*", "/css/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
//                .and()
//                .formLogin()
//                    .loginPage("/login").permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password") // correspond field name with password in the login form this is the default values
//                    .usernameParameter("username") // correspond field name with username in the login form  this is the default values
//                .and()
//                    .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingverysecured")// default 2 weeks
//                .userDetailsService(this.userDetailsServiceBean())
//                  .userDetailsService(applicationUserService)
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // only possible with csrf disable
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");
//                .httpBasic();
    }

    @Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {
        UserDetails rafaelUser = User.builder()
                .username("rafael")
                .password(passwordEncoder.encode("123"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantAuthorities())
                .build();

        UserDetails leopoldinhoUser = User.builder()
                .username("leopold")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantAuthorities())
                .build();

        UserDetails elaineUser = User.builder()
                .username("elaine")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantAuthorities())
                .build();

        return new InMemoryUserDetailsManager(rafaelUser, leopoldinhoUser, elaineUser);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
         auth.authenticationProvider(daoAuthenticationProvider());
    }
}
