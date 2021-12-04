package com.rafaelrahn.springsecuritycourse.auth;

import com.google.common.collect.Lists;
import com.rafaelrahn.springsecuritycourse.security.ApplicationUserRole;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().filter(
                applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        return Lists.newArrayList(
                new ApplicationUser("rafael",
                        passwordEncoder.encode("123"),
                        ApplicationUserRole.ADMIN.getGrantAuthorities(),
                        true,
                        true,
                        true,
                        true
                ), new ApplicationUser("elaine",
                        passwordEncoder.encode("123"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantAuthorities(),
                        true,
                        true,
                        true,
                        true
                ), new ApplicationUser("leopold",
                        passwordEncoder.encode("123"),
                        ApplicationUserRole.STUDENT.getGrantAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
    }
}
