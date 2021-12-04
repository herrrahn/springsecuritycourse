package com.rafaelrahn.springsecuritycourse.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class UserManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Rafael"),
            new Student(2, "Elaine"),
            new Student(3, "Leopold")
    );

    @GetMapping
    // hasRole('') hasAnyRole('') hasAuthority() hasAnyAuthority()
    @PreAuthorize("hasAnyRole('ADMIN', 'ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerStudent(@RequestBody  Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer id) {
        System.out.println(id);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer id, @RequestBody Student student) {
        System.out.printf("%s %s", id, student);
    }
}
