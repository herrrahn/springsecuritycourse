package com.rafaelrahn.springsecuritycourse.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
    private static final List<Student> students = Arrays.asList(
            new Student(1, "Rafael"),
            new Student(2, "Elaine"),
            new Student(3, "Leopold")
    );

    @GetMapping(path = "{studentId}")
    public Student findById(@PathVariable("studentId") Integer id) {
        return students.stream()
                .filter(s -> s.getId().equals(id))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Student " + id + " not found")
                );
    }
}
