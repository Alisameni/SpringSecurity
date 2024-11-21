package com.example.springSecurity.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/student")
public class StudentController {

    public static final List<Student> students = Arrays.asList(
            new Student(1,"James Bond"),
            new Student(2,"Maria Jones"),
            new Student(3,"Anna Smith")
    );
    @GetMapping("/{studentId}")
    public Student getStudent(@PathVariable Integer studentId){
            return students.stream()
                    .filter(student -> studentId.equals(student.getStudentId()))
                    .findFirst()
                    .orElseThrow(() ->new IllegalStateException("student with ID" + studentId + "does not exists"));
    }
}
