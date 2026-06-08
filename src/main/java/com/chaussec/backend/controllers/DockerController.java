package com.chaussec.backend.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class DockerController {
    
    @GetMapping("/docker")
    public String getMethodName() {
        return "Hi !";
    }
    
}
