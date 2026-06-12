package com.chaussec.backend.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/chaussec")
public class RequinController {
    
    @GetMapping("/requin")
    public String getRequin(){
        return "Requin";
    }

}
