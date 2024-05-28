package de.hft_stuttgart.it_security_2.test.boundary;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api")
@RequiredArgsConstructor
class DummyController {

    @GetMapping("/dummy")
    public String getDummy() {
        return "dummy";
    }
}
