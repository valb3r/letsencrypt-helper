package example.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleRestController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
