package example.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Just and example RestController, so that project is not so empty
@RestController
public class ExampleRestController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
