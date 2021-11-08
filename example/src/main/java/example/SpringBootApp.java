package example;

import com.github.valb3r.letsencrypthelper.TomcatWellKnownLetsEncryptChallengeEndpointConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(TomcatWellKnownLetsEncryptChallengeEndpointConfig.class) // Enable LetsEncrypt certficate management
public class SpringBootApp {

    public static void main(String[] args){
        SpringApplication.run(SpringBootApp.class, args);
    }
}
