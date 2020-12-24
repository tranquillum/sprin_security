package test;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class PasswordEncoderTest {

    @Test
    public void producesHashFromPlaintext() {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(11);

        String hash = encoder.encode("admin");

        System.out.println(hash);

        assertThat(hash, startsWith("$2a$10"));
        assertThat(hash.length(), is(60));
    }

}
