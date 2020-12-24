package conf;

import conf.security.ApiAuthenticationFilter;
import conf.security.handlers.ApiAccessDeniedHandler;
import conf.security.handlers.ApiEntryPoint;
import conf.security.handlers.ApiLogoutSuccessHandler;
import conf.security.jwt.JwtAuthenticationFilter;
import conf.security.jwt.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:/application.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${jwt.signing.key}")
    private String jwtKey;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.authorizeRequests().antMatchers("/api/home").permitAll();
        http.authorizeRequests().antMatchers("/api/login").permitAll();
        http.authorizeRequests()
                .antMatchers("/api/admin/**").hasRole("ADMIN");
        http.authorizeRequests().antMatchers("/api/**").authenticated();



        http.exceptionHandling().authenticationEntryPoint(new ApiEntryPoint());

        http.exceptionHandling().accessDeniedHandler(new ApiAccessDeniedHandler());

        http.logout().logoutSuccessHandler(new ApiLogoutSuccessHandler());


        http.logout().logoutUrl("/api/logout");

//        var apiLoginFilter = new ApiAuthenticationFilter(authenticationManager(), "/api/login");

//        JWT
        var apiLoginFilter = new JwtAuthenticationFilter(authenticationManager(), "/api/login", jwtKey);
        var jwtAuthFilter = new JwtAuthorizationFilter(authenticationManager(), jwtKey);
        http.addFilterBefore(jwtAuthFilter, LogoutFilter.class);

//        disable session
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterAfter(apiLoginFilter, LogoutFilter.class);


    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        builder.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user")
                .password("$2a$10$RBLZ8is2VXLb4aHBI1FoxuXBrjjZbphgZpJ9NWa3zii.yFjmPaJJS")
                .roles("USER")
                .and()
                .withUser("admin")
                .password("$2a$12$atJ4Is6NBQ8lkvCQVnyneOCtzcKnHiHaNGG/jezczMx5MCsqQSimO")
                .roles("USER", "ADMIN");
    }

}