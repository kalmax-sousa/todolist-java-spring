package br.com.kalmaxsousa.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.kalmaxsousa.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        
        var servletPath = request.getServletPath();
        if(!servletPath.startsWith("/tasks/")){
            chain.doFilter(request, response);
            return;
        }
        
        var authorization = request.getHeader("Authorization");
        if(authorization == null){
            response.sendError(401);
            return;
        }

        authorization = authorization.replace("Basic ", "");

        var authDecoded = new String(Base64.getDecoder().decode(authorization), "UTF-8");

        var credentials = authDecoded.split(":");
        var username = credentials[0];
        var password = credentials[1];

        var user = this.userRepository.findByUsername(username);

        if(user == null){
            response.sendError(401);
        } else {
            var passwordVerified = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if(passwordVerified.verified){
                request.setAttribute("userId", user.getId());
                chain.doFilter(request, response);        
            } else {
                response.sendError(401);
            }
        }

        
    }
    
}
