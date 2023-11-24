package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.Account;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false)String error,
                        @RequestParam(value = "exception", required = false)String exception, Model model){
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);
        return "user/login/login";
    }

    @GetMapping("/logout") // get방식으로 로그아웃 처리
    public String logout(HttpServletRequest request , HttpServletResponse response){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // 현재 인증된 사용자 정보

        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request,response,authentication); //로그 아웃
        }

        return "redirect:/login";
    }

    @GetMapping("/denied")
    public String accessDenied(@RequestParam(value = "exception", required = false)String exception,Model model){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account)authentication.getPrincipal();

        model.addAttribute("username",account.getUsername());
        model.addAttribute("exception",exception);

        return "user/login/denied";
    }

    /*@GetMapping("/api/login")
    public String ajaxLoginForm(){
        return "user/login/ajaxLogin";
    }*/
}
