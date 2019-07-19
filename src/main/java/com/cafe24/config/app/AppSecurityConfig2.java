package com.cafe24.config.app;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.ServletException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.cafe24.mysite.security.CustomUrlAuthenticationSuccessHandler;


@Configuration
@EnableWebSecurity
public class AppSecurityConfig2 {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Bean(name="springSecurityFilterChain")
	public FilterChainProxy filterChainProxy() throws Exception {
		List<SecurityFilterChain> filterChains = new ArrayList<SecurityFilterChain>();
		filterChains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/assets/**")));
		filterChains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/favicon.ico")));
		filterChains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"), 
				// filter chains
				// 1. securityContextPersistenceFilter()
				securityContextPersistenceFilter()
				
				// 2. logoutFilter()
				, logoutFilter()
				
				// 3. usernamePasswordAuthenticationFilter()
				, usernamePasswordAuthenticationFilter()
				
				// 4. anonymousAuthenticationFilter();
				, anonymousAuthenticationFilter()
				
				// 5. exceptionTranslationFilter()
				, exceptionTranslationFilter()
				
				// 6. filterSecurityInterceptor()
				, filterSecurityInterceptor()
				
				
				));
		return new FilterChainProxy(filterChains);
	}

	/**
	 * Description
	 * : 1. SecurityContextPersistenceFilter
	 * 	 	SecurityContext 관리하는 필터
	 * @author rdevnoah
	 * @return
	 */
	@Bean
	public SecurityContextPersistenceFilter securityContextPersistenceFilter() {
		return new SecurityContextPersistenceFilter(new HttpSessionSecurityContextRepository());
	}
	
	/**
	 * Description
	 * : 2. LogoutFilter
	 * 		logout 처리하는 필터
	 * 		
	 * 		CustomLogoutSuccessHandler (로그아웃이 성공하면 web에서는 메인화면이지만, API인 경우 JSON으로 응답해야하기 때문에)
	 * @author rdevnoah
	 * @return
	 * @throws ServletException 
	 */
	@Bean
	public LogoutFilter logoutFilter() throws ServletException {
		
		CookieClearingLogoutHandler cookieClearingLogoutHandler = new CookieClearingLogoutHandler("JSESSIONID");
		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
		securityContextLogoutHandler.setInvalidateHttpSession(true);
		securityContextLogoutHandler.setClearAuthentication(true);
		
		LogoutFilter logoutFilter = new LogoutFilter("/", cookieClearingLogoutHandler);
		logoutFilter.setFilterProcessesUrl("/user/logout");
		logoutFilter.afterPropertiesSet();
		return logoutFilter;
	}
	
	/**
	 * Description
	 * : 3. UsernamePasswordAuthenticationFilter
	 * 		인증(Authenticatin) 처리
	 * @author rdevnoah
	 * @return
	 */
	@Bean
	public AbstractAuthenticationProcessingFilter usernamePasswordAuthenticationFilter() {
		UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
		
		
		usernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager());
		usernamePasswordAuthenticationFilter.setUsernameParameter("email");
		usernamePasswordAuthenticationFilter.setPasswordParameter("password");
		usernamePasswordAuthenticationFilter.setFilterProcessesUrl("/user/auth");
		usernamePasswordAuthenticationFilter.setAllowSessionCreation(true);
		usernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
		usernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/user/login?result=fail"));
		usernamePasswordAuthenticationFilter.afterPropertiesSet();
		return usernamePasswordAuthenticationFilter;
	}
	
	/**
	 * Description
	 * : 4. AnonymousAuthenticationFilter
	 * 		!isAuthenticated()에 대한 처리
	 * @author rdevnoah
	 * @return
	 */
	@Bean
	public AnonymousAuthenticationFilter anonymousAuthenticationFilter() {
		return new AnonymousAuthenticationFilter("0A97C60B53D77E5");
	}
	
	
	
	
	/**
	 * Description
	 * : 5. ExceptionTranslationFilter
	 * 		인증 또는 권한이 없는 접근은 Exception을 바생시킨다.
	 * 		예외에 대한 처리
	 * @author rdevnoah
	 * @return
	 */
	@Bean
	public ExceptionTranslationFilter exceptionTranslationFilter() {
		
		//인증 실패하면 /user/login 으로 간다.
		AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/user/login");
		
		//인증은 했지만, 권한이 실패하면 403으로 간다.
		AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
		//controller 타고 가야하는듯
		accessDeniedHandler.setErrorPage("/WEB-INF/views/error/403.jsp");
		
		ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(authenticationEntryPoint); //인증실패 생성자에서 설정
		exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler); //권한실패 set으로 설정
		
		return exceptionTranslationFilter;
	}
	
	/**
	 * Description
	 * : 6. FilterSecurityInterceptor
	 * 		Interceptor URL 접근 제어
	 * @author rdevnoah
	 * @return
	 * @throws Exception
	 */
	@Bean
	public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		
		filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
		filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = 
				new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
		requestMap.put(new AntPathRequestMatcher("/user/update"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/user/logout"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/board/write"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/board/delete"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/board/modify"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/admin/**"), SecurityConfig.createList("hasRole('ADMIN')"));
		//gallery는 구현 아직 구현 안함.
//		requestMap.put(new AntPathRequestMatcher("/gallery/upload"), SecurityConfig.createList("hasRole('ADMIN')"));
//		requestMap.put(new AntPathRequestMatcher("/gallery/delete"), SecurityConfig.createList("hasRole('ADMIN')"));
		//requestMap.put(new AntPathRequestMatcher("/**"), SecurityConfig.createList("permitAll"));
		
		
		
		FilterInvocationSecurityMetadataSource newSource = 
				new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, new DefaultWebSecurityExpressionHandler());
		
		filterSecurityInterceptor.setSecurityMetadataSource(newSource);
		
		return filterSecurityInterceptor;
	}
	
	@Bean
	public AuthenticationManager authenticationManager() {
		AuthenticationManager authenticationManager = new ProviderManager(Arrays.asList(authenticationProvider()));
		return authenticationManager;
	}
	
	
	@Bean
	public AuthenticationProvider authenticationProvider(){
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		
		return encoder;
	}
	
	@Bean
	public AffirmativeBased accessDecisionManager() throws Exception {
		RoleVoter roleVoter = new RoleVoter();
		roleVoter.setRolePrefix("ROLE_");
		AffirmativeBased affirmativeBased = new AffirmativeBased(Arrays.asList(roleVoter, 
				new WebExpressionVoter(), new AuthenticatedVoter()));
		affirmativeBased.setAllowIfAllAbstainDecisions(false);
		affirmativeBased.afterPropertiesSet();
		return affirmativeBased;
	}
	
	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new CustomUrlAuthenticationSuccessHandler();
	}
}

