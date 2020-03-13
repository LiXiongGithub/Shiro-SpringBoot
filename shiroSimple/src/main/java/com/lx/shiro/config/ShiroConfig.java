package com.lx.shiro.config;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lx.shiro.filter.JWTFilter;
import com.lx.shiro.shiro.CustomRealm;

/**
 * Created with IntelliJ IDEA
 *
 * @Author yuanhaoyue swithaoy@gmail.com
 * @Description shiro 配置
 * @Date 2018-03-28
 * @Time 17:21
 */
@Configuration
public class ShiroConfig {
	/**
	 * 过滤器默认权限表 {anon=anon, authc=authc, authcBasic=authcBasic, logout=logout,
	 * noSessionCreation=noSessionCreation, perms=perms, port=port, rest=rest,
	 * roles=roles, ssl=ssl, user=user}
	 * <p>
	 * anon, authc, authcBasic, user 是第一组认证过滤器 perms, port, rest, roles, ssl
	 * 是第二组授权过滤器
	 * <p>
	 * user 和 authc 的不同：当应用开启了rememberMe时, 用户下次访问时可以是一个user, 但绝不会是authc,
	 * 因为authc是需要重新认证的, user表示用户不一定已通过认证, 只要曾被Shiro记住过登录状态的用户就可以正常发起请求,比如rememberMe
	 * 以前的一个用户登录时开启了rememberMe, 然后他关闭浏览器, 下次再访问时他就是一个user, 而不会authc
	 *
	 * @param securityManager
	 *            初始化 ShiroFilterFactoryBean 的时候需要注入 SecurityManager
	 */
	@Bean
	public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

		// -------------------------------设置自定义过滤器
		// 添加自己的过滤器并且取名为jwt，设置我们自定义的JWT过滤器
		Map<String, Filter> filterMap = new LinkedHashMap<>();
		filterMap.put("jwt", new JWTFilter());
		shiroFilterFactoryBean.setFilters(filterMap);

		// --------------------------------设置异常跳转
		// 必须设置 SecurityManager
		shiroFilterFactoryBean.setSecurityManager(securityManager);

		// 设置无权限时跳转的 url;
		shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized/无权限");
		// setLoginUrl 如果不设置值，默认会自动寻找Web工程根目录下的"/login.jsp"页面 或 "/login" 映射
		// shiroFilterFactoryBean.setLoginUrl("/login");
		// 设置无权限时跳转的 url,权限认证失败的时候回跳转到该url
		// shiroFilterFactoryBean.setUnauthorizedUrl("/login");
		// shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized/无权限");

		// --------------------------------设置已有过滤器过滤规则

		Map<String, String> filterRuleMap = new HashMap<>();
		// 所有请求通过我们自己的JWT Filter
		filterRuleMap.put("/**", "jwt");
		// 访问 /unauthorized/** 不通过JWTFilter
		filterRuleMap.put("/unauthorized/**", "anon");
		// 开放swagger接口
		filterRuleMap.put("/swagger-ui.html", "anon");
		filterRuleMap.put("/swagger-resources", "anon");
		filterRuleMap.put("/v2/api-docs", "anon");
		filterRuleMap.put("/webjars/springfox-swagger-ui/**", "anon");

		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterRuleMap);
		System.out.println("Shiro拦截器工厂类注入成功");
		return shiroFilterFactoryBean;
	}

	/**
	 * 注入 securityManager
	 */
	@Bean
	public SecurityManager securityManager(CustomRealm customRealm) {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		// 设置自定义 realm.
		securityManager.setRealm(customRealm);

		/*
		 * 关闭shiro自带的session，详情见文档
		 * http://shiro.apache.org/session-management.html#SessionManagement-
		 * StatelessApplications%28Sessionless%29
		 */
		DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
		DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
		defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
		subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
		securityManager.setSubjectDAO(subjectDAO);
		return securityManager;
	}

	/**
	 * 添加注解支持
	 */
	@Bean
	public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
		// 强制使用cglib，防止重复代理和可能引起代理出错的问题
		// https://zhuanlan.zhihu.com/p/29161098
		defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
		return defaultAdvisorAutoProxyCreator;
	}

	@Bean
	public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
		AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
		advisor.setSecurityManager(securityManager);
		return advisor;
	}

	@Bean
	public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}
}