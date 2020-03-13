package com.lx.shiro.filter;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;

import com.lx.shiro.bean.JWTAuthenticationToken;
import com.lx.shiro.mapper.WhiteUrlMapper;
import com.lx.shiro.pojo.WhiteUrl;
import com.lx.shiro.util.LogVo;
import com.lx.shiro.util.SpringUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * Created with IntelliJ IDEA
 *
 * @Author yuanhaoyue swithaoy@gmail.com
 * @Description preHandle->isAccessAllowed->isLoginAttempt->executeLogin
 * @Date 2018-04-08
 * @Time 12:36
 */
@Component
@Slf4j
public class JWTFilter extends BasicHttpAuthenticationFilter {
	private Logger logger = log;
	
	
	
	private WhiteUrlMapper whiteUrlMapper;
	

	/**
	 * 如果带有 token，则对 token 进行检查，否则直接通过
	 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws UnauthorizedException {
		// 判断请求的请求头是否带上 "Token"
		logger.info("进入过滤器");
		if (isLoginAttempt(request, response)) {
			// 如果存在，则进入 executeLogin 方法执行登入，检查 token 是否正确
			try {
				executeLogin(request, response);
				return true;
			} catch (Exception e) {
				logger.info("认证错误：" + e.getMessage());
				responseError(response, "认证错误，请重新登录!");
			}
		} else {
			// 如果请求头不存在token，则校验是否存在于白名单表中的url，不存在响应错误。
			if (whiteUrlMapper == null) {
				whiteUrlMapper = (WhiteUrlMapper) SpringUtils.getBean(WhiteUrlMapper.class);
			}
			List<WhiteUrl> WhiteUrlList = whiteUrlMapper.selectAll();
			List<String> urlList = new ArrayList<String>();
			WhiteUrlList.stream().forEach(data -> {
				urlList.add(data.getUrl());
			});
			HttpServletRequest httpServletRequest = (HttpServletRequest) request;
			String url = httpServletRequest.getRequestURI();
			if(!urlList.contains(url)) {
				logger.info("认证错误：" + url);
				responseError(response, url+"无权限访问，请登录后访问!");
			}
		}
		// 如果请求头不存在 Token，则可能是执行登陆操作或者是游客状态访问，无需检查 token，直接返回 放行
		log.info("过滤器通过!");
		return true;
	}

	/**
	 * 判断用户是否想要登入。 检测 header 里面是否包含 Token 字段
	 */
	@Override
	protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
		HttpServletRequest req = (HttpServletRequest) request;
		String token = req.getHeader("Token");
		return token != null;
	}

	/**
	 * 执行登陆操作
	 */
	@Override
	protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
		// 如果请求头有token，则每次访问都进行jet的token校验
		// 1.校验token是否正确
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		String token = httpServletRequest.getHeader("Token");
		LogVo logVo = new LogVo();
		logVo.setToken(token);
		JWTAuthenticationToken jwtAuthenticationToken = new JWTAuthenticationToken();
		jwtAuthenticationToken.setLogVo(logVo);
		// 进入customrealm进行登录校验
		getSubject(request, response).login(jwtAuthenticationToken);

		// 2.校验前端传入的角色
		if (!StringUtils.isEmpty(httpServletRequest.getParameter("role"))) {
			getSubject(request, response).checkRole(logVo.getRole());
		}
		String url = httpServletRequest.getRequestURI();
		// 3.校验前端请求路径权限
		getSubject(request, response).checkPermission(url);

		// 如果没有抛出异常则代表登入成功，返回true
		return true;
	}

	/**
	 * 对跨域提供支持
	 */
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
		httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
		httpServletResponse.setHeader("Access-Control-Allow-Headers",
				httpServletRequest.getHeader("Access-Control-Request-Headers"));
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpServletResponse.setStatus(HttpStatus.OK.value());
			return false;
		}
		return super.preHandle(request, response);
	}

	/**
	 * 将非法请求跳转到 /unauthorized/**
	 */
	private void responseError(ServletResponse response, String message) {
		try {
			log.error(message);
			HttpServletResponse httpServletResponse = (HttpServletResponse) response;
			// 设置编码，否则中文字符在重定向时会变为空字符串
			message = URLEncoder.encode(message, "UTF-8");
			httpServletResponse.sendRedirect("/unauthorized/" + message);
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

}
