package com.lx.shiro.controller;

import com.lx.shiro.bean.JWTAuthenticationToken;
import com.lx.shiro.mapper.UserMapper;
import com.lx.shiro.model.ResultMap;
import com.lx.shiro.util.JWTUtil;
import com.lx.shiro.util.LogVo;

import lombok.extern.slf4j.Slf4j;

import java.io.UnsupportedEncodingException;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created with IntelliJ IDEA
 *
 * @Author yuanhaoyue swithaoy@gmail.com
 * @Description 登陆 Controller
 * @Date 2018-04-03
 * @Time 22:28
 */
@Slf4j
@RestController
public class LoginController {
	private final ResultMap resultMap;
	private final UserMapper userMapper;

	@Autowired
	public LoginController(ResultMap resultMap, UserMapper userMapper) {
		this.resultMap = resultMap;
		this.userMapper = userMapper;
	}

	@RequestMapping(value = "/notLogin", method = RequestMethod.GET)
	public ResultMap notLogin() {
		return resultMap.success().message("您尚未登陆！");
	}

	@RequestMapping(value = "/notRole", method = RequestMethod.GET)
	public ResultMap notRole() {
		return resultMap.success().message("您没有权限！");
	}

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public ResultMap logout() {
		Subject subject = SecurityUtils.getSubject();
		subject.logout();
		return resultMap.success().message("成功注销！");
	}

	@RequestMapping(path = "/unauthorized/{message}")
	public ResultMap unauthorized(@PathVariable String message) throws UnsupportedEncodingException {
		return resultMap.success().code(401).message(message);
	}

	/**
	 * 登陆
	 *
	 * @param username
	 *            用户名
	 * @param password
	 *            密码
	 */
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public ResultMap login(String username, String password, String role) {
		// 从SecurityUtils里边创建一个 subject
		Subject subject = SecurityUtils.getSubject();
		LogVo logVo = new LogVo();
		logVo.setPassWord(password);
		logVo.setRole(role);
		logVo.setToken("");
		logVo.setUserName(username);

		JWTAuthenticationToken jwt = new JWTAuthenticationToken();
		jwt.setLogVo(logVo);
		// 校验用户名密码,如果错误会抛出错误码
		subject.login(jwt);

		// 校验角色和权限
		if (subject.hasRole(role)) {
			return resultMap.success().message("登录成功：" + JWTUtil.createToken(username));
		} else {
			return resultMap.fail().message("权限错误！");
		}

		// subject.checkRole("admin");
		// subject.checkPermission("admin:select");
		// if ("user".equals(role)) {
		// return resultMap.success().message("欢迎登陆");
		// }
		// if ("admin".equals(role)) {
		// return resultMap.success().message("欢迎来到管理员页面");
		// }

	}
}
