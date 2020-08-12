## Shiro

* shiro-stu 项目是Shiro的Java的基础语法demo。  

* springboot-shiro 项目是Shiro基于web的项目，通过SpringBoot整合Shiro和Sitemesh，前端使用sb-admin-1.0.4，实现用户的密码加密，身份认证和授权判断。  


Shiro 核心功能案例讲解 基于SpringBoot 有源码
Shiro 核心功能案例讲解 基于SpringBoot 有源码
从实战中学习Shiro的用法。本章使用SpringBoot快速搭建项目。整合SiteMesh框架布局页面。整合Shiro框架实现用身份认证，授权，数据加密功能。通过本章内容，你将学会用户权限的分配规则，SpringBoot整合Shiro的配置，Shiro自定义Realm的创建，Shiro标签式授权和注解式授权的使用场景，等实战技能，还在等什么，快来学习吧！

技术：SpringBoot，Shiro，SiteMesh，Spring，SpringDataJpa，SpringMVC，Bootstrap-sb-admin-1.0.4
说明：前端使用的是Bootstrap-sb-admin模版。注意文章贴出的代码可能不完整，请以github上源码为主，谢谢！
源码：https://github.com/ITDragonBlog/daydayup/tree/master/Shiro 喜欢的朋友可以鼓励（star）下。
效果图：



Shiro 功能介绍
四个核心：登录认证，权限验证，会话管理，数据加密。
六个支持：支持WEB开发，支持缓存，支持线程并发验证，支持测试，支持用户切换，支持"记住我"功能。

• Authentication ：身份认证，也可以理解为登录，验证用户身份。
• Authorization ：权限验证，也可以理解为授权，验证用户是否拥有某个权限；即判断用户是否能进行什么操作。
• Session Manager ：会话管理，用户登录后就是一次会话，在退出前，用户的所有信息都在会话中。
• Cryptography ：数据加密，保护数据的安全性，常见的有密码的加盐加密。
• Web Support ：支持Web开发。
• Caching ：缓存，Shiro将用户信息、拥有的角色/权限数据缓存，以提高程序效率。
• Concurrency ：支持多线程应用的并发验证，即在一个线程中开启另一个线程，Shiro能把权限自动传播过去。
• Testing ：提供测试支持。
• Run As ：允许一个用户以另一个用户的身份进行访问；前提是两个用户运行切换身份。
• Remember Me ：记住我，常见的功能，即登录一次后，在指定时间内免登录。

Shiro 功能介绍

Shiro 架构介绍
三个角色：当前用户 Subject，安全管理器 SecurityManager，权限配置域 Realm。

• Subject ：代表当前用户，提供了很多方法，如login和logout。Subject 只是一个门面，与Subject的所有交互都会委托给SecurityManager，SecurityManager才是真正的执行者；
• SecurityManager ：安全管理器；Shiro的核心，它负责与Shiro的其他组件进行交互，即所有与安全有关的操作都会与SecurityManager 交互；且管理着所有的 Subject；
• Realm ：Shiro 从 Realm 获取安全数据（如用户、角色、权限），SecurityManager 要验证用户身份，必需要从 Realm 获取相应的用户信息，判断用户身份是否合法，判断用户角色或权限是否授权。

SpringBoot 整合SiteMesh
SiteMesh 是一个网页布局和修饰的框架，利用它可以将网页的内容和页面结构分离，以达到页面结构共享的目的。

SiteMesh 统一了页面的风格，减少了重复代码，提高了页面的复用率，是一款值得我们去学习的框架（也有很多坑）。当然，今天的主角是Shiro，这里只介绍它的基本用法。
SpringBoot 整合SiteMesh只需二个步骤：
第一步：配置拦截器FIlter，并在web中注册bean。
第二步：创建装饰页面，引入常用的css和js文件，统一系统样式。

配置拦截器FIlter
指定拦截的URL请求路径，指定装饰页面的文件全路径，指定不需要拦截的URL请求路径。这里拦截所有请求到装饰页面，只有登录页面和静态资源不拦截。

import org.sitemesh.builder.SiteMeshFilterBuilder;
import org.sitemesh.config.ConfigurableSiteMeshFilter;
/**
 * 配置SiteMesh拦截器FIlter，指定装饰页面和不需要拦截的路径
 * @author itdragon
 */
public class WebSiteMeshFilter extends ConfigurableSiteMeshFilter{  
  
    @Override  
    protected void applyCustomConfiguration(SiteMeshFilterBuilder builder) {  
        builder.addDecoratorPath("/*", "/WEB-INF/layouts/default.jsp")  // 配置装饰页面
               .addExcludedPath("/static/*") 	// 静态资源不拦截
               .addExcludedPath("/login**");  	// 登录页面不拦截
    }  

}
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
/**
 * web.xml 配置
 * @author itdragon
 */
@Configuration
public class WebConfig {

	@Bean	// 配置siteMesh3
	public FilterRegistrationBean siteMeshFilter(){
		FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
		WebSiteMeshFilter siteMeshFilter = new WebSiteMeshFilter();
		filterRegistrationBean.setFilter(siteMeshFilter);
		return filterRegistrationBean;
	}
	
}
创建装饰页面
SiteMesh语法
<sitemesh:write property='title'/> : 被修饰页面title的内容会在这里显示。
<sitemesh:write property='head'/> : 被修饰页面head的内容会在这里显示，除了title。
<sitemesh:write property='body'/> : 被修饰页面body的内容会在这里显示。
需要注意的是：SiteMesh的jar有OpenSymphony（最新版是2009年）和Apache（最新版是2015年），两者用法是有差异的。笔者选择的是Apache版本的jar。

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%> 
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%> 
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<meta name="viewport" content="initial-scale=1.0, width=device-width, user-scalable=no" />
		<title>ITDragon系统-<sitemesh:write property='title'/></title>
		<link type="image/x-icon" href="images/favicon.ico" rel="shortcut icon">
		<c:set var="ctx" value="${pageContext.request.contextPath}" />
		<link href="${ctx}/static/sb-admin-1.0.4/css/bootstrap.min.css" rel="stylesheet">
	    <link href="${ctx}/static/sb-admin-1.0.4/css/sb-admin.css" rel="stylesheet">
		<sitemesh:write property='head'/>
	</head>
	<body>
		<div id="wrapper">
			<%@ include file="/WEB-INF/layouts/header.jsp"%>
			<div class='mainBody'>
		      <sitemesh:write property='body'/>
		    </div>
		</div>
	    <script src="${ctx}/static/sb-admin-1.0.4/js/jquery.js"></script>
	    <script src="${ctx}/static/sb-admin-1.0.4/js/bootstrap.min.js"></script>
	</body>
</html>
SpringBoot 整合Shiro
这是本章的核心知识点，SpringBoot 整合Shiro 有三个步骤：
第一步：创建实体类：用户，角色，权限。确定三者关系，以方便Realm的授权工作。
第二步：创建自定义安全数据源Realm：负责用户登录认证，用户操作授权。
第三步：创建Spring整合Shiro配置类：配置拦截规则，生命周期，安全管理器，安全数据源，等。

创建实体类
实体类：User，SysRole，SysPermission。
权限设计思路：
1). 角色表确定系统菜单资源，权限表确定菜单操作资源。
2). 用户主要通过角色来获取权限，且一个用户可以拥有多个角色（不推荐，但必须支持该功能）。
3). 一个角色可以拥有多个权限，同时也可以有用多个用户。
4). 一个权限可以被多个角色使用。
5). 工作都是从易到难，我们可以先从“一个用户拥有一个角色，一个角色拥有多个权限”开始。
有了上面的分析，三个实体类代码如下，省略了get/set方法。

import java.util.List;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
/**
 * 用户实体类
 * @author itdragon
 */
@Table(name="itdragon_user_shiro")
@Entity
public class User {
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Long id;						// 自增长主键，默认ID为1的账号为超级管理员
	private String account;					// 登录的账号
	private String userName;				// 注册的昵称
	@Transient
	private String plainPassword; 			// 登录时的密码，不持久化到数据库
	private String password;				// 加密后的密码
	private String salt;					// 用于加密的盐
	private String iphone;					// 手机号
	private String email;					// 邮箱
	private String platform;				// 用户来自的平台
	private String createdDate;				// 用户注册时间
	private String updatedDate;				// 用户最后一次登录时间
	@ManyToMany(fetch=FetchType.EAGER)
    @JoinTable(name = "SysUserRole", joinColumns = { @JoinColumn(name = "uid") }, inverseJoinColumns ={@JoinColumn(name = "roleId") })
    private List<SysRole> roleList;			// 一个用户拥有多个角色
	private Integer status;					// 用户状态，0表示用户已删除
}
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
/**
 * 角色表，决定用户可以访问的页面
 * @author itdragon
 */
@Table(name="itdragon_sysrole")
@Entity
public class SysRole {
    @Id
    @GeneratedValue
    private Integer id; 
    private String role; 		// 角色
    private String description; // 角色描述
    private Boolean available = Boolean.FALSE; // 默认不可用
    //角色 -- 权限关系：多对多关系; 取出这条数据时，把它关联的数据也同时取出放入内存中
    @ManyToMany(fetch=FetchType.EAGER)
    @JoinTable(name="SysRolePermission",joinColumns={@JoinColumn(name="roleId")},inverseJoinColumns={@JoinColumn(name="permissionId")})
    private List<SysPermission> permissions;
    // 用户 - 角色关系：多对多关系;
    @ManyToMany
    @JoinTable(name="SysUserRole",joinColumns={@JoinColumn(name="roleId")},inverseJoinColumns={@JoinColumn(name="uid")})
    private List<User> users;
}
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
/**
 * 权限表，决定用户的具体操作
 * @author itdragon
 */
@Table(name = "itdragon_syspermission")
@Entity
public class SysPermission {
	@Id
	@GeneratedValue
	private Integer id;
	private String name; 		// 名称
	private String url; 		// 资源路径
	private String permission; 	// 权限字符串 如：employees:create,employees:update,employees:delete
	private Boolean available = Boolean.FALSE; // 默认不可用
	@ManyToMany
	@JoinTable(name = "SysRolePermission", joinColumns = { @JoinColumn(name = "permissionId") }, inverseJoinColumns = {@JoinColumn(name = "roleId") })
	private List<SysRole> roles;
}
创建自定义安全数据源Realm
Shiro 从 Realm 获取安全数据（如用户、角色、权限），SecurityManager 身份认证和权限认证都是从Realm中获取相应的用户信息，然后做比较判断是否有身份登录，是否有权限操作。
Shiro 支持多个Realm。同时也有不同的认证策略：
• FirstSuccessfulStrategy : 只要有一个Realm成功就返回，后面的忽略；
• AtLeastOneSuccessfulStrategy : 只要有一个Realm成功就通过，返回所有认证成功的信息，默认；
• AllSuccessfulStrategy : 必须所有Realm都成功才算通过

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import com.itdragon.pojo.SysPermission;
import com.itdragon.pojo.SysRole;
import com.itdragon.pojo.User;
import com.itdragon.service.UserService;

/**
 * 自定义安全数据Realm，重点
 * @author itdragon
 */
public class ITDragonShiroRealm extends AuthorizingRealm {
	
	private static final transient Logger log = LoggerFactory.getLogger(ITDragonShiroRealm.class);
	
	@Autowired
	private UserService userService;
	
	/**
	 * 授权
	 */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    	log.info("^^^^^^^^^^^^^^^^^^^^ ITDragon 配置当前用户权限");
    	String username = (String) principals.getPrimaryPrincipal();
    	User user = userService.findByAccount(username);
    	if(null == user){
            return null;
        }
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		for (SysRole role : user.getRoleList()) {
			authorizationInfo.addRole(role.getRole());	// 添加角色
			for (SysPermission permission : role.getPermissions()) {
				authorizationInfo.addStringPermission(permission.getPermission());	// 添加具体权限
			}
		}
        return authorizationInfo;
    }

    /**
     * 身份认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
    	log.info("^^^^^^^^^^^^^^^^^^^^ ITDragon 认证用户身份信息");
		String username = (String) token.getPrincipal(); // 获取用户登录账号
		User userInfo = userService.findByAccount(username); // 通过账号查加密后的密码和盐，这里一般从缓存读取
        if(null == userInfo){
            return null;
        }
		// 1). principal: 认证的实体信息. 可以是 username, 也可以是数据表对应的用户的实体类对象. 
		Object principal = username;
		// 2). credentials: 加密后的密码. 
		Object credentials = userInfo.getPassword();
		// 3). realmName: 当前 realm 对象的唯一名字. 调用父类的 getName() 方法
		String realmName = getName();
		// 4). credentialsSalt: 盐值. 注意类型是ByteSource
		ByteSource credentialsSalt = ByteSource.Util.bytes(userInfo.getSalt());
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
		return info;
    }
}
创建Spring整合Shiro配置类
第一步：配置Shiro拦截器，指定URL请求的权限。首先静态资源和登录请求匿名访问，然后是用户登出操作，最后是所有请求都需身份认证。Shiro拦截器优先级是从上到下，切勿将/**=authc，放在前面。
第二步：配置Shiro生命周期处理器，
第三步：配置自定义Realm，负责身份认证和授权。
第四步：配置安全管理器SecurityManager，Shiro的核心。

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
/**
 * Shiro 配置，重点
 * @author itdragon
 */
@Configuration
public class ShiroSpringConfig {

	private static final transient Logger log = LoggerFactory.getLogger(ShiroSpringConfig.class);

	/**
	 * 配置拦截器
	 *  
	 * 定义拦截URL权限，优先级从上到下 
	 * 1). anon  : 匿名访问，无需登录 
	 * 2). authc : 登录后才能访问 
	 * 3). logout: 登出
	 * 4). roles : 角色过滤器
	 * 
	 * URL 匹配风格
	 * 1). ?：匹配一个字符，如 /admin? 将匹配 /admin1，但不匹配 /admin 或 /admin/；
	 * 2). *：匹配零个或多个字符串，如 /admin* 将匹配 /admin 或/admin123，但不匹配 /admin/1；
	 * 2). **：匹配路径中的零个或多个路径，如 /admin/** 将匹配 /admin/a 或 /admin/a/b
	 * 
	 * 配置身份验证成功，失败的跳转路径
	 */
	@Bean
	public ShiroFilterFactoryBean shirFilter(DefaultWebSecurityManager securityManager) {
		log.info("^^^^^^^^^^^^^^^^^^^^ ITDragon 配置Shiro拦截工厂");
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
		filterChainDefinitionMap.put("/static/**", "anon");	// 静态资源匿名访问
		filterChainDefinitionMap.put("/employees/login", "anon");// 登录匿名访问
		filterChainDefinitionMap.put("/logout", "logout");	// 用户退出，只需配置logout即可实现该功能
		filterChainDefinitionMap.put("/**", "authc");		// 其他路径均需要身份认证，一般位于最下面，优先级最低
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		shiroFilterFactoryBean.setLoginUrl("/login");		// 登录的路径
		shiroFilterFactoryBean.setSuccessUrl("/dashboard");	// 登录成功后跳转的路径
		shiroFilterFactoryBean.setUnauthorizedUrl("/403");	// 验证失败后跳转的路径
		return shiroFilterFactoryBean;
	}
	
	/**
     * 配置Shiro生命周期处理器
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }
    
    /**
     * 自动创建代理类，若不添加，Shiro的注解可能不会生效。
     */
    @Bean
    @DependsOn({"lifecycleBeanPostProcessor"})
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }
    
    /**
     * 开启Shiro的注解
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager());
        return authorizationAttributeSourceAdvisor;
    }
	
    /**
     * 配置加密匹配，使用MD5的方式，进行1024次加密
     */
	@Bean
	public HashedCredentialsMatcher hashedCredentialsMatcher() {
		HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
		hashedCredentialsMatcher.setHashAlgorithmName("MD5");
		hashedCredentialsMatcher.setHashIterations(1024);
		return hashedCredentialsMatcher;
	}

	/**
	 * 自定义Realm，可以多个
	 */
	@Bean
	public ITDragonShiroRealm itDragonShiroRealm() {
		ITDragonShiroRealm itDragonShiroRealm = new ITDragonShiroRealm();
		itDragonShiroRealm.setCredentialsMatcher(hashedCredentialsMatcher());
		return itDragonShiroRealm;
	}

	/**
	 * SecurityManager 安全管理器；Shiro的核心
	 */
	@Bean
	public DefaultWebSecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setRealm(itDragonShiroRealm());
		return securityManager;
	}

}
实现业务逻辑
系统有四个菜单：控制面板 Dashboard，员工管理 Employees，权限管理 Permissions，角色管理 Roles 。
系统有三个角色：超级管理员 admin, 经理 manager, 普通员工 staff 。
业务的逻辑要求：

admin角色可以访问所有菜单，manager角色除了Roles菜单外都可以访问，staff角色只能访问Dashboard和Employees菜单 。
admin角色拥有删除用户信息的权限，其他两个角色没有权限。
实现业务逻辑步骤：
第一步：模拟数据，创建用户，角色，权限数据。
第二步：左侧菜单权限配置，需要用到Shiro的标签式授权。
第三步：在删除用户的Controller层方法上配置操作权限，需要用到Shiro的注解式授权。
第四步：权限验证失败统一处理。

配置数据
sql文件路径：https://github.com/ITDragonBlog/daydayup/tree/master/Shiro/springboot-shiro/sql
建议先执行sql文件，再启动项目。
用户密码通常采用加盐加密的方式，笔者采用MD5的加密方式，以UUID作为盐，进行1024次加密。代码如下：

import java.util.UUID;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import com.itdragon.pojo.User;
/**
 * 工具类
 * @author itdragon
 */
public class ItdragonUtils {
	
	private static final String ALGORITHM_NAME = "MD5";
	private static final Integer HASH_ITERATIONS = 1024;
	
	public static void entryptPassword(User user) {
		String salt = UUID.randomUUID().toString();
		String temPassword = user.getPlainPassword();
		Object md5Password = new SimpleHash(ALGORITHM_NAME, temPassword, ByteSource.Util.bytes(salt), HASH_ITERATIONS);
		user.setSalt(salt);
		user.setPassword(md5Password.toString());
	}

}
左侧菜单权限配置
系统使用了SiteMesh框架，左侧菜单页面属于修饰页面的一部分。只需要在一个文件中添加shiro的标签，就可以在整个系统生效，耦合性很低。
<shiro:guest> : 允许游客访问的代码块
<shiro:user> : 允许已经验证或者通过"记住我"登录的用户才能访问的代码块。
<shiro:authenticated> : 只有通过登录操作认证身份，而并非通过"记住我"登录的用户才能访问的代码块。
<shiro:notAuthenticated> : 未登录的用户显示的代码块。
<shiro:principal> : 显示当前登录的用户信息。
<shiro:hasRole name="admin"> ： 只有拥有admin角色的用户才能访问的代码块。
<shiro:hasAnyRoles name="admin,manager"> ： 只有拥有admin或者manager角色的用户才能访问的代码块。
<shiro:lacksRole name="admin"> : 没有admin角色的用户显示的代码块
<shiro:hasPermission name="admin:delete"> : 只有拥有"admin:delete"权限的用户才能访问的代码块。
<shiro:lacksPermission name="admin:delete"> : 没有"admin:delete"权限的用户显示的代码块。

<div class="collapse navbar-collapse navbar-ex1-collapse">
	<ul class="nav navbar-nav side-nav itdragon-nav">
		<li class="active">
			<a href="/dashboard"><i class="fa fa-fw fa-dashboard"></i> Dashboard</a>
		</li>
		<li>
			<a href="/employees"><i class="fa fa-fw fa-bar-chart-o"></i> Employees</a>
		</li>
		<!-- 只有角色为admin或manager的用户才有权限访问  -->
		<shiro:hasAnyRoles name="admin,manager">
		<li>
			<a href="/permission"><i class="fa fa-fw fa-table"></i> Permissions</a>
		</li>
		</shiro:hasAnyRoles>
		<!-- 只有角色为admin的用户才有权限访问  -->
		<shiro:hasRole name="admin">
		<li>
			<a href="/roles"><i class="fa fa-fw fa-file"></i> Roles</a>
		</li>
		</shiro:hasRole>
	</ul>
</div>
在操作上添加权限
Shiro常见的权限注解有：
@RequiresAuthentication : 表示当前 Subject 已经认证登录的用户才能调用的代码块。
@RequiresUser : 表示当前 Subject 已经身份验证或通过记住我登录的。
@RequiresGuest : 表示当前 Subject 没有身份验证，即是游客身份。
@RequiresRoles(value={"admin", "user"}, logical=Logical.AND) : 表示当前 Subject 需要角色 admin和user
@RequiresPermissions (value={"user:update", "user:delete"}, logical= Logical.OR) : 表示当前 Subject 需要权限 user:update或user:delete。
这里值得注意的是：如果你的注解没有生效，很可能没有配置Shiro注解开启的问题。

@RequestMapping(value = "delete/{id}")
@RequiresPermissions(value={"employees:delete"})
public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
	userService.deleteUser(id);
	redirectAttributes.addFlashAttribute("message", "删除用户成功");
	return "redirect:/employees";
}
权限验证失败统一处理
Shiro提供权限验证失败跳转页面的功能，但这个逻辑是不友好的。我们需要统一处理权限验证失败，并返回执行失败的页面。

import org.apache.shiro.web.util.WebUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
/**
 * 异常统一处理
 * @author itdragon
 */
@ControllerAdvice
public class ExceptionController {
	
	@ExceptionHandler(org.apache.shiro.authz.AuthorizationException.class)
    public String handleException(RedirectAttributes redirectAttributes, Exception exception, HttpServletRequest request) {
        redirectAttributes.addFlashAttribute("message", "抱歉！您没有权限执行这个操作，请联系管理员！");
		String url = WebUtils.getRequestUri(request);
		return "redirect:/" + url.split("/")[1];	// 请求的规则 : /page/operate
    }
	
}
Shiro和SpringSecurity
Shiro使用更简单，更容易上手。
Spring Security功能更强大，和Spring无缝整合，但学习门槛比Shiro高。
我的建议是两个都可以学习，谁知道公司下一秒会选择什么框架。。。
总结
Shiro 四个核心功能：身份认证，授权，数据加密，Seesion管理。
Shiro 三个重要角色：Subject，SecurityManager，Realm。
Shiro 五个常见开发：自定义Realm，配置拦截器，标签式授权控制菜单，注解式授权控制操作，权限不够异常统一处理。
项目搭建推荐从拦截器开始，然后再是身份认证，角色权限认证，操作权限认证。
Shiro 其他知识后续介绍。
到这里Shiro 核心功能案例讲解 基于SpringBoot 的文章就写完了，一个基本的系统也搭完了。还有很多缺陷和建议，不吝赐教！如果文章对你有帮助，可以点个"推荐"，也可以"关注"我，获得更多丰富的知识。

其他知识查考文献
Shiro 权限注解 ：http://blog.csdn.net/w_stronger/article/details/73109248

Spring @ControllerAdvice注解 ： http://blog.csdn.net/jackfrued/article/details/76710885

bootstrap 模块页面 ： https://startbootstrap.com/template-categories/all/
