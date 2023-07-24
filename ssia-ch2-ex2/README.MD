# Spring Security in Action

## Chapter 1

##### Overriding default configurations

The main components acting in the authentication process for Spring Security and the
relationships among these. This architecture represents the backbone of implementing
authentication with Spring Security. We’ll refer to it often throughout the book when discussing different implementations for authentication and authorization.

![alt text](D:\Kiran\Practice\Java\IntelliJ-Workspace\spring_security_in_action_source_code\media\authentication-process.png)

1. The authentication filter delegates the authentication request to the
authentication manager and, based on the response, configures the
security context.
2. The authentication manager uses the authentication provider to process
authentication.
3. The authentication provider implements the authentication logic.
4. The user details service implements user management responsibility,
which the authentication provider uses in the authentication logic.
5. The password encoder implements password management, which the
authentication provider uses in the authentication logic.
6. The security context keeps the authentication data after the
authentication process.

In the following paragraphs, I’ll discuss these autoconfigured beans:

* UserDetailsService
* PasswordEncoder

	The PasswordEncoder does two things:
	* 	Encodes a password (usually using an encryption or a hashing algorithm)
	* 	Verifies if the password matches an existing encoding

Let’s create the Spring Boot web application project, exposing a REST endpoint by creating the project and adding the correct dependencies in pom.xml

```
	<dependency>  
		<groupId>org.springframework.boot</groupId>  
		<artifactId>spring-boot-starter-security</artifactId>  
	</dependency>

	<dependency>  
		<groupId>org.springframework.boot</groupId>  
		<artifactId>spring-boot-starter-web</artifactId>  
	</dependency>
```
  
Main.java
```
	import org.springframework.boot.SpringApplication;  
	import org.springframework.boot.autoconfigure.SpringBootApplication;  

	@SpringBootApplication  
	public class Main {  
		public static void main(String[] args) {  
			SpringApplication.run(Main.class, args);  
		}  
	}
```  
  
HelloController.java  
```
	import org.springframework.web.bind.annotation.GetMapping;  
	import org.springframework.web.bind.annotation.RestController;  

	@RestController  
	public class HelloController {  
		@GetMapping("/hello")  
		public String hello() {  
			return "Hello!";  
		}  
	}
```
  
You’ll see how, without doing much, Spring Security secures this endpoint using HTTP Basic authentication. HTTP Basic is a way a web app authenticates a user by means of a set of credentials (username and password) that the app gets in the header of the HTTP request.
  
Just by creating the project and adding the correct dependencies, Spring Boot applies default configurations, including a username and a password when you start the application.
  
```curl http://localhost:8080/hello```
  
![](../media/14c4a5532d96a1ce6a5aae42d20e7973.png)
  
The @RestController annotation registers the bean in the context and tells Spring that the application uses this instance as a web controller. Also, the annotation specifies that the application has to set the response body of the HTTP response from the method’s return value. The @GetMapping annotation maps the /hello path to the implemented method through a GET request. Once you run the application, besides the other lines in the console, you should see something that looks similar to this:
  
**Using generated security password: 93a01cf0-794b-4b98-86ef-54860f36f7f3**
  
```curl http://localhost:8080/hello```
  
And the response to the call:
  
```
	{
		"status":401,
		"error":"Unauthorized",
		"message":"Unauthorized",
		"path":"/hello"
	}
```

This implementation only registers the default credentials in the internal memory of the application. These default credentials are “user” with a default password that’s a universally unique identifier (UUID). This default password is randomly generated when
the Spring context is loaded (at the app startup). At this time, the application writes the password to the console where you can see it.
  
This default implementation serves only as a proof of concept and allows us to see that the dependency is in place.The implementation stores the credentials in-memory—the application doesn’t persist the credentials. This approach is suitable for examples or proof of concepts.
