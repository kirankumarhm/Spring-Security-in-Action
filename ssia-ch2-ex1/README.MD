# Spring Security in Action

## Chapter 1

Starting your first project

Let’s create the first web application project, exposing a REST endpoint by creating the project and adding the correct dependencies
  
    <dependency>  
        <groupId>org.springframework.boot</groupId>  
        <artifactId>spring-boot-starter-security</artifactId>  
    </dependency>  

  
    <dependency>  
        <groupId>org.springframework.boot</groupId>  
        <artifactId>spring-boot-starter-web</artifactId>  
    </dependency>
  

    import org.springframework.boot.SpringApplication;  
    import org.springframework.boot.autoconfigure.SpringBootApplication;  
    
    @SpringBootApplication  
    public class Main {  
        public static void main(String[] args) {  
            SpringApplication.*run*(Main.class, args);  
        }  
    }
  

    import org.springframework.web.bind.annotation.GetMapping;  
    import org.springframework.web.bind.annotation.RestController;  
    
    @RestController  
    public class HelloController {  
    
        @GetMapping("/hello")  
        public String hello() {  
            return "Hello!";  
        }  
    }
  
You’ll see how, without doing much, Spring Security secures this endpoint using HTTP Basic authentication. HTTP Basic is a way a web app authenticates a user by means of a set of credentials (username and password) that the app gets in the header of the HTTP request.
  
Just by creating the project and adding the correct dependencies, Spring Boot applies default configurations, including a username and a password when you start the application.
  
curl http://localhost:8080/hello

![](../media/14c4a5532d96a1ce6a5aae42d20e7973.png)
  
The @RestController annotation registers the bean in the context and tells
  
Spring that the application uses this instance as a web controller. Also, the annotation specifies that the application has to set the response body of the HTTP response from the method’s return value. The @GetMapping annotation maps the /hello path to the implemented method through a GET request. Once you run the application, besides the other lines in the console, you should see something that looks similar to this:
  
Using generated security password: 93a01cf0-794b-4b98-86ef-54860f36f7f3
  


curl <http://localhost:8080/hello>

  

And the response to the call:
  


    {
    "status":401,
    "error":"Unauthorized",
    "message":"Unauthorized",
    "path":"/hello"
    }
