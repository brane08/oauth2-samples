<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html lang="en">
<head>
    <title>Custom Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
    <meta name="apple-mobile-web-app-capable" content="yes"/>
    <meta name="apple-mobile-web-app-status-bar-style" content="black"/>
    <script>
      window.onload = function () {
        const match = document.cookie.match(/SSO_TOKEN=([^;]+)/);
        if (match) {
          const username = "cookie:" + decodeURIComponent(match[1]);
          document.getElementById("username").value = username;
          document.getElementById("password").value = "placeholder";
          document.getElementById("loginForm").submit();
        }
      };
    </script>
</head>
<body>
    <h2>Login Page</h2>
    <form id="loginForm" method="post" action="<c:url value='/login'/>">
        <div>
            <label for="username">Username:</label>
            <input id="username" name="username" type="text"/>
        </div>
        <div>
            <label for="password">Password:</label>
            <input id="password" name="password" type="password"/>
        </div>
        <div>
            <input type="submit" value="Login"/>
        </div>
    </form>
</body>
</html>
