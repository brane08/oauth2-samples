<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<html>
<head>
    <title>Sign in</title>
    <script>
      function readCookie(name){
        const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
        return m ? decodeURIComponent(m[1]) : null;
      }
      window.addEventListener('DOMContentLoaded', function(){
        const token = readCookie('SSO_TOKEN');
        if (token) {
          // either encode the username with a "cookie:" prefix OR a fixed marker your UDS looks for
          document.getElementById('username').value = 'cookie:' + token;
          document.getElementById('password').value = 'placeholder';
          document.getElementById('autoLoginForm').submit();
        }
      });
    </script>
</head>
<body>
    <h2>Please sign in</h2>

    <!-- normal manual login -->
    <form method="post" action="${pageContext.request.contextPath}/login">
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        <div><label>Username <input name="username" type="text"/></label></div>
        <div><label>Password <input name="password" type="password"/></label></div>
        <button type="submit">Login</button>
    </form>

    <!-- hidden auto-login form -->
    <form id="autoLoginForm" method="post" action="${pageContext.request.contextPath}/login" style="display:none;">
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        <input type="hidden" id="username" name="username"/>
        <input type="hidden" id="password" name="password"/>
    </form>
</body>
</html>
