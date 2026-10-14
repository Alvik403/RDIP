<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Вход · Реестр ДиП</title>
  <link rel="stylesheet" href="${url.resourcesPath}/css/login.css">
</head>
<body>
  <main class="card">
    <div class="brand">
      <strong>Реестр договоров и платежей</strong>
      <span>ДиП</span>
    </div>
    <h1>Вход</h1>
    <#if message?has_content && message.type != "warning">
      <div class="alert ${message.type}">${kcSanitize(message.summary)?no_esc}</div>
    </#if>
    <#if realm.password>
      <form action="${url.loginAction}" method="post">
        <#if !usernameHidden??>
          <label for="username">Имя пользователя</label>
          <input id="username" name="username" value="${login.username!''}" autocomplete="username" autofocus required>
        </#if>
        <label for="password">Пароль</label>
        <input id="password" name="password" type="password" autocomplete="current-password" <#if usernameHidden??>autofocus</#if> required>
        <input type="hidden" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>>
        <button name="login" type="submit">Войти</button>
      </form>
    </#if>
  </main>
</body>
</html>
