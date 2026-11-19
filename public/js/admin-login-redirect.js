(function () {
  var body = document.body;
  var username = body ? body.getAttribute('data-admin-login-user') : '';
  if (username) {
    try {
      sessionStorage.setItem('adminLoginToken', username);
    } catch (_e) {
      // ignore
    }
  }
  window.location.replace('/');
})();
