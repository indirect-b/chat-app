(function () {
  var token = '';

  function h() {
    return { 'Content-Type': 'application/json', 'x-admin-token': token };
  }

  function escapeHtml(t) {
    return String(t || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function go(sec, el) {
    document.querySelectorAll('[id^="s-"]').forEach(function (node) {
      node.classList.add('hidden');
    });
    var target = document.getElementById('s-' + sec);
    if (target) target.classList.remove('hidden');
    document.querySelectorAll('.nav').forEach(function (node) {
      node.classList.remove('on');
    });
    if (el) el.classList.add('on');
    if (sec === 'users') loadUsers();
    if (sec === 'reports') loadReports();
    if (sec === 'msgs') loadMsgs();
    if (sec === 'groups') loadGroups();
    if (sec === 'dash') loadStats();
    if (sec === 'rules') loadRules();
  }

  function doLogin() {
    var passEl = document.getElementById('adminPass');
    var p = passEl ? passEl.value : '';
    fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: p }),
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok) {
          token = p;
          document.getElementById('loginWrap').classList.add('hidden');
          document.getElementById('panel').classList.remove('hidden');
          loadStats();
        } else {
          document.getElementById('loginErr').textContent = 'رمز اشتباه است';
        }
      });
  }

  function loadStats() {
    fetch('/api/admin/stats', { headers: h() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) return;
        document.getElementById('st1').textContent = d.stats.totalUsers;
        document.getElementById('st2').textContent = d.stats.onlineUsers;
        document.getElementById('st3').textContent = d.stats.totalMessages;
        document.getElementById('st4').textContent = d.stats.totalGroups;
        document.getElementById('st5').textContent = d.stats.pendingReports;
        var max = Math.max.apply(null, d.stats.daily.map(function (x) { return x.count; }).concat([1]));
        var bar = document.getElementById('chartBar');
        var lbl = document.getElementById('chartLabels');
        bar.innerHTML = '';
        lbl.innerHTML = '';
        d.stats.daily.forEach(function (item) {
          var h2 = Math.max((item.count / max) * 100, 2);
          var barDiv = document.createElement('div');
          barDiv.className = 'bar';
          barDiv.style.height = h2 + '%';
          barDiv.setAttribute('data-val', String(item.count));
          bar.appendChild(barDiv);
          var lblDiv = document.createElement('div');
          lblDiv.className = 'bar-label';
          lblDiv.textContent = item.date.slice(5);
          lbl.appendChild(lblDiv);
        });
      });
  }

  function loadUsers() {
    fetch('/api/admin/users', { headers: h() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) return;
        var tbody = document.getElementById('usersTbl');
        tbody.innerHTML = d.users
          .map(function (u) {
            var uname = escapeHtml(u.username);
            var blockBtn = u.is_blocked
              ? '<button type="button" class="btn-sm btn-green" data-action="unblock" data-user="' + uname + '">رفع بلاک</button>'
              : '<button type="button" class="btn-sm btn-red" data-action="block" data-user="' + uname + '">بلاک</button>';
            return (
              '<tr>' +
              '<td><b>@' + uname + '</b>' + (u.is_blocked ? '<span class="badge bred badge-gap">مسدود</span>' : '') + '</td>' +
              '<td><span class="badge ' + (u.last_seen && !u.is_blocked ? 'bon' : 'boff') + '">' + (u.is_blocked ? '🚫 مسدود' : '⚫ آفلاین') + '</span></td>' +
              '<td>-</td>' +
              '<td class="action-cell">' +
              '<button type="button" class="btn-sm btn-cyan" data-action="login-as" data-user="' + uname + '">🔑 ورود</button>' +
              '<button type="button" class="btn-sm btn-red" data-action="kick" data-user="' + uname + '">کیک</button>' +
              blockBtn +
              '</td></tr>'
            );
          })
          .join('');
      });
  }

  function loadReports() {
    fetch('/api/admin/reports', { headers: h() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) return;
        var tbody = document.getElementById('reportsTbl');
        if (!d.reports.length) {
          tbody.innerHTML = '<tr><td colspan="6" class="muted-cell">گزارشی نیست</td></tr>';
          return;
        }
        tbody.innerHTML = d.reports
          .map(function (r) {
            var badgeClass = r.status === 'pending' ? 'byel' : r.status === 'resolved' ? 'bon' : 'bred';
            var badgeText = r.status === 'pending' ? 'در انتظار' : r.status === 'resolved' ? 'رسیدگی شد' : 'رد شد';
            return (
              '<tr>' +
              '<td>' + escapeHtml(r.reporter) + '</td>' +
              '<td>' + escapeHtml(r.reported_user) + '</td>' +
              '<td>' + escapeHtml(r.reason) + '</td>' +
              '<td class="ellipsis-cell">' + escapeHtml(r.message_text || '-') + '</td>' +
              '<td><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
              '<td class="action-cell">' +
              '<button type="button" class="btn-sm btn-green" data-action="resolve-report" data-id="' + escapeHtml(r.id) + '">✅</button>' +
              '<button type="button" class="btn-sm btn-red" data-action="dismiss-report" data-id="' + escapeHtml(r.id) + '">❌</button>' +
              '<button type="button" class="btn-sm" data-action="block" data-user="' + escapeHtml(r.reported_user) + '">🚫</button>' +
              '</td></tr>'
            );
          })
          .join('');
      });
  }

  function loadMsgs() {
    fetch('/api/admin/messages', { headers: h() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) return;
        var v = document.getElementById('msgsView');
        var entries = Object.entries(d.messages);
        if (!entries.length) {
          v.innerHTML = '<p class="muted-cell">پیامی وجود ندارد</p>';
          return;
        }
        v.innerHTML = entries
          .map(function (pair) {
            var rid = pair[0];
            var msgs = pair[1];
            return (
              '<div class="tbl-wrap">' +
              '<div class="room-header">🗂 ' + escapeHtml(rid.replace('group__', 'گروه: ').replace('__', ' ↔ ')) + '</div>' +
              '<table><thead><tr><th>فرستنده</th><th>پیام</th><th>زمان</th><th>حذف</th></tr></thead><tbody>' +
              msgs
                .map(function (m) {
                  return (
                    '<tr><td>' + escapeHtml(m.sender) + '</td><td>' + escapeHtml(m.text || '[فایل]') + '</td><td>' + escapeHtml(m.time) + '</td>' +
                    '<td><button type="button" class="btn-sm btn-red" data-action="del-msg" data-room="' + escapeHtml(rid) + '" data-id="' + escapeHtml(m.id) + '">حذف</button></td></tr>'
                  );
                })
                .join('') +
              '</tbody></table></div>'
            );
          })
          .join('');
      });
  }

  function loadGroups() {
    fetch('/api/admin/groups', { headers: h() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d.ok) return;
        var tbody = document.getElementById('groupsTbl');
        if (!d.groups.length) {
          tbody.innerHTML = '<tr><td colspan="3" class="muted-cell">گروهی نیست</td></tr>';
          return;
        }
        tbody.innerHTML = d.groups
          .map(function (g) {
            return (
              '<tr><td>' + escapeHtml(g.name) + '</td><td>' + escapeHtml(g.members.join(', ')) + '</td><td>' +
              escapeHtml(new Date(g.created_at).toLocaleDateString('fa-IR')) + '</td></tr>'
            );
          })
          .join('');
      });
  }

  function loadRules() {
    fetch('/api/settings/rules')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        document.getElementById('rulesText').value = d.rules || '';
      });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('loginBtn').addEventListener('click', doLogin);
    document.getElementById('adminPass').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') doLogin();
    });

    document.querySelectorAll('.nav[data-sec]').forEach(function (navEl) {
      navEl.addEventListener('click', function () {
        go(navEl.getAttribute('data-sec'), navEl);
      });
    });

    document.getElementById('refreshStatsBtn').addEventListener('click', loadStats);
    document.getElementById('createGroupBtn').addEventListener('click', function () {
      var name = document.getElementById('gName').value.trim();
      var members = document.getElementById('gMembers').value.split(',').map(function (m) { return m.trim(); }).filter(Boolean);
      if (!name || !members.length) return;
      fetch('/api/admin/create-group', { method: 'POST', headers: h(), body: JSON.stringify({ name: name, members: members }) })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('gMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ گروه ساخته شد' : d.msg;
        });
    });

    document.getElementById('addToGroupBtn').addEventListener('click', function () {
      fetch('/api/admin/add-to-group', {
        method: 'POST',
        headers: h(),
        body: JSON.stringify({
          groupId: document.getElementById('agId').value.trim(),
          username: document.getElementById('agUser').value.trim(),
        }),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('agMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ اضافه شد' : d.msg;
        });
    });

    document.getElementById('sendAnnounceBtn').addEventListener('click', function () {
      var text = document.getElementById('annText').value.trim();
      var imageUrl = document.getElementById('annImg').value.trim();
      if (!text) return;
      fetch('/api/admin/announce', { method: 'POST', headers: h(), body: JSON.stringify({ text: text, imageUrl: imageUrl }) })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('annMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ به ' + d.sent + ' نفر ارسال شد' : d.msg;
        });
    });

    document.getElementById('saveRulesBtn').addEventListener('click', function () {
      fetch('/api/admin/set-rules', {
        method: 'POST',
        headers: h(),
        body: JSON.stringify({ rules: document.getElementById('rulesText').value }),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('rulesMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ ذخیره شد' : 'خطا';
        });
    });

    document.getElementById('modeNormalBtn').addEventListener('click', function () { setMode('normal'); });
    document.getElementById('modeMaintBtn').addEventListener('click', function () { setMode('maintenance'); });

    function setMode(mode) {
      var msg = document.getElementById('maintMsg').value;
      fetch('/api/admin/set-mode', { method: 'POST', headers: h(), body: JSON.stringify({ mode: mode, msg: msg }) })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('serverMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ سرور حالت ' + (mode === 'normal' ? 'عادی' : 'به‌روزرسانی') + ' شد' : 'خطا';
          var cm = document.getElementById('currentMode');
          cm.textContent = mode === 'normal' ? 'عادی' : 'به‌روزرسانی';
          cm.className = mode === 'normal' ? 'mode-normal' : 'mode-maint';
        });
    }

    document.getElementById('blockUserBtn').addEventListener('click', function () {
      var username = document.getElementById('blockUser').value.trim();
      var reason = document.getElementById('blockReason').value.trim();
      var blockType = document.getElementById('blockType').value;
      var blockUntil = document.getElementById('blockUntil').value;
      if (!username) return;
      fetch('/api/admin/block', {
        method: 'POST',
        headers: h(),
        body: JSON.stringify({ username: username, reason: reason, blockType: blockType, blockUntil: blockUntil || null }),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('blockMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ کاربر مسدود شد' : 'خطا';
        });
    });

    document.getElementById('unblockUserBtn').addEventListener('click', function () {
      var username = document.getElementById('unblockUser').value.trim();
      if (!username) return;
      fetch('/api/admin/unblock', { method: 'POST', headers: h(), body: JSON.stringify({ username: username }) })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var p = document.getElementById('unblockMsg');
          p.className = d.ok ? 'ok' : 'err';
          p.textContent = d.ok ? '✅ مسدودیت برداشته شد' : 'خطا';
        });
    });

    document.addEventListener('click', function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest('button[data-action]') : null;
      if (!btn) return;
      var action = btn.getAttribute('data-action');
      var user = btn.getAttribute('data-user');
      var id = btn.getAttribute('data-id');
      var room = btn.getAttribute('data-room');

      if (action === 'kick' && user) {
        fetch('/api/admin/kick', { method: 'POST', headers: h(), body: JSON.stringify({ username: user }) })
          .then(function (r) { return r.json(); })
          .then(function (d) { if (d.ok) loadUsers(); });
      } else if (action === 'login-as' && user) {
        fetch('/api/admin/login-as', { method: 'POST', headers: h(), body: JSON.stringify({ username: user }) })
          .then(function (r) { return r.json(); })
          .then(function (d) { if (d.ok && d.url) window.location.assign(d.url); });
      } else if (action === 'block' && user) {
        document.getElementById('blockUser').value = user;
        go('server', document.querySelector('.nav[data-sec="server"]'));
      } else if (action === 'unblock' && user) {
        fetch('/api/admin/unblock', { method: 'POST', headers: h(), body: JSON.stringify({ username: user }) })
          .then(function (r) { return r.json(); })
          .then(function (d) { if (d.ok) loadUsers(); });
      } else if (action === 'resolve-report' && id) {
        fetch('/api/admin/report-action', { method: 'POST', headers: h(), body: JSON.stringify({ reportId: id, status: 'resolved' }) })
          .then(function () { loadReports(); });
      } else if (action === 'dismiss-report' && id) {
        fetch('/api/admin/report-action', { method: 'POST', headers: h(), body: JSON.stringify({ reportId: id, status: 'dismissed' }) })
          .then(function () { loadReports(); });
      } else if (action === 'del-msg' && id && room) {
        fetch('/api/admin/message', { method: 'DELETE', headers: h(), body: JSON.stringify({ roomId: room, msgId: id }) })
          .then(function () { loadMsgs(); });
      }
    });
  });
})();
