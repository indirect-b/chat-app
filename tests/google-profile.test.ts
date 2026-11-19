/**
 * Google profile sync — pure-function tests + wiring assertions.
 *
 * No network, no credentials, no Google calls: the profile
 * normalization helpers, the login-time sync decision (custom flags
 * win over Google), the profile-edit flag decision, and source-level
 * proof that both login flows and the profile endpoint use them.
 * The database itself (Postgres + JSON fallback) is not exercised
 * here — the SQL shapes are covered by the fallback branches in
 * db.ts and by the live check after deploy.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  GOOGLE_PHOTO_HOST,
  normalizeGooglePicture,
  normalizeGoogleProfileName,
  resolveGoogleProfileSync,
  resolveProfileUpdate,
} from '../src/server/profileSync';

const PHOTO = 'https://lh3.googleusercontent.com/a-/photo123';

describe('normalizeGoogleProfileName', () => {
  it('trims and keeps a normal name', () => {
    assert.equal(normalizeGoogleProfileName('  Mohammad Taha  '), 'Mohammad Taha');
  });

  it('strips control characters (no header/line injection via the name)', () => {
    assert.equal(normalizeGoogleProfileName('Ali\nReza\t'), 'AliReza');
  });

  it('caps at 100 characters', () => {
    assert.equal(normalizeGoogleProfileName('a'.repeat(150))?.length, 100);
  });

  it('returns null for empty / blank / non-string names', () => {
    assert.equal(normalizeGoogleProfileName(''), null);
    assert.equal(normalizeGoogleProfileName('   '), null);
    assert.equal(normalizeGoogleProfileName(undefined), null);
    assert.equal(normalizeGoogleProfileName(null), null);
    assert.equal(normalizeGoogleProfileName(42), null);
  });
});

describe('normalizeGooglePicture', () => {
  it('keeps a Google photo URL', () => {
    assert.equal(normalizeGooglePicture(PHOTO), PHOTO);
  });

  it('rejects any other host (tracking / spoofed photo URLs)', () => {
    assert.equal(normalizeGooglePicture('https://evil.example.com/p.jpg'), null);
    assert.equal(normalizeGooglePicture('https://photos.google.com/p.jpg'), null);
    assert.equal(normalizeGooglePicture('https://lh3.googleusercontent.com.evil.com/p.jpg'), null);
  });

  it('rejects http and unparsable values', () => {
    assert.equal(normalizeGooglePicture('http://lh3.googleusercontent.com/p.jpg'), null);
    assert.equal(normalizeGooglePicture('not a url'), null);
    assert.equal(normalizeGooglePicture(''), null);
    assert.equal(normalizeGooglePicture(undefined), null);
    assert.equal(normalizeGooglePicture(null), null);
  });

  it('pins exactly one photo host', () => {
    assert.equal(GOOGLE_PHOTO_HOST, 'lh3.googleusercontent.com');
  });
});

describe('resolveGoogleProfileSync (login-time merge)', () => {
  it('applies name + photo for a user with no custom flags', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: null, avatar: null, name_custom: 0, avatar_custom: 0 },
      { name: 'Sara', picture: PHOTO }
    );
    assert.deepEqual(merged, { display_name: 'Sara', avatar: PHOTO });
  });

  it('keeps a manually-set name but still updates the photo', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: 'My Name', avatar: null, name_custom: 1, avatar_custom: 0 },
      { name: 'Sara', picture: PHOTO }
    );
    assert.deepEqual(merged, { display_name: 'My Name', avatar: PHOTO });
  });

  it('keeps a manually-set avatar but still updates the name', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: null, avatar: '/api/media/abc', name_custom: 0, avatar_custom: 1 },
      { name: 'Sara', picture: PHOTO }
    );
    assert.deepEqual(merged, { display_name: 'Sara', avatar: '/api/media/abc' });
  });

  it('returns null when both fields are manually set (nothing to sync)', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: 'My Name', avatar: '/api/media/abc', name_custom: 1, avatar_custom: 1 },
      { name: 'Sara', picture: PHOTO }
    );
    assert.equal(merged, null);
  });

  it('never clears a stored value when the token carries none', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: 'Old Name', avatar: PHOTO, name_custom: 0, avatar_custom: 0 },
      { name: null, picture: null }
    );
    assert.equal(merged, null);
  });

  it('refreshes a non-custom field when Google changed it', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: 'Old Name', avatar: null, name_custom: 0, avatar_custom: 0 },
      { name: 'New Name', picture: null }
    );
    assert.deepEqual(merged, { display_name: 'New Name', avatar: null });
  });

  it('returns null when the Google values already match the stored ones', () => {
    const merged = resolveGoogleProfileSync(
      { display_name: 'Sara', avatar: PHOTO, name_custom: 0, avatar_custom: 0 },
      { name: 'Sara', picture: PHOTO }
    );
    assert.equal(merged, null);
  });

  it('treats rows created before the profile columns existed as empty', () => {
    const merged = resolveGoogleProfileSync(
      {},
      { name: 'Sara', picture: PHOTO }
    );
    assert.deepEqual(merged, { display_name: 'Sara', avatar: PHOTO });
  });
});

describe('resolveProfileUpdate (manual edit flags)', () => {
  it('raises the name flag only when the submitted name differs', () => {
    const next = resolveProfileUpdate(
      { display_name: 'Sara', avatar: null, name_custom: 0, avatar_custom: 0 },
      { display_name: 'Sara Ahmadi' }
    );
    assert.equal(next.display_name, 'Sara Ahmadi');
    assert.equal(next.name_custom, 1);
    assert.equal(next.avatar_custom, 0);
  });

  it('leaves both flags at 0 on a save that changes nothing', () => {
    const next = resolveProfileUpdate(
      { display_name: 'Sara', avatar: PHOTO, name_custom: 0, avatar_custom: 0 },
      { display_name: 'Sara', avatar: PHOTO }
    );
    assert.equal(next.name_custom, 0);
    assert.equal(next.avatar_custom, 0);
  });

  it('leaves unsubmitted fields untouched (older clients)', () => {
    const next = resolveProfileUpdate(
      { display_name: 'Sara', avatar: PHOTO, name_custom: 0, avatar_custom: 0 },
      {}
    );
    assert.deepEqual(next, {
      display_name: 'Sara',
      avatar: PHOTO,
      name_custom: 0,
      avatar_custom: 0,
    });
  });

  it('clearing the name (empty string) is a manual choice and raises the flag', () => {
    const next = resolveProfileUpdate(
      { display_name: 'Sara', avatar: null, name_custom: 0, avatar_custom: 0 },
      { display_name: '' }
    );
    assert.equal(next.display_name, null);
    assert.equal(next.name_custom, 1);
  });

  it('raises the avatar flag when a new photo is uploaded', () => {
    const next = resolveProfileUpdate(
      { display_name: null, avatar: PHOTO, name_custom: 0, avatar_custom: 0 },
      { avatar: '/api/media/new-avatar' }
    );
    assert.equal(next.avatar, '/api/media/new-avatar');
    assert.equal(next.avatar_custom, 1);
    assert.equal(next.name_custom, 0);
  });
});

describe('server wiring (source assertions)', () => {
  const serverSrc = fs.readFileSync(path.resolve(process.cwd(), 'server.ts'), 'utf8');
  const chatSrc = fs.readFileSync(
    path.resolve(process.cwd(), 'src/components/ChatApp.tsx'),
    'utf8'
  );

  it('both Google login flows share completeGoogleSignIn with the verified profile', () => {
    // /api/google-login (popup JSON) and /api/google-redirect (form POST)
    // must both verify the token and pass its profile into the shared
    // helper — otherwise one flow would silently skip the sync.
    const loginStart = serverSrc.indexOf("app.post('/api/google-login'");
    const loginBlock = serverSrc.slice(loginStart, loginStart + 2200);
    assert.match(loginBlock, /completeGoogleSignIn\(\s*email,\s*verified\.profile\s*\)/);

    const redirectStart = serverSrc.indexOf("app.post('/api/google-redirect'");
    const redirectBlock = serverSrc.slice(redirectStart, redirectStart + 2600);
    assert.match(redirectBlock, /completeGoogleSignIn\(\s*email,\s*verified\.profile\s*\)/);

    const helperStart = serverSrc.indexOf('async function completeGoogleSignIn');
    const helperBlock = serverSrc.slice(helperStart, helperStart + 2600);
    assert.match(helperBlock, /resolveGoogleProfileSync/);
    assert.match(helperBlock, /INSERT INTO users \(username, bale_chat_id, joined_at, recovery_code_hash, email, display_name, avatar, name_custom, avatar_custom\)/);
  });

  it('POST /api/user/update resolves the edit through resolveProfileUpdate and stores the flags', () => {
    const start = serverSrc.indexOf("app.post('/api/user/update'");
    const block = serverSrc.slice(start, start + 2200);
    assert.match(block, /resolveProfileUpdate/);
    assert.match(block, /display_name=\$4, name_custom=\$5, avatar_custom=\$6/);
    // The ownership gate must still be there (profile-auth fix).
    assert.match(block, /checkOwnUsername/);
  });

  it('the contacts endpoint returns the display name', () => {
    const start = serverSrc.indexOf("app.get('/api/contacts/:username'");
    const block = serverSrc.slice(start, start + 1200);
    assert.match(block, /u\.display_name/);
    assert.match(block, /display_name: r\.display_name/);
  });

  it('CSP allows the Google photo host in img-src and nothing else new', () => {
    const helmetStart = serverSrc.indexOf('helmet({');
    const helmetBlock = serverSrc.slice(helmetStart, serverSrc.indexOf('}));', helmetStart));
    assert.match(
      helmetBlock,
      /imgSrc:\s*\["'self'", 'data:', 'blob:', 'https:\/\/lh3\.googleusercontent\.com'\]/
    );
    // No wildcard image source, no other Google host in the Helmet block.
    assert.equal(helmetBlock.includes("'*'"), false);
    const googleHosts = (helmetBlock.match(/https:\/\/[a-z0-9.-]+\.googleusercontent\.com/g) || []).filter(
      (h, i, arr) => arr.indexOf(h) === i
    );
    assert.deepEqual(googleHosts, ['https://lh3.googleusercontent.com']);
  });

  it('the client shows the display name with a username fallback', () => {
    assert.match(chatSrc, /name: c\.display_name \|\| c\.username/);
    assert.match(chatSrc, /groupMemberProfiles\[msg\.sender\]\?\.display_name \|\| msg\.sender/);
    assert.match(chatSrc, /display_name: nameInput/);
  });

  it('Google photos render directly; other external avatar URLs render nothing (no token leak)', () => {
    assert.match(chatSrc, /props\.src\.startsWith\('https:\/\/lh3\.googleusercontent\.com\/'\)/);
    assert.match(chatSrc, /if \(isOtherExternal\) return null;/);
  });
});
