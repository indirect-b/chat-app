/**
 * Privacy policy page — content tests.
 *
 * No network: asserts the policy HTML served at GET /privacy states the
 * facts the code actually implements (sign-in identifiers, E2E-encrypted
 * messages, salted recovery-code hash, Google sharing email + name,
 * Render storage, in-app account deletion, contact email) and contains
 * no scripts, no styles and no external resources (it must render under
 * the strict CSP: styleSrc 'self', no unsafe-inline).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PRIVACY_HTML } from '../src/server/privacy';

describe('privacy policy page', () => {
  it('is a complete HTML document with the required title', () => {
    assert.match(PRIVACY_HTML, /^<!DOCTYPE html>/);
    assert.ok(PRIVACY_HTML.includes('<title>Privacy Policy — chat-app'));
    assert.ok(PRIVACY_HTML.includes('سیاست حریم خصوصی'));
  });

  it('states the sign-in identifiers collected (Bale ID / email)', () => {
    assert.ok(PRIVACY_HTML.includes('آیدی بله'));
    assert.ok(PRIVACY_HTML.includes('آدرس ایمیل'));
    assert.ok(PRIVACY_HTML.includes('Bale ID'));
    assert.ok(PRIVACY_HTML.includes('email address'));
  });

  it('states messages are stored encrypted and unreadable by the server', () => {
    assert.ok(PRIVACY_HTML.includes('رمزگذاری‌شده'));
    assert.ok(PRIVACY_HTML.includes('سرور نمی‌تواند آن‌ها را بخواند'));
    assert.ok(PRIVACY_HTML.includes('end-to-end encrypted'));
    assert.ok(PRIVACY_HTML.includes('server cannot read them'));
  });

  it('states only the salted hash of the recovery code is stored', () => {
    assert.ok(PRIVACY_HTML.includes('هش نمکی'));
    assert.ok(PRIVACY_HTML.includes('خود کد هرگز ذخیره نمی‌شود'));
    assert.ok(PRIVACY_HTML.includes('salted (scrypt) hash'));
    assert.ok(PRIVACY_HTML.includes('the code itself is never stored'));
  });

  it('states Google Sign-In shares only email and name', () => {
    assert.ok(PRIVACY_HTML.includes('ورود با گوگل'));
    assert.ok(PRIVACY_HTML.includes('Google shares only your email address and name'));
  });

  it('states data is stored on Render and deletion is available in-app', () => {
    assert.ok(PRIVACY_HTML.includes('Render'));
    assert.ok(PRIVACY_HTML.includes('حذف حساب'));
    assert.ok(PRIVACY_HTML.includes('Deleting your account'));
  });

  it('gives the privacy contact email', () => {
    assert.ok(PRIVACY_HTML.includes('indirectnebula6@gmail.com'));
  });

  it('contains no scripts, no styles and no external resources (CSP-safe)', () => {
    assert.ok(!/<script/i.test(PRIVACY_HTML), 'must not contain <script>');
    assert.ok(!/<style/i.test(PRIVACY_HTML), 'must not contain <style>');
    assert.ok(!/style\s*=/i.test(PRIVACY_HTML), 'must not contain inline style attributes');
    assert.ok(!/src\s*=\s*"https?:/i.test(PRIVACY_HTML), 'must not load external scripts');
    assert.ok(!/href\s*=\s*"https?:/i.test(PRIVACY_HTML), 'must not link external stylesheets');
  });
});
