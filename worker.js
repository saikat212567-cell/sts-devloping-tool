export default {
  // =================================================================
  // 1. STANDARD HTTP REQUESTS (Frontend interacting with Database)
  // =================================================================
  async fetch(request, env, ctx) {
    // --- [CRITICAL-1 FIX]: Restrict CORS Origins ---
    const ALLOWED_ORIGINS = [
        'https://sankar-tea-shop.saikat212567.workers.dev'
    ];
    const origin = request.headers.get('Origin') || '';
    const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    const jsonHeaders = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json',
      'Vary': 'Origin'
    };

    if (request.method === 'OPTIONS') return new Response(null, { headers: jsonHeaders });

    // --- [CRITICAL-2 FIX]: Authentication Gate (helper - used for POST only) ---
    async function safeCompare(a, b) {
        if (!a || !b) return false;
        const enc = new TextEncoder();
        const keyA = await crypto.subtle.importKey('raw', enc.encode(a), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sigA = new Uint8Array(await crypto.subtle.sign('HMAC', keyA, enc.encode('auth')));
        const keyB = await crypto.subtle.importKey('raw', enc.encode(b), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sigB = new Uint8Array(await crypto.subtle.sign('HMAC', keyB, enc.encode('auth')));
        if (sigA.length !== sigB.length) return false;
        let diff = 0;
        for (let i = 0; i < sigA.length; i++) diff |= sigA[i] ^ sigB[i];
        return diff === 0;
    }

    // --- [HIGH-2 & HIGH-3 FIX]: Input Validation Helpers ---
    function isValidEmailList(str) {
        if (!str || typeof str !== 'string' || str.length > 200) return false;
        return str.split(',').every(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim()));
    }

    function validateTxItem(item) {
        if (!item.date || typeof item.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(item.date)) return false;
        if (!item.particulars || typeof item.particulars !== 'string' || item.particulars.length > 50) return false;
        if (item.account !== undefined && item.account !== null && typeof item.account !== 'string') return false;
        if (item.amount !== undefined && item.amount !== null && (typeof item.amount !== 'number' || !isFinite(item.amount) || Math.abs(item.amount) > 10000000)) return false;
        return true;
    }

    if (request.method === 'GET') {
      try {
        const { results: transactions } = await env.DB.prepare("SELECT * FROM transactions ORDER BY id ASC").all();
        const { results: denominations } = await env.DB.prepare("SELECT * FROM denominations").all();
        
        let objSTSJ = transactions.map(t => {
            const d = denominations.find(den => den.date === t.date) || {};
            return { 
                date: t.date, account: t.account || "", particulars: t.particulars || "", 
                amount: t.amount !== undefined && t.amount !== null ? t.amount : "", denomDate: d.date || "", 
                note10: d.note10 || "", note20: d.note20 || "", note50: d.note50 || "", note100: d.note100 || "", note200: d.note200 || "", note500: d.note500 || "",
                coin1: d.coin1 || "", coin2: d.coin2 || "", coin5: d.coin5 || "", coin10: d.coin10 || "", coin20: d.coin20 || ""
            };
        });

        let cloudPin = "";
        try {
            await env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
            const pinRes = await env.DB.prepare("SELECT value FROM settings WHERE key = 'STS_PIN'").first();
            if (pinRes && pinRes.value !== "") cloudPin = pinRes.value; 
        } catch(e) {} 

        let scheduledEmails = [];
        try {
            let dbStr = await env.STS_DB.get("SCHEDULED_EMAILS");
            // [MEDIUM-4 FIX]: Try/Catch around JSON parse
            if (dbStr) scheduledEmails = JSON.parse(dbStr);
        } catch(e) { scheduledEmails = []; }

        return new Response(JSON.stringify({ status: "success", stsj: objSTSJ, pinHash: cloudPin, emails: scheduledEmails }), { headers: jsonHeaders });
      } catch (err) {
        console.error(err);
        // [MEDIUM-3 FIX]: Generic Error Message
        return new Response(JSON.stringify({ status: "error", message: "Internal Server Error" }), { headers: jsonHeaders, status: 500 });
      }
    }

    if (request.method === 'POST') {
      // --- [AUDIT FIX #2]: POST-only Authentication Gate ---
      const authHeader = request.headers.get('Authorization');
      const expectedKey = env.STS_API_KEY;
      if (expectedKey && !(await safeCompare(authHeader || '', `Bearer ${expectedKey}`))) {
          return new Response(JSON.stringify({ status: 'error', message: 'Unauthorized Access' }), {
              headers: jsonHeaders, status: 401
          });
      }

      // --- [MEDIUM-5 FIX]: Overall Payload Size Limit (5MB) ---
      const bodyText = await request.text();
      if (bodyText.length > 5 * 1024 * 1024) { 
          return new Response(JSON.stringify({ status: "error", message: "Payload too large" }), { headers: jsonHeaders, status: 413 });
      }

      let data;
      try { data = JSON.parse(bodyText); } catch(e) { return new Response(JSON.stringify({ status: "error", message: "Invalid JSON format" }), { headers: jsonHeaders, status: 400 }); }

      if (data.action === "UPDATE_PIN") {
        if (!data.pin || typeof data.pin !== 'string' || data.pin.length > 128) {
            return new Response(JSON.stringify({ status: "error", message: "Invalid PIN length/format" }), { headers: jsonHeaders, status: 400 });
        }
        try {
            await env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
            await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('STS_PIN', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(String(data.pin)).run();
            return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
        } catch(e) { 
            console.error(e);
            return new Response(JSON.stringify({ status: "error", message: "Failed to update PIN" }), { headers: jsonHeaders, status: 500 });
        }
      }

      if (data.action === "REQUEST_OTP") {
         if (!isValidEmailList(data.emails)) {
             return new Response(JSON.stringify({ status: "error", message: "Invalid email format" }), { headers: jsonHeaders, status: 400 });
         }
         // --- [LOW-3 FIX]: KV Based Rate Limiting ---
         const rateLimitKey = `RATE_OTP_${data.emails}`;
         const attempts = parseInt(await env.STS_DB.get(rateLimitKey) || "0");
         if (attempts >= 5) {
             return new Response(JSON.stringify({ status: "error", message: "Too many OTP requests. Try again later." }), { headers: jsonHeaders, status: 429 });
         }
         await env.STS_DB.put(rateLimitKey, String(attempts + 1), { expirationTtl: 600 });

         const otpBuffer = new Uint32Array(1);
         crypto.getRandomValues(otpBuffer);
         const otp = String(100000 + (otpBuffer[0] % 900000));
         await env.STS_DB.put(`OTP_${data.emails}`, otp, { expirationTtl: 600 }); 
         
         // [MEDIUM-2 & HIGH-1 FIX]
         ctx.waitUntil(
             fetch(env.GOOGLE_SCRIPT_URL, { method: 'POST',
                body: JSON.stringify({ action: "SEND_OTP_ONLY", emails: data.emails, otp: otp }) })
                .catch(err => console.error("OTP email send failed:", err))
         );
         return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
      }
      // --- BIOMETRIC ACTIONS ---
// ⚠️ এখানে আপনার Google App Script-এর লাইভ লিংক এবং আপনার ইমেইলটা বসিয়ে দিন
      const APP_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbxT2IoAuVTjJiSW4AkWrzQsl4mmIwzendPOX_pkOL4Jv5ohORx8rP03FIjlzxlLlU7J/exec"; 
      const ADMIN_EMAIL = "dass46206@gmail.com"; 

      // 📩 ১. OTP পাঠানোর API (Cloudflare -> App Script)
      if (data.action === "SEND_REGISTRATION_OTP") {
        try {
            let otp = Math.floor(100000 + Math.random() * 900000).toString(); 
            
            await env.DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
            await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('BIO_REG_OTP', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(otp).run();
            
            // Cloudflare নিজে App Script-কে রিকোয়েস্ট পাঠাচ্ছে
            let emailText = `Your STS App Fingerprint Registration OTP is: ${otp}.\nDo not share this with anyone!`;
            await fetch(APP_SCRIPT_URL, {
                method: "POST",
                body: JSON.stringify({ action: "SEND_ALERT_EMAIL", email: ADMIN_EMAIL, subject: "STS Security OTP", message: emailText })
            });
            
            return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
        } catch(e) { return new Response(JSON.stringify({ status: "error", message: e.message }), { headers: jsonHeaders, status: 500 }); }
      }

      // 🔐 ২. OTP ভেরিফাই ও অ্যালার্ট পাঠানোর API (Cloudflare -> App Script)
      // 🔐 ২. OTP ভেরিফাই ও অ্যালার্ট পাঠানোর API (Cloudflare -> App Script)
      if (data.action === "REGISTER_BIOMETRIC") {
        try {
            let otpRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'BIO_REG_OTP'").first();
            if(!otpRow || otpRow.value !== data.otp) {
                return new Response(JSON.stringify({ status: "error", message: "Invalid or Expired OTP!" }), { headers: jsonHeaders, status: 401 });
            }

            await env.DB.prepare("DELETE FROM settings WHERE key = 'BIO_REG_OTP'").run();

            let ip = request.headers.get('CF-Connecting-IP') || 'Unknown IP';
            let location = (request.cf && request.cf.city ? request.cf.city : '') + ', ' + (request.cf && request.cf.country ? request.cf.country : '');
            let deviceName = data.device_name || 'Unknown Device'; 

            await env.DB.prepare(`CREATE TABLE IF NOT EXISTS active_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_name TEXT, credential_id TEXT, ip_address TEXT, location TEXT, reg_date DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
            
            // 💡 [NEW FIX]: একই নামের (যেমন: POCO F3 GT) কোনো পুরনো এন্ট্রি থাকলে সেটা আগে ডিলিট করে দাও!
            await env.DB.prepare("DELETE FROM active_devices WHERE device_name = ?").bind(deviceName).run();

            // তারপর নতুন চাবিটা ফ্রেশ করে সেভ করো
            await env.DB.prepare("INSERT INTO active_devices (device_name, credential_id, ip_address, location) VALUES (?, ?, ?, ?)").bind(deviceName, String(data.credential_id), ip, location).run();
            
            // Alert মেইল ফায়ার করা হচ্ছে
            let alertMsg = `⚠️ SECURITY ALERT: New Device Added to Sankar Tea Shop!\n\n📱 Device: ${deviceName}\n🌐 IP Address: ${ip}\n📍 Location: ${location}\n🕒 Time: ${new Date().toLocaleString()}`;
            
            fetch(APP_SCRIPT_URL, {
                method: "POST",
                body: JSON.stringify({ action: "SEND_ALERT_EMAIL", email: ADMIN_EMAIL, subject: "⚠️ New Device Registered!", message: alertMsg })
            }).catch(e => console.log("Alert email failed."));

            return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
        } catch(e) { return new Response(JSON.stringify({ status: "error", message: e.message }), { headers: jsonHeaders, status: 500 }); }
      }
            // 🔐 ৩. ফিঙ্গারপ্রিন্ট ভেরিফাই করার আপডেটেড API
      if (data.action === "VERIFY_BIOMETRIC") {
        try {
            // চেক করা হচ্ছে ডিভাইসটি নতুন active_devices টেবিলে আছে কি না
            const row = await env.DB.prepare("SELECT id FROM active_devices WHERE credential_id = ?").bind(data.credential_id).first();
            
            if (row) {
                // ডেটাবেসে মিলে গেলে সাকসেস
                return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
            }
            
            // না মিললে হ্যাকার ভেবে কিক-আউট
            return new Response(JSON.stringify({ status: "error", message: "Access Revoked or Device Not Found!" }), { headers: jsonHeaders, status: 401 });
        } catch(e) { 
            return new Response(JSON.stringify({ status: "error", message: e.message }), { headers: jsonHeaders, status: 500 });
        }
      }
      if (data.action === "VERIFY_OTP") {
         const savedOtp = await env.STS_DB.get(`OTP_${data.emails}`);
         if (savedOtp === data.otp) {
             await env.STS_DB.delete(`OTP_${data.emails}`);
             return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
         }
         return new Response(JSON.stringify({ status: "error", message: "Invalid OTP" }), { headers: jsonHeaders });
      }

      if (data.action === "SAVE_EMAIL_CONFIG") {
         if (!data.config || JSON.stringify(data.config).length > 1024) {
             return new Response(JSON.stringify({ status: "error", message: "Config payload too large" }), { headers: jsonHeaders, status: 400 });
         }
         let existingArr = [];
         try {
             let existingStr = await env.STS_DB.get("SCHEDULED_EMAILS");
             if (existingStr) existingArr = JSON.parse(existingStr);
         } catch(e) { existingArr = []; }

         existingArr = existingArr.filter(c => c.email !== data.config.email);
         // --- [AUDIT FIX #5]: Cap email config array at 20 entries ---
         if (existingArr.length >= 20) {
             return new Response(JSON.stringify({ status: "error", message: "Maximum 20 email schedules allowed" }), { headers: jsonHeaders, status: 400 });
         }
         existingArr.push(data.config);
         await env.STS_DB.put("SCHEDULED_EMAILS", JSON.stringify(existingArr));
         return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
      }

      if (data.action === "DELETE_EMAIL_CONFIG") {
         // --- [HIGH-4 FIX]: Bounds Checking for Deletion ---
         let idx = parseInt(data.index, 10);
         if (isNaN(idx) || idx < 0) {
             return new Response(JSON.stringify({ status: "error", message: "Invalid index" }), { headers: jsonHeaders, status: 400 });
         }

         let existingArr = [];
         try {
             let existingStr = await env.STS_DB.get("SCHEDULED_EMAILS");
             if (existingStr) existingArr = JSON.parse(existingStr);
         } catch(e) { existingArr = []; }

         if (idx >= existingArr.length) {
             return new Response(JSON.stringify({ status: "error", message: "Index out of range" }), { headers: jsonHeaders, status: 400 });
         }

         existingArr.splice(idx, 1);
         await env.STS_DB.put("SCHEDULED_EMAILS", JSON.stringify(existingArr));
         return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
      }

      if (data.action === "SEND_ON_DEMAND_STATEMENT") {
         // [MEDIUM-2 & HIGH-1 FIX]
         ctx.waitUntil(
             fetch(env.GOOGLE_SCRIPT_URL, { method: 'POST', 
                body: JSON.stringify(data) })
             .catch(err => console.error("On-demand statement failed:", err))
         );
         return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
      }
// 📱 ১. ডিভাইস লগ দেখার জন্য API
      if (data.action === "GET_DEVICES") {
        try {
            let res = await env.DB.prepare("SELECT id, device_name, ip_address, location, reg_date FROM active_devices ORDER BY id DESC").all();
            return new Response(JSON.stringify({ status: "success", devices: res.results }), { headers: jsonHeaders });
        } catch(e) { return new Response(JSON.stringify({ status: "error" }), { headers: jsonHeaders, status: 500 }); }
      }

      // 🗑️ ২. ডিভাইস ব্লক/রিমুভ করার API
      if (data.action === "REVOKE_DEVICE") {
        try {
            await env.DB.prepare("DELETE FROM active_devices WHERE id = ?").bind(data.device_id).run();
            return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
        } catch(e) { return new Response(JSON.stringify({ status: "error" }), { headers: jsonHeaders, status: 500 }); }
      }
      // --- [AUDIT FIX #10]: Reject unknown action values ---
      if (data.action) {
          return new Response(JSON.stringify({ status: "error", message: "Unknown action" }), { headers: jsonHeaders, status: 400 });
      }

      let items = Array.isArray(data) ? data : [data];
      
      // --- [MEDIUM-2 FIX]: Try/Catch wrapped around transaction batch ---
      ctx.waitUntil((async () => {
          try {
              for (let item of items) {
                  // --- [HIGH-2 FIX]: Strict validation of transaction row ---
                  if (!validateTxItem(item)) continue;
                  
                  let finalAmt = item.amount !== undefined ? item.amount : 0;
                  let isBalance = ["CLOSING CASH", "CLOSING FLOAT", "RESERVE IN", "CLOSING BANK BALANCE"].includes(item.particulars);

                  if (isBalance) {
                      let existing = await env.DB.prepare("SELECT id FROM transactions WHERE date = ? AND account = ? AND particulars = ?").bind(item.date, item.account || "", item.particulars).first();
                      if (existing) { await env.DB.prepare("UPDATE transactions SET amount = ? WHERE id = ?").bind(finalAmt, existing.id).run(); } 
                      else { await env.DB.prepare("INSERT INTO transactions (date, account, particulars, amount) VALUES (?, ?, ?, ?)").bind(item.date, item.account || "", item.particulars, finalAmt).run(); }

                      if (item.particulars === "CLOSING CASH") {
                          await env.DB.prepare(`INSERT INTO denominations (date, note10, note20, note50, note100, note200, note500, coin1, coin2, coin5, coin10, coin20, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(date) DO UPDATE SET note10=excluded.note10, note20=excluded.note20, note50=excluded.note50, note100=excluded.note100, note200=excluded.note200, note500=excluded.note500, coin1=excluded.coin1, coin2=excluded.coin2, coin5=excluded.coin5, coin10=excluded.coin10, coin20=excluded.coin20, total_amount=excluded.total_amount`)
                          .bind(item.date, item.note10||0, item.note20||0, item.note50||0, item.note100||0, item.note200||0, item.note500||0, item.coin1||0, item.coin2||0, item.coin5||0, item.coin10||0, item.coin20||0, item.absoluteAmount || item.amount || 0).run();
                      }
                  } else {
                      if (finalAmt !== 0) { await env.DB.prepare("INSERT INTO transactions (date, account, particulars, amount) VALUES (?, ?, ?, ?)").bind(item.date, item.account || "", item.particulars, finalAmt).run(); }
                  }
              }

              if (items.length > 0 && items[0].date) {
                  const editDate = items[0].date;
                  const now = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
                  const todayIso = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
                  
                  if (editDate < todayIso) {
                      const { results: updatedTx } = await env.DB.prepare("SELECT * FROM transactions WHERE date = ?").bind(editDate).all();
                      const { results: updatedDenom } = await env.DB.prepare("SELECT * FROM denominations WHERE date = ?").bind(editDate).all();
                      await fetch(env.GOOGLE_SCRIPT_URL, { method: "POST", body: JSON.stringify({ action: "DAILY_BACKUP_SYNC", date: editDate, transactions: updatedTx, denominations: updatedDenom }) }).catch(e => console.error(e));
                  }
              }
          } catch(err) {
              console.error("Transaction processing error:", err);
          }
      })());
      
      return new Response(JSON.stringify({ status: "success" }), { headers: jsonHeaders });
    }
  },

  // =================================================================
  // 2. AUTOMATED CRON JOBS (Daily, Weekly, Monthly Ranging)
  // =================================================================
  async scheduled(event, env, ctx) {
      const date = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
      const currentHour = date.getHours(); 
      const dayOfWeek = date.getDay(); 
      const dateOfMonth = date.getDate();
      
      const reportDate = new Date(date);
      if (currentHour < 6) { reportDate.setDate(reportDate.getDate() - 1); }
      const rY = reportDate.getFullYear();
      const rM = String(reportDate.getMonth() + 1).padStart(2, '0'); const rD = String(reportDate.getDate()).padStart(2, '0');
      const targetIsoDate = `${rY}-${rM}-${rD}`;
      
      // ========================================================
      // TASK A: DAILY GOOGLE SHEETS BACKUP (Runs at 1:00 AM)
      // ========================================================
      if (currentHour === 1) {
          const backupStartDate = env.BACKUP_START_DATE || "2026-06-24"; // [LOW-1 FIX]
          if (targetIsoDate >= backupStartDate) {
              const { results: tResults } = await env.DB.prepare("SELECT * FROM transactions WHERE date = ?").bind(targetIsoDate).all();
              const { results: dResults } = await env.DB.prepare("SELECT * FROM denominations WHERE date = ?").bind(targetIsoDate).all();
              if (tResults && tResults.length > 0) {
                  await fetch(env.GOOGLE_SCRIPT_URL, { method: "POST", body: JSON.stringify({ action: "DAILY_BACKUP_SYNC", date: targetIsoDate, transactions: tResults, denominations: dResults }) }).catch(e=>console.error(e));
              }
          }
      }

      // ========================================================
      // TASK B: AUTOMATED EMAIL SUMMARY (Runs at 2:00 AM)
      // ========================================================
      if (currentHour === 2) {
          let emails = [];
          try {
              let dbStr = await env.STS_DB.get("SCHEDULED_EMAILS");
              if (!dbStr) return;
              emails = JSON.parse(dbStr); // [MEDIUM-4 FIX]
          } catch(e) { return; }

          for (let config of emails) {
             let shouldSend = false;
             let startDateIso = "";
             let endDateIso = targetIsoDate; 
             let reportLabel = targetIsoDate;
             
             if (config.freq === "DAILY") {
                 shouldSend = true;
                 startDateIso = targetIsoDate;
                 reportLabel = `Daily Summary: ${targetIsoDate}`;
             } 
             else if (config.freq === "WEEKLY" && config.day == dayOfWeek) {
                 shouldSend = true;
                 let sd = new Date(reportDate);
                 sd.setDate(sd.getDate() - 6); 
                 // --- [MEDIUM-1 TYPO FIX]: Changed 'crtring' to 'String' ---
                 startDateIso = `${sd.getFullYear()}-${String(sd.getMonth() + 1).padStart(2, '0')}-${String(sd.getDate()).padStart(2, '0')}`;
                 reportLabel = `Weekly Report: ${startDateIso} to ${endDateIso}`;
             } 
             else if (config.freq === "MONTHLY" && config.date == dateOfMonth) {
                 shouldSend = true;
                 let sd = new Date(reportDate);
                 sd.setMonth(sd.getMonth() - 1);
                 let pY = sd.getFullYear();
                 let pM = String(sd.getMonth() + 1).padStart(2, '0');
                 startDateIso = `${pY}-${pM}-01`;
                 
                 let ld = new Date(pY, sd.getMonth() + 1, 0);
                 endDateIso = `${pY}-${pM}-${String(ld.getDate()).padStart(2, '0')}`;
                 reportLabel = `Monthly Report: ${pY}-${pM}`;
             }

             if (shouldSend) {
                 const { results } = await env.DB.prepare("SELECT * FROM transactions WHERE date >= ? AND date <= ? ORDER BY date ASC, id ASC").bind(startDateIso, endDateIso).all();
                 await fetch("https://sts-pdf-server-1012055640452.asia-south1.run.app/auto-generate", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                       action: "SEND_CRON_SUMMARY",
                       emails: config.email,
                       dateRange: reportLabel,
                       ledgerData: results 
                    })
                 }).catch(e => console.error("Cron email failed:", e));
             }
          }
      }
  }
};
