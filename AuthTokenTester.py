# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JButton, JLabel, JTextField, JTextArea,
                          JScrollPane, BoxLayout, JTabbedPane, JSplitPane,
                          JMenuItem, BorderFactory, JComboBox, JCheckBox,
                          SwingUtilities, JProgressBar)
from javax.swing.border import TitledBorder
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Font
import threading
import time
import json
import re
from datetime import datetime


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AuthTokenTester")
        self._captured_token = None
        self._captured_session = None
        self._login_request = None
        self._results = []
        self._running = False
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self._log("AuthTokenTester loaded. Ready.")

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        header.setBackground(Color(25, 25, 45))
        lbl = JLabel("  AuthTokenTester - Session & Token Resilience Tester  ")
        lbl.setForeground(Color(100, 200, 255))
        lbl.setFont(Font("Monospaced", Font.BOLD, 13))
        header.add(lbl)
        self._panel.add(header, BorderLayout.NORTH)
        tabs = JTabbedPane()
        tabs.addTab("Config", self._build_config_tab())
        tabs.addTab("Run Tests", self._build_tests_tab())
        tabs.addTab("Results", self._build_results_tab())
        tabs.addTab("Log", self._build_log_tab())
        self._panel.add(tabs, BorderLayout.CENTER)

    def _build_config_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        t = JPanel(GridLayout(4, 2, 5, 5))
        t.setBorder(TitledBorder("Target"))
        t.add(JLabel("Host:"))
        self._host_field = JTextField("example.com", 30)
        t.add(self._host_field)
        t.add(JLabel("Port:"))
        self._port_field = JTextField("443", 10)
        t.add(self._port_field)
        t.add(JLabel("Protocol:"))
        self._proto_combo = JComboBox(["https", "http"])
        t.add(self._proto_combo)
        t.add(JLabel("Test Endpoint:"))
        self._endpoint_field = JTextField("/api/profile", 30)
        t.add(self._endpoint_field)
        panel.add(t)

        tk = JPanel(GridLayout(4, 2, 5, 5))
        tk.setBorder(TitledBorder("Token / Session"))
        tk.add(JLabel("Token Header Name:"))
        self._token_header_field = JTextField("Authorization", 20)
        tk.add(self._token_header_field)
        tk.add(JLabel("Token Prefix:"))
        self._token_prefix_field = JTextField("Bearer ", 20)
        tk.add(self._token_prefix_field)
        tk.add(JLabel("Session Cookie Names (comma):"))
        self._session_cookie_field = JTextField("JSESSIONID,session,PHPSESSID", 20)
        tk.add(self._session_cookie_field)
        tk.add(JLabel("Manual Token (optional):"))
        self._manual_token_field = JTextField("", 30)
        tk.add(self._manual_token_field)
        panel.add(tk)

        lo = JPanel(GridLayout(3, 2, 5, 5))
        lo.setBorder(TitledBorder("Logout Endpoint"))
        lo.add(JLabel("Logout Path:"))
        self._logout_path_field = JTextField("/api/logout", 30)
        lo.add(self._logout_path_field)
        lo.add(JLabel("Logout Method:"))
        self._logout_method_combo = JComboBox(["POST", "GET", "DELETE"])
        lo.add(self._logout_method_combo)
        lo.add(JLabel("Logout Body (JSON):"))
        self._logout_body_field = JTextField("{}", 30)
        lo.add(self._logout_body_field)
        panel.add(lo)

        op = JPanel(GridLayout(3, 2, 5, 5))
        op.setBorder(TitledBorder("Test Options"))
        self._check_logout   = JCheckBox("Token valid after logout", True)
        self._check_parallel = JCheckBox("Parallel token reuse", True)
        self._check_expiry   = JCheckBox("Token expiry check", True)
        self._check_fixation = JCheckBox("Session fixation", True)
        self._check_replay   = JCheckBox("Token replay", True)
        op.add(self._check_logout)
        op.add(self._check_parallel)
        op.add(self._check_expiry)
        op.add(self._check_fixation)
        op.add(self._check_replay)
        op.add(JLabel("Parallel request count:"))
        self._parallel_count = JTextField("5", 5)
        op.add(self._parallel_count)
        panel.add(op)

        bp = JPanel(FlowLayout())
        sb = JButton("Save Config")
        sb.addActionListener(lambda e: self._save_config())
        bp.add(sb)
        mb = JButton("Use Manual Token")
        mb.addActionListener(lambda e: self._use_manual_token())
        bp.add(mb)
        panel.add(bp)

        return JScrollPane(panel)

    def _build_tests_tab(self):
        panel = JPanel(BorderLayout())
        st = JPanel(GridLayout(3, 2, 5, 5))
        st.setBorder(TitledBorder("Captured Credentials"))
        st.add(JLabel("Token:"))
        self._token_display = JLabel("Not captured yet")
        self._token_display.setForeground(Color(150, 150, 150))
        st.add(self._token_display)
        st.add(JLabel("Session:"))
        self._session_display = JLabel("Not captured yet")
        self._session_display.setForeground(Color(150, 150, 150))
        st.add(self._session_display)
        st.add(JLabel("Target:"))
        self._target_display = JLabel("Not configured")
        st.add(self._target_display)
        panel.add(st, BorderLayout.NORTH)

        pp = JPanel(BorderLayout())
        pp.setBorder(TitledBorder("Progress"))
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("Ready")
        self._progress_label = JLabel("  Waiting to start...")
        pp.add(self._progress_bar, BorderLayout.NORTH)
        pp.add(self._progress_label, BorderLayout.CENTER)
        panel.add(pp, BorderLayout.CENTER)

        bp = JPanel(FlowLayout())
        rb = JButton("Run All Tests")
        rb.setBackground(Color(40, 130, 40))
        rb.setForeground(Color.WHITE)
        rb.addActionListener(lambda e: self._run_all_tests())
        bp.add(rb)

        for label, fn in [
            ("Logout Test",   self._run_test_logout),
            ("Parallel Test", self._run_test_parallel),
            ("Expiry Test",   self._run_test_expiry),
            ("Fixation Test", self._run_test_fixation),
            ("Replay Test",   self._run_test_replay),
        ]:
            b = JButton(label)
            fn_ref = fn
            b.addActionListener(lambda e, f=fn_ref: self._thread(f))
            bp.add(b)

        sb2 = JButton("Stop")
        sb2.setBackground(Color(180, 40, 40))
        sb2.setForeground(Color.WHITE)
        sb2.addActionListener(lambda e: self._stop())
        bp.add(sb2)
        panel.add(bp, BorderLayout.SOUTH)
        return panel

    def _build_results_tab(self):
        panel = JPanel(BorderLayout())
        self._summary_area = JTextArea(8, 60)
        self._summary_area.setEditable(False)
        self._summary_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._summary_area.setBackground(Color(20, 20, 35))
        self._summary_area.setForeground(Color(180, 255, 180))
        ss = JScrollPane(self._summary_area)
        ss.setBorder(TitledBorder("Summary"))
        self._results_area = JTextArea(20, 60)
        self._results_area.setEditable(False)
        self._results_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._results_area.setBackground(Color(15, 15, 25))
        self._results_area.setForeground(Color(220, 220, 220))
        rs = JScrollPane(self._results_area)
        rs.setBorder(TitledBorder("Details"))
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, ss, rs)
        split.setDividerLocation(200)
        panel.add(split, BorderLayout.CENTER)
        bp = JPanel(FlowLayout())
        clr = JButton("Clear")
        clr.addActionListener(lambda e: self._clear_results())
        bp.add(clr)
        exp = JButton("Export JSON")
        exp.addActionListener(lambda e: self._export_results())
        bp.add(exp)
        panel.add(bp, BorderLayout.SOUTH)
        return panel

    def _build_log_tab(self):
        self._log_area = JTextArea(30, 80)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._log_area.setBackground(Color(10, 10, 20))
        self._log_area.setForeground(Color(160, 255, 160))
        return JScrollPane(self._log_area)

    def getTabCaption(self):
        return "AuthTokenTester"

    def getUiComponent(self):
        return self._panel

    def createMenuItems(self, invocation):
        items = []
        m1 = JMenuItem("AuthTokenTester: Mark as Login request")
        m1.addActionListener(lambda e: self._mark_login(invocation))
        items.append(m1)
        m2 = JMenuItem("AuthTokenTester: Mark as Logout request")
        m2.addActionListener(lambda e: self._mark_logout(invocation))
        items.append(m2)
        m3 = JMenuItem("AuthTokenTester: Extract token/session from here")
        m3.addActionListener(lambda e: self._extract_from(invocation))
        items.append(m3)
        m4 = JMenuItem("AuthTokenTester: Mark as Test Endpoint")
        m4.addActionListener(lambda e: self._mark_endpoint(invocation))
        items.append(m4)
        return items

    def _mark_login(self, inv):
        msgs = inv.getSelectedMessages()
        if msgs:
            self._login_request = msgs[0]
            self._extract_token_from_message(msgs[0])
            self._log("[+] Login request marked.")

    def _mark_logout(self, inv):
        msgs = inv.getSelectedMessages()
        if msgs:
            ri = self._helpers.analyzeRequest(msgs[0])
            self._logout_path_field.setText(str(ri.getUrl().getPath()))
            self._log("[+] Logout marked: " + str(ri.getUrl().getPath()))

    def _mark_endpoint(self, inv):
        msgs = inv.getSelectedMessages()
        if msgs:
            ri = self._helpers.analyzeRequest(msgs[0])
            path = str(ri.getUrl().getPath())
            self._endpoint_field.setText(path)
            self._log("[+] Test endpoint: " + path)

    def _extract_from(self, inv):
        msgs = inv.getSelectedMessages()
        if msgs:
            self._extract_token_from_message(msgs[0])

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            try:
                self._extract_token_from_message(messageInfo)
            except:
                pass

    def _extract_token_from_message(self, messageInfo):
        try:
            resp = messageInfo.getResponse()
            if not resp:
                return
            ri = self._helpers.analyzeResponse(resp)
            headers = ri.getHeaders()
            token_hdr = self._token_header_field.getText().strip().lower()
            prefix = self._token_prefix_field.getText().strip()
            for h in headers:
                if token_hdr in str(h).lower():
                    parts = str(h).split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip()
                        if prefix and val.startswith(prefix):
                            val = val[len(prefix):]
                        if len(val) > 10:
                            self._captured_token = val
                            self._set_token_display(val[:50] + "...")
            cookie_names = [c.strip() for c in self._session_cookie_field.getText().split(",")]
            for h in headers:
                if "set-cookie:" in str(h).lower():
                    for cn in cookie_names:
                        m = re.search(cn + r"=([^;]+)", str(h))
                        if m:
                            self._captured_session = m.group(1)
                            self._set_session_display(self._captured_session[:30] + "...")
            if not self._captured_token:
                body = self._helpers.bytesToString(resp[ri.getBodyOffset():])
                try:
                    data = json.loads(body)
                    for key in ["token", "access_token", "accessToken", "jwt", "id_token", "auth_token"]:
                        if key in data:
                            self._captured_token = str(data[key])
                            self._set_token_display(self._captured_token[:50] + "...")
                            break
                except:
                    pass
        except:
            pass

    def _save_config(self):
        self._target_host = self._host_field.getText().strip()
        self._target_port = int(self._port_field.getText().strip())
        self._target_protocol = str(self._proto_combo.getSelectedItem())
        self._test_endpoint = self._endpoint_field.getText().strip()
        disp = self._target_protocol + "://" + self._target_host + ":" + str(self._target_port)
        self._target_display.setText(disp)
        self._log("[+] Config saved: " + disp)

    def _use_manual_token(self):
        t = self._manual_token_field.getText().strip()
        if t:
            self._captured_token = t
            self._set_token_display(t[:50] + "...")
            self._log("[+] Manual token set.")
        else:
            self._log("[!] Manual token field is empty.")

    def _thread(self, fn):
        t = threading.Thread(target=fn)
        t.daemon = True
        t.start()

    def _run_all_tests(self):
        self._results = []
        self._save_config()
        if not self._captured_token and not self._captured_session:
            self._log("[!] No token captured. Fill in manual token or intercept traffic.")
            return

        def run():
            self._running = True
            tests = []
            if self._check_logout.isSelected():
                tests.append(("Token valid after logout", self._run_test_logout))
            if self._check_parallel.isSelected():
                tests.append(("Parallel token reuse", self._run_test_parallel))
            if self._check_expiry.isSelected():
                tests.append(("Token expiry", self._run_test_expiry))
            if self._check_fixation.isSelected():
                tests.append(("Session fixation", self._run_test_fixation))
            if self._check_replay.isSelected():
                tests.append(("Token replay", self._run_test_replay))
            for i, (name, fn) in enumerate(tests):
                if not self._running:
                    break
                self._set_progress(int(i * 100.0 / len(tests)), "Running: " + name)
                fn()
                time.sleep(0.5)
            self._set_progress(100, "Done")
            self._render_results()
            self._log("[OK] All tests finished.")

        self._thread(run)

    def _stop(self):
        self._running = False
        self._log("[!] Stopping...")

    def _run_test_logout(self):
        self._log("\n[TEST 1] Token validity after logout...")
        result = {"test": "Token Valid After Logout", "timestamp": str(datetime.now()),
                  "steps": [], "vulnerable": False, "severity": "INFO", "description": ""}
        token = self._get_token()
        if not token:
            result["steps"].append("SKIP: No token")
            self._results.append(result)
            return
        r1 = self._auth_request(token)
        result["steps"].append("Pre-logout: HTTP " + str(r1.get("status", "?")))
        if r1.get("status", 0) not in [200, 201]:
            result["description"] = "Token already invalid before test."
            self._results.append(result)
            return
        path = self._logout_path_field.getText().strip()
        method = str(self._logout_method_combo.getSelectedItem())
        body = self._logout_body_field.getText().strip()
        lr = self._send_request(method, path, token, body)
        result["steps"].append("Logout (" + method + " " + path + "): HTTP " + str(lr.get("status", "?")))
        time.sleep(1)
        r3 = self._auth_request(token)
        status = r3.get("status", 0)
        result["steps"].append("Post-logout: HTTP " + str(status))
        if status in [200, 201]:
            result["vulnerable"] = True
            result["severity"] = "HIGH"
            result["description"] = "VULNERABLE: Token still valid after logout! No server-side invalidation."
            self._log("[!!!] HIGH: Token still valid after logout!")
        elif status in [401, 403]:
            result["description"] = "SECURE: Token invalidated after logout (HTTP " + str(status) + ")"
            self._log("[OK] Token invalidated.")
        else:
            result["description"] = "UNCLEAR: HTTP " + str(status) + " - manual review needed"
        self._results.append(result)

    def _run_test_parallel(self):
        self._log("\n[TEST 2] Parallel token reuse...")
        result = {"test": "Parallel Token Reuse", "timestamp": str(datetime.now()),
                  "steps": [], "vulnerable": False, "severity": "INFO", "description": ""}
        token = self._get_token()
        if not token:
            result["steps"].append("SKIP: No token")
            self._results.append(result)
            return
        try:
            count = int(self._parallel_count.getText().strip())
        except:
            count = 5
        responses = []
        lock = threading.Lock()
        def send(idx):
            r = self._auth_request(token)
            with lock:
                responses.append(r)
        threads = [threading.Thread(target=send, args=(i,)) for i in range(count)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=15)
        success = sum(1 for r in responses if r.get("status") in [200, 201])
        result["steps"].append(str(count) + " parallel requests sent")
        result["steps"].append("Successful: " + str(success) + " / " + str(count))
        if success == count:
            result["vulnerable"] = True
            result["severity"] = "MEDIUM"
            result["description"] = "INFO: All " + str(count) + " parallel requests succeeded. No single-use token policy."
            self._log("[!] MEDIUM: All parallel requests accepted.")
        elif success > 0:
            result["description"] = "PARTIAL: " + str(success) + "/" + str(count) + " succeeded."
        else:
            result["description"] = "SECURE: Parallel requests rejected."
        self._results.append(result)

    def _run_test_expiry(self):
        self._log("\n[TEST 3] Token expiry...")
        result = {"test": "Token Expiry", "timestamp": str(datetime.now()),
                  "steps": [], "vulnerable": False, "severity": "INFO", "description": ""}
        token = self._get_token()
        if not token:
            result["steps"].append("SKIP: No token")
            self._results.append(result)
            return
        if token.count(".") == 2:
            try:
                import base64
                parts = token.split(".")
                hdr_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(hdr_b64))
                alg = str(header.get("alg", "unknown"))
                result["steps"].append("JWT alg: " + alg)
                if alg.lower() == "none":
                    result["vulnerable"] = True
                    result["severity"] = "CRITICAL"
                    result["description"] = "CRITICAL: alg:none detected! Signature bypass possible."
                    self._log("[!!!] CRITICAL: alg:none JWT!")
                pay_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(pay_b64))
                if "exp" in payload:
                    exp = payload["exp"]
                    now = time.time()
                    remaining = exp - now
                    result["steps"].append("exp remaining: " + str(int(remaining)) + "s")
                    if remaining < 0:
                        r = self._auth_request(token)
                        if r.get("status") in [200, 201]:
                            result["vulnerable"] = True
                            result["severity"] = "HIGH"
                            result["description"] = "VULNERABLE: Expired JWT still accepted!"
                            self._log("[!!!] HIGH: Expired JWT accepted!")
                        else:
                            result["description"] = "SECURE: Expired JWT rejected."
                    elif remaining > 86400 * 30:
                        result["vulnerable"] = True
                        result["severity"] = "MEDIUM"
                        result["description"] = "WARNING: Token valid for " + str(int(remaining / 86400)) + " more days. Too long-lived."
                        self._log("[!] MEDIUM: Token lives " + str(int(remaining / 86400)) + " more days.")
                    else:
                        result["description"] = "OK: Token expires in " + str(int(remaining / 3600)) + " hours."
                        self._log("[OK] Token expiry is reasonable.")
                else:
                    result["vulnerable"] = True
                    result["severity"] = "MEDIUM"
                    result["description"] = "WARNING: JWT has no exp claim. Token never expires!"
                    self._log("[!] MEDIUM: No exp claim!")
            except Exception as e:
                result["steps"].append("JWT decode error: " + str(e))
        else:
            result["description"] = "Opaque token. Expiry must be tested server-side."
        self._results.append(result)

    def _run_test_fixation(self):
        self._log("\n[TEST 4] Session fixation...")
        result = {"test": "Session Fixation", "timestamp": str(datetime.now()),
                  "steps": [], "vulnerable": False, "severity": "INFO", "description": ""}
        if not self._login_request:
            result["description"] = "Mark login request via right-click to enable this test."
            self._results.append(result)
            return
        try:
            ri = self._helpers.analyzeRequest(self._login_request)
            req_headers = ri.getHeaders()
            cookie_names = [c.strip() for c in self._session_cookie_field.getText().split(",")]
            pre_session = None
            for h in req_headers:
                if "cookie:" in str(h).lower():
                    for cn in cookie_names:
                        m = re.search(cn + r"=([^;]+)", str(h))
                        if m:
                            pre_session = m.group(1)
            s1 = (pre_session[:20] + "...") if pre_session else "not found"
            s2 = (self._captured_session[:20] + "...") if self._captured_session else "not found"
            result["steps"].append("Pre-login session: " + s1)
            result["steps"].append("Post-login session: " + s2)
            if pre_session and self._captured_session:
                if pre_session == self._captured_session:
                    result["vulnerable"] = True
                    result["severity"] = "HIGH"
                    result["description"] = "VULNERABLE: Session ID not changed after login! Session fixation risk."
                    self._log("[!!!] HIGH: Session fixation detected!")
                else:
                    result["description"] = "SECURE: Session ID renewed after login."
                    self._log("[OK] Session renewed.")
            else:
                result["description"] = "SKIPPED: Not enough session data to compare."
        except Exception as e:
            result["steps"].append("Error: " + str(e))
        self._results.append(result)

    def _run_test_replay(self):
        self._log("\n[TEST 5] Token replay...")
        result = {"test": "Token Replay", "timestamp": str(datetime.now()),
                  "steps": [], "vulnerable": False, "severity": "INFO", "description": ""}
        token = self._get_token()
        if not token:
            result["steps"].append("SKIP: No token")
            self._results.append(result)
            return
        r1 = self._auth_request(token)
        time.sleep(2)
        r2 = self._auth_request(token)
        time.sleep(2)
        r3 = self._auth_request(token)
        statuses = [r1.get("status"), r2.get("status"), r3.get("status")]
        result["steps"].append("Replay responses: " + str(statuses))
        success = sum(1 for s in statuses if s in [200, 201])
        if success >= 2:
            result["vulnerable"] = True
            result["severity"] = "LOW"
            result["description"] = "INFO: Token reusable (expected for stateless JWT). No one-time token policy."
        else:
            result["description"] = "SECURE: Token rejected on replay."
        self._results.append(result)

    def _auth_request(self, token):
        endpoint = self._endpoint_field.getText().strip()
        token_hdr = self._token_header_field.getText().strip()
        prefix = self._token_prefix_field.getText().strip()
        host = self._host_field.getText().strip()
        headers = [
            "GET " + endpoint + " HTTP/1.1",
            "Host: " + host,
            token_hdr + ": " + prefix + token,
            "User-Agent: AuthTokenTester/1.0",
            "Accept: application/json",
            "Connection: close"
        ]
        if self._captured_session:
            cn = self._session_cookie_field.getText().split(",")[0].strip()
            headers.append("Cookie: " + cn + "=" + self._captured_session)
        return self._raw_request(headers, "")

    def _send_request(self, method, path, token, body=""):
        token_hdr = self._token_header_field.getText().strip()
        prefix = self._token_prefix_field.getText().strip()
        host = self._host_field.getText().strip()
        headers = [
            method + " " + path + " HTTP/1.1",
            "Host: " + host,
            token_hdr + ": " + prefix + token,
            "Content-Type: application/json",
            "Content-Length: " + str(len(body)),
            "Connection: close"
        ]
        return self._raw_request(headers, body)

    def _raw_request(self, headers, body):
        try:
            host = self._host_field.getText().strip()
            port = int(self._port_field.getText().strip())
            use_https = (str(self._proto_combo.getSelectedItem()) == "https")
            req_str = "\r\n".join(headers) + "\r\n\r\n" + body
            svc = self._helpers.buildHttpService(host, port, use_https)
            resp = self._callbacks.makeHttpRequest(svc, self._helpers.stringToBytes(req_str))
            if resp:
                ri = self._helpers.analyzeResponse(resp.getResponse())
                status = ri.getStatusCode()
                self._log("[HTTP] " + str(headers[0]) + " -> " + str(status))
                return {"status": status}
        except Exception as e:
            self._log("[ERR] " + str(e))
            return {"status": 0, "error": str(e)}
        return {"status": 0}

    def _get_token(self):
        m = self._manual_token_field.getText().strip()
        return m if m else self._captured_token

    def _set_token_display(self, text):
        def u():
            self._token_display.setText(text)
            self._token_display.setForeground(Color(50, 200, 80))
        SwingUtilities.invokeLater(u)

    def _set_session_display(self, text):
        def u():
            self._session_display.setText(text)
            self._session_display.setForeground(Color(50, 200, 80))
        SwingUtilities.invokeLater(u)

    def _set_progress(self, val, text):
        def u():
            self._progress_bar.setValue(val)
            self._progress_bar.setString(text)
            self._progress_label.setText("  " + text)
        SwingUtilities.invokeLater(u)

    def _log(self, msg):
        def u():
            ts = datetime.now().strftime("%H:%M:%S")
            self._log_area.append("[" + ts + "] " + msg + "\n")
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(u)

    def _render_results(self):
        def u():
            total = len(self._results)
            vulns = [r for r in self._results if r.get("vulnerable")]
            crit  = [r for r in vulns if r.get("severity") == "CRITICAL"]
            high  = [r for r in vulns if r.get("severity") == "HIGH"]
            med   = [r for r in vulns if r.get("severity") == "MEDIUM"]
            s  = "=" * 50 + "\n"
            s += "  AuthTokenTester - Summary\n"
            s += "  " + str(datetime.now()) + "\n"
            s += "=" * 50 + "\n"
            s += "  Total    : " + str(total) + "\n"
            s += "  CRITICAL : " + str(len(crit)) + "\n"
            s += "  HIGH     : " + str(len(high)) + "\n"
            s += "  MEDIUM   : " + str(len(med)) + "\n"
            s += "  Clean    : " + str(total - len(vulns)) + "\n"
            s += "=" * 50 + "\n"
            self._summary_area.setText(s)
            d = ""
            for r in self._results:
                sev = r.get("severity", "INFO")
                icon = "[!!!]" if sev in ["CRITICAL","HIGH"] else ("[!]" if sev == "MEDIUM" else "[OK]")
                d += "\n" + icon + " " + r["test"] + "\n"
                d += "  Severity : " + sev + "\n"
                d += "  Result   : " + r.get("description", "") + "\n"
                for step in r.get("steps", []):
                    d += "    > " + step + "\n"
                d += "-" * 45 + "\n"
            self._results_area.setText(d)
        SwingUtilities.invokeLater(u)

    def _clear_results(self):
        self._results = []
        self._results_area.setText("")
        self._summary_area.setText("")

    def _export_results(self):
        try:
            import tempfile, os
            path = os.path.join(tempfile.gettempdir(), "auth_token_results.json")
            with open(path, "w") as f:
                json.dump(self._results, f, indent=2, default=str)
            self._log("[+] Exported: " + path)
        except Exception as e:
            self._log("[ERR] Export failed: " + str(e))
