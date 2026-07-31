import importlib
import os
import tempfile
import unittest


class HookboxTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["DATABASE_PATH"] = os.path.join(self.tmp.name, "test.db")
        os.environ["SECRET_KEY"] = "test-secret"
        os.environ["ALLOW_REGISTRATION"] = "true"
        os.environ["MAX_REQUESTS_PER_ENDPOINT"] = "500"
        import app
        self.module = importlib.reload(app)
        self.module.app.config.update(TESTING=True)
        self.client = self.module.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess["csrf"]

    def register(self):
        self.client.get("/cadastro")
        return self.client.post("/cadastro", data={"csrf": self.csrf(), "name": "Ada", "email": "ada@example.com", "password": "segura123"})

    def test_register_create_capture_and_customize(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        self.client.get("/painel")
        response = self.client.post("/endpoints", data={"csrf": self.csrf(), "name": "Pagamentos"})
        self.assertEqual(response.status_code, 302)
        endpoint_id = int(response.location.rstrip("/").split("/")[-1])
        dashboard = self.client.get("/painel")
        self.assertIn(b"Seus endpoints", dashboard.data)
        self.assertIn(b"TOTAL DE REQUISI", dashboard.data)
        self.assertIn(b'data-endpoint-search="Pagamentos', dashboard.data)
        with self.module.app.app_context():
            endpoint = self.module.db().execute("SELECT * FROM endpoints WHERE id=?", (endpoint_id,)).fetchone()
        captured = self.client.post(f"/hook/{endpoint['uuid']}/events?source=test", json={"paid": True}, headers={"X-Test": "yes"})
        self.assertEqual(captured.status_code, 200)
        detail = self.client.get(f"/endpoints/{endpoint_id}")
        self.assertIn(b"/events?source=test", detail.data)
        selected = self.client.get(f"/endpoints/{endpoint_id}?request=1")
        self.assertIn(b"HEADERS COMPLETOS", selected.data)
        self.assertIn(b"X-Test: yes", selected.data)
        self.assertIn(b'data-tab="body"', selected.data)
        self.assertIn(b'data-tab="headers"', selected.data)
        self.assertIn(b'data-tab="query"', selected.data)
        self.assertIn(b'data-tab="cookies"', selected.data)
        self.assertIn(b"Reenviar requisi", selected.data)
        exported = self.client.get(f"/endpoints/{endpoint_id}/requests/1/export")
        self.assertEqual(exported.status_code, 200)
        self.assertIn("attachment", exported.headers["Content-Disposition"])
        self.client.post(f"/endpoints/{endpoint_id}/config", data={"csrf": self.csrf(), "name": "Pagamentos", "status": "202", "content_type": "text/plain", "body": "accepted"})
        custom = self.client.put(f"/hook/{endpoint['uuid']}", data="hello")
        self.assertEqual(custom.status_code, 202)
        self.assertEqual(custom.data, b"accepted")
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertEqual(custom.headers["X-Content-Type-Options"], "nosniff")

    def test_secret_archive_and_uuid_rotation(self):
        self.register(); self.client.get("/painel")
        created = self.client.post("/endpoints", data={"csrf": self.csrf(), "name": "Privado"})
        endpoint_id = int(created.location.rstrip("/").split("/")[-1])
        self.client.post(f"/endpoints/{endpoint_id}/config", data={"csrf": self.csrf(), "name": "Privado", "status": "200", "content_type": "application/json", "body": "{}", "secret": "token-test"})
        with self.module.app.app_context():
            token = self.module.db().execute("SELECT uuid FROM endpoints WHERE id=?", (endpoint_id,)).fetchone()[0]
        self.assertEqual(self.client.post(f"/hook/{token}").status_code, 401)
        self.assertEqual(self.client.post(f"/hook/{token}", headers={"X-Hookbox-Secret": "token-test"}).status_code, 200)
        self.client.post(f"/endpoints/{endpoint_id}/archive", data={"csrf": self.csrf()})
        self.assertEqual(self.client.post(f"/hook/{token}", headers={"X-Hookbox-Secret": "token-test"}).status_code, 410)

    def test_admin_can_change_password_and_invalidate_old_login(self):
        self.register()
        self.client.get("/admin")
        changed = self.client.post("/admin/users/1/password", data={"csrf": self.csrf(), "password": "nova-senha-123"})
        self.assertEqual(changed.status_code, 302)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.client.post("/sair", data={"csrf": self.csrf()})
        self.client.get("/login")
        old_login = self.client.post("/login", data={"csrf": self.csrf(), "email": "ada@example.com", "password": "segura123"})
        self.assertEqual(old_login.status_code, 200)
        new_login = self.client.post("/login", data={"csrf": self.csrf(), "email": "ada@example.com", "password": "nova-senha-123"})
        self.assertEqual(new_login.status_code, 302)

    def test_unknown_hook_and_auth_protection(self):
        self.assertEqual(self.client.post("/hook/unknown").status_code, 404)
        self.assertEqual(self.client.get("/painel").status_code, 302)


if __name__ == "__main__":
    unittest.main()
