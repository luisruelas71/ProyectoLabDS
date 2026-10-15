import unittest

from auth_system import TeacherAuthService


class TeacherAuthServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = TeacherAuthService(
            users={"profesor": TeacherAuthService.hash_password("clave-segura")}
        )

    def test_login_valid_credentials_grants_access(self) -> None:
        session = self.service.login("profesor", "clave-segura")

        self.assertIsNotNone(session)
        assert session is not None
        self.assertTrue(session.access_granted)
        self.assertEqual(session.role, "teacher")
        self.assertEqual(session.username, "profesor")

    def test_login_invalid_password_denies_access(self) -> None:
        session = self.service.login("profesor", "clave-incorrecta")

        self.assertIsNone(session)

    def test_login_unknown_user_denies_access(self) -> None:
        session = self.service.login("otro-profesor", "clave-segura")

        self.assertIsNone(session)


if __name__ == "__main__":
    unittest.main()
