import logging

class Rastreador_de_Sessão_e_Autenticação:
    def __init__(self):
        self.login_attempts_by_ip = {}
        self.login_attempts_by_user = {}

        logging.basicConfig(
            filename='session_events.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def log_session_start(self, user_id):
        logging.info(f"Session started for user: {user_id}")

    def log_session_end(self, user_id):
        logging.info(f"Session ended for user: {user_id}")

    def log_token_revocation(self, user_id, token_id):
        logging.info(f"Token revoked for user: {user_id}, token: {token_id}")

    def record_login_attempt(self, user_id, ip_address, success, login_method, failure_reason=None):
        if ip_address not in self.login_attempts_by_ip:
            self.login_attempts_by_ip[ip_address] = 0

        if user_id not in self.login_attempts_by_user:
            self.login_attempts_by_user[user_id] = 0

        if success:
            self.login_attempts_by_ip[ip_address] = 0
            self.login_attempts_by_user[user_id] = 0
            logging.info(
                f"Authentication SUCCESS for user: {user_id} from IP: {ip_address} using method: {login_method}"
            )
        else:
            self.login_attempts_by_ip[ip_address] += 1
            self.login_attempts_by_user[user_id] += 1
            logging.warning(
                f"Authentication FAILURE for user: {user_id} from IP: {ip_address} using method: {login_method} "
                f"(Attempt {self.login_attempts_by_user[user_id]} for user, {self.login_attempts_by_ip[ip_address]} for IP). "
                f"Reason: {failure_reason if failure_reason else 'Unknown'}"
            )
