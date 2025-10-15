import requests
from device_info import DeviceEnvironmentSDK

"""
IP Location SDK - Coleta de Dados com Geolocalização
Desenvolvido para TCC - Curso de Cyber Segurança

Funcionalidades:
- Geolocalização por IP com múltiplos provedores
- Rastreamento de sessão e autenticação
- Arquitetura baseada em Provider Interface
- Coleta abrangente de dados de segurança
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union, Any
from datetime import datetime, timedelta
import requests
import json
import logging
from enum import Enum
import hashlib
import time
from device_info import DeviceEnvironmentSDK

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

session_id = "sess_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


class AuthMethod(Enum):
    """Métodos de autenticação suportados"""
    PASSWORD = "password"
    MFA = "mfa"
    SSO = "sso"
    BIOMETRIC = "biometric"
    TOKEN = "token"


class AuthResult(Enum):
    """Resultados possíveis de autenticação"""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    EXPIRED = "expired"


class GeoLocationData:
    """Classe para padronizar dados de geolocalização"""
    
    def __init__(self):
        self.ip: str = ""
        self.country: str = ""
        self.country_code: str = ""
        self.city: str = ""
        self.region: str = ""
        self.latitude: float = 0.0
        self.longitude: float = 0.0
        self.timezone: str = ""
        self.isp: str = ""
        self.organization: str = ""
        self.is_proxy: bool = False
        self.is_vpn: bool = False
        self.threat_level: str = "low"
        self.timestamp: datetime = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "isp": self.isp,
            "organization": self.organization,
            "is_proxy": self.is_proxy,
            "is_vpn": self.is_vpn,
            "threat_level": self.threat_level,
            "timestamp": self.timestamp.isoformat()
        }


class SessionData:
    """Classe para dados da sessão do usuário"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.now()
        self.last_activity = datetime.now()
        self.duration = timedelta(0)
        self.page_views = 0
        self.actions_count = 0
        self.is_active = True
    
    def update_activity(self):
        """Atualiza última atividade e calcula duração"""
        self.last_activity = datetime.now()
        self.duration = self.last_activity - self.start_time
        self.actions_count += 1
    
    def end_session(self):
        """Finaliza a sessão"""
        self.is_active = False
        self.duration = datetime.now() - self.start_time
    
    def get_session_time_minutes(self) -> float:
        """Retorna tempo de sessão em minutos"""
        if self.is_active:
            current_duration = datetime.now() - self.start_time
        else:
            current_duration = self.duration
        return current_duration.total_seconds() / 60


class RequestOriginData:
    """Classe para dados de origem da requisição"""
    
    def __init__(self):
        self.url: str = ""
        self.referer: str = ""
        self.entry_route: str = ""
        self.user_agent_http: str = ""
        self.user_agent_https: str = ""
        self.headers: Dict[str, str] = {}
        self.method: str = "GET"
        self.protocol: str = "HTTP/1.1"
        self.timestamp: datetime = datetime.now()


class AuthenticationData:
    """Classe para dados de autenticação"""
    
    def __init__(self):
        self.user_id: Optional[str] = None
        self.username: Optional[str] = None
        self.auth_method: AuthMethod = AuthMethod.PASSWORD
        self.auth_result: AuthResult = AuthResult.FAILED
        self.failure_reason: Optional[str] = None
        self.consecutive_failures: int = 0
        self.last_success: Optional[datetime] = None
        self.last_failure: Optional[datetime] = None
        self.ip_address: str = ""
        self.timestamp: datetime = datetime.now()
        self.session_id: Optional[str] = None


# ============= PROVIDER INTERFACE =============

class GeoLocationProviderInterface(ABC):
    """Interface abstrata para provedores de geolocalização"""
    
    @abstractmethod
    def get_location(self, ip_address: str) -> GeoLocationData:
        """Método abstrato para obter localização por IP"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Verifica se o provedor está disponível"""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Retorna nome do provedor"""
        pass


# ============= IMPLEMENTAÇÕES DE PROVEDORES =============

class IPInfoProvider(GeoLocationProviderInterface):
    """Provedor usando IPInfo.io"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://ipinfo.io"
    
    def get_location(self, ip_address: str) -> GeoLocationData:
        """Obtém localização usando IPInfo"""
        geo_data = GeoLocationData()
        geo_data.ip = ip_address
        
        try:
            url = f"{self.base_url}/{ip_address}/json"
            params = {"token": self.api_key} if self.api_key else {}
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Mapear dados do IPInfo para nosso formato
            geo_data.country = data.get("country", "")
            geo_data.city = data.get("city", "")
            geo_data.region = data.get("region", "")
            
            # Processar coordenadas
            if "loc" in data:
                coords = data["loc"].split(",")
                geo_data.latitude = float(coords[0]) if len(coords) > 0 else 0.0
                geo_data.longitude = float(coords[1]) if len(coords) > 1 else 0.0
            
            geo_data.timezone = data.get("timezone", "")
            geo_data.isp = data.get("org", "")
            
            logger.info(f"IPInfo: Localização obtida para IP {ip_address}")
            
        except Exception as e:
            logger.error(f"Erro ao consultar IPInfo para IP {ip_address}: {str(e)}")
            
        return geo_data
    
    def is_available(self) -> bool:
        """Testa disponibilidade do IPInfo"""
        try:
            response = requests.get(f"{self.base_url}/8.8.8.8/json", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_provider_name(self) -> str:
        return "IPInfo.io"


class IPAPIProvider(GeoLocationProviderInterface):
    """Provedor usando IP-API.com"""
    
    def __init__(self):
        self.base_url = "http://ip-api.com/json"
    
    def get_location(self, ip_address: str) -> GeoLocationData:
        """Obtém localização usando IP-API"""
        geo_data = GeoLocationData()
        geo_data.ip = ip_address
        
        try:
            url = f"{self.base_url}/{ip_address}"
            params = {
                "fields": "status,message,country,countryCode,region,city,lat,lon,timezone,isp,org,proxy"
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "success":
                geo_data.country = data.get("country", "")
                geo_data.country_code = data.get("countryCode", "")
                geo_data.city = data.get("city", "")
                geo_data.region = data.get("region", "")
                geo_data.latitude = data.get("lat", 0.0)
                geo_data.longitude = data.get("lon", 0.0)
                geo_data.timezone = data.get("timezone", "")
                geo_data.isp = data.get("isp", "")
                geo_data.organization = data.get("org", "")
                geo_data.is_proxy = data.get("proxy", False)
                
                logger.info(f"IP-API: Localização obtida para IP {ip_address}")
            else:
                logger.warning(f"IP-API retornou erro para IP {ip_address}: {data.get('message', 'Unknown error')}")
                
        except Exception as e:
            logger.error(f"Erro ao consultar IP-API para IP {ip_address}: {str(e)}")
            
        return geo_data
    
    def is_available(self) -> bool:
        """Testa disponibilidade do IP-API"""
        try:
            response = requests.get(f"{self.base_url}/8.8.8.8", timeout=5)
            data = response.json()
            return data.get("status") == "success"
        except:
            return False
    
    def get_provider_name(self) -> str:
        return "IP-API.com"


class MockGeoProvider(GeoLocationProviderInterface):
    """Provedor mock para testes e desenvolvimento"""
    
    def get_location(self, ip_address: str) -> GeoLocationData:
        """Retorna dados simulados"""
        geo_data = GeoLocationData()
        geo_data.ip = ip_address
        geo_data.country = "Brazil"
        geo_data.country_code = "BR"
        geo_data.city = "São Paulo"
        geo_data.region = "SP"
        geo_data.latitude = -23.5505
        geo_data.longitude = -46.6333
        geo_data.timezone = "America/Sao_Paulo"
        geo_data.isp = "Mock ISP"
        
        logger.info(f"Mock Provider: Dados simulados para IP {ip_address}")
        return geo_data
    
    def is_available(self) -> bool:
        return True
    
    def get_provider_name(self) -> str:
        return "Mock Provider"


# ============= CLASSE PRINCIPAL =============

class IPLocationSDK:
    """SDK principal para coleta de dados de geolocalização e sessão"""
    
    def __init__(self):
        self.providers: List[GeoLocationProviderInterface] = []
        self.sessions: Dict[str, SessionData] = {}
        self.auth_attempts: Dict[str, List[AuthenticationData]] = {}
        self.default_provider_index = 0
        
        # Configurar provedores padrão
        self._setup_default_providers()
    
    def _setup_default_providers(self):
        """Configura provedores padrão"""
        self.providers = [
            IPAPIProvider(),
            IPInfoProvider(),
            MockGeoProvider()  # Fallback
        ]
    
    def add_provider(self, provider: GeoLocationProviderInterface):
        """Adiciona um novo provedor"""
        self.providers.append(provider)
        logger.info(f"Provedor adicionado: {provider.get_provider_name()}")
    
    def get_ip_location(self, ip_address: str, retry_on_failure: bool = True) -> Optional[GeoLocationData]:
        """
        Obtém localização do IP usando o primeiro provedor disponível
        
        Args:
            ip_address: IP para localizar
            retry_on_failure: Se deve tentar outros provedores em caso de falha
            
        Returns:
            GeoLocationData ou None se falhar
        """
        if not self.providers:
            logger.error("Nenhum provedor de geolocalização configurado")
            return None
        
        # Tentar provedor padrão primeiro
        for i, provider in enumerate(self.providers):
            try:
                if provider.is_available():
                    location_data = provider.get_location(ip_address)
                    if location_data and location_data.country:  # Verificar se obteve dados válidos
                        logger.info(f"Localização obtida via {provider.get_provider_name()}")
                        return location_data
                else:
                    logger.warning(f"Provedor {provider.get_provider_name()} não está disponível")
                    
            except Exception as e:
                logger.error(f"Erro ao usar provedor {provider.get_provider_name()}: {str(e)}")
                
            if not retry_on_failure:
                break
        
        logger.error(f"Falha ao obter localização para IP {ip_address} com todos os provedores")
        return None
    
    def create_session(self, session_id: str) -> SessionData:
        """Cria uma nova sessão"""
        session = SessionData(session_id)
        self.sessions[session_id] = session
        logger.info(f"Nova sessão criada: {session_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Obtém sessão existente"""
        return self.sessions.get(session_id)
    
    def update_session_activity(self, session_id: str):
        """Atualiza atividade da sessão"""
        if session_id in self.sessions:
            self.sessions[session_id].update_activity()
    
    def end_session(self, session_id: str):
        """Finaliza uma sessão"""
        if session_id in self.sessions:
            self.sessions[session_id].end_session()
            logger.info(f"Sessão finalizada: {session_id} - Duração: {self.sessions[session_id].get_session_time_minutes():.2f} minutos")
    
    def record_auth_attempt(self, auth_data: AuthenticationData):
        """Registra tentativa de autenticação"""
        user_key = auth_data.username or auth_data.ip_address
        
        if user_key not in self.auth_attempts:
            self.auth_attempts[user_key] = []
        
        # Calcular tentativas consecutivas de falha
        if auth_data.auth_result == AuthResult.FAILED:
            recent_attempts = [a for a in self.auth_attempts[user_key] 
                             if a.timestamp > datetime.now() - timedelta(hours=1)]
            consecutive_failures = len([a for a in recent_attempts 
                                      if a.auth_result == AuthResult.FAILED])
            auth_data.consecutive_failures = consecutive_failures + 1
        else:
            auth_data.consecutive_failures = 0
        
        self.auth_attempts[user_key].append(auth_data)
        
        logger.info(f"Tentativa de auth registrada: {auth_data.auth_result.value} - "
                   f"Falhas consecutivas: {auth_data.consecutive_failures}")
    
    def get_user_auth_history(self, user_identifier: str, hours: int = 24) -> List[AuthenticationData]:
        """Obtém histórico de autenticação do usuário"""
        if user_identifier not in self.auth_attempts:
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [auth for auth in self.auth_attempts[user_identifier] 
                if auth.timestamp > cutoff_time]
    
    def analyze_security_risk(self, ip_address: str, session_id: str) -> Dict[str, Any]:
        """Análise de risco de segurança baseada nos dados coletados"""
        risk_analysis = {
            "ip_address": ip_address,
            "session_id": session_id,
            "risk_level": "low",
            "risk_factors": [],
            "recommendations": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Obter dados de localização
        geo_data = self.get_ip_location(ip_address)
        if geo_data:
            if geo_data.is_proxy or geo_data.is_vpn:
                risk_analysis["risk_factors"].append("Uso de proxy/VPN detectado")
                risk_analysis["risk_level"] = "medium"
        
        # Analisar sessão
        session = self.get_session(session_id)
        if session:
            if session.get_session_time_minutes() < 1:
                risk_analysis["risk_factors"].append("Sessão muito curta")
            elif session.get_session_time_minutes() > 480:  # 8 horas
                risk_analysis["risk_factors"].append("Sessão excessivamente longa")
        
        # Analisar tentativas de autenticação
        auth_history = self.get_user_auth_history(ip_address, 1)
        failed_attempts = len([a for a in auth_history if a.auth_result == AuthResult.FAILED])
        
        if failed_attempts > 5:
            risk_analysis["risk_factors"].append(f"Múltiplas falhas de autenticação ({failed_attempts})")
            risk_analysis["risk_level"] = "high"
        elif failed_attempts > 2:
            risk_analysis["risk_factors"].append(f"Algumas falhas de autenticação ({failed_attempts})")
            if risk_analysis["risk_level"] == "low":
                risk_analysis["risk_level"] = "medium"
        
        # Gerar recomendações
        if risk_analysis["risk_level"] == "high":
            risk_analysis["recommendations"].extend([
                "Implementar CAPTCHA",
                "Considerar bloqueio temporário do IP",
                "Requerer autenticação adicional"
            ])
        elif risk_analysis["risk_level"] == "medium":
            risk_analysis["recommendations"].extend([
                "Monitorar atividade do usuário",
                "Implementar rate limiting"
            ])
        
        return risk_analysis
    
    def generate_comprehensive_report(self, ip_address: str, session_id: str) -> Dict[str, Any]:
        """Gera relatório completo dos dados coletados"""
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "ip_address": ip_address,
                "session_id": session_id
            },
            "geolocation": {},
            "session_data": {},
            "authentication_history": [],
            "security_analysis": {},
            "summary": {}
        }
        
        # Dados de geolocalização
        geo_data = self.get_ip_location(ip_address)
        if geo_data:
            report["geolocation"] = geo_data.to_dict()
        
        # Dados de sessão
        session = self.get_session(session_id)
        if session:
            report["session_data"] = {
                "session_id": session.session_id,
                "start_time": session.start_time.isoformat(),
                "duration_minutes": session.get_session_time_minutes(),
                "page_views": session.page_views,
                "actions_count": session.actions_count,
                "is_active": session.is_active
            }
        
        # Histórico de autenticação
        auth_history = self.get_user_auth_history(ip_address, 24)
        report["authentication_history"] = [
            {
                "timestamp": auth.timestamp.isoformat(),
                "method": auth.auth_method.value,
                "result": auth.auth_result.value,
                "consecutive_failures": auth.consecutive_failures,
                "failure_reason": auth.failure_reason
            }
            for auth in auth_history
        ]
        
        # Análise de segurança
        report["security_analysis"] = self.analyze_security_risk(ip_address, session_id)
        
        # Resumo
        report["summary"] = {
            "total_auth_attempts": len(auth_history),
            "failed_auth_attempts": len([a for a in auth_history if a.auth_result == AuthResult.FAILED]),
            "session_duration_minutes": session.get_session_time_minutes() if session else 0,
            "location_detected": bool(geo_data and geo_data.country),
            "risk_level": report["security_analysis"]["risk_level"]
        }
        
        return report


# ============= EXEMPLO DE USO =============

def exemplo_uso():
    """Demonstração de uso da SDK"""
    print("=== Demonstração IP Location SDK ===\n")
    
    # Inicializar SDK
    sdk = IPLocationSDK()
    
    # Simular dados de uma requisição
    device = DeviceEnvironmentSDK()
    retorno_network = device.get_network_info()
    ip_teste = retorno_network["public_ip"]  # IP do Google DNS para teste
    
    
    print(f"Testando com IP: {ip_teste}")
    print(f"Session ID: {session_id}\n")
    
    # 1. Criar sessão
    print("1. Criando sessão...")
    session = sdk.create_session(session_id)
    time.sleep(1)  # Simular atividade
    
    # 2. Obter localização
    print("2. Obtendo geolocalização...")
    location = sdk.get_ip_location(ip_teste)
    if location:
        print(f"   País: {location.country}")
        print(f"   Cidade: {location.city}")
        print(f"   ISP: {location.isp}")
    
    # 3. Simular tentativas de autenticação
    print("\n3. Simulando tentativas de autenticação...")
    
    # Tentativa falhada
    auth_fail = AuthenticationData()
    auth_fail.username = "user_teste"
    auth_fail.ip_address = ip_teste
    auth_fail.auth_method = AuthMethod.PASSWORD
    auth_fail.auth_result = AuthResult.FAILED
    auth_fail.failure_reason = "Senha incorreta"
    auth_fail.session_id = session_id
    
    sdk.record_auth_attempt(auth_fail)
    
    # Tentativa bem-sucedida
    auth_success = AuthenticationData()
    auth_success.username = "user_teste"
    auth_success.ip_address = ip_teste
    auth_success.auth_method = AuthMethod.PASSWORD
    auth_success.auth_result = AuthResult.SUCCESS
    auth_success.session_id = session_id
    
    sdk.record_auth_attempt(auth_success)
    
    # 4. Atualizar atividade da sessão
    print("4. Simulando atividade na sessão...")
    for i in range(3):
        sdk.update_session_activity(session_id)
        time.sleep(0.5)
    
    # 5. Gerar relatório completo
    print("\n5. Gerando relatório completo...")
    relatorio = sdk.generate_comprehensive_report(ip_teste, session_id)
    
    print(f"\n=== RELATÓRIO COMPLETO ===")
    print(f"Risco: {relatorio['security_analysis']['risk_level'].upper()}")
    print(f"Duração da sessão: {relatorio['summary']['session_duration_minutes']:.2f} minutos")
    print(f"Tentativas de auth: {relatorio['summary']['total_auth_attempts']}")
    print(f"Localização detectada: {'Sim' if relatorio['summary']['location_detected'] else 'Não'}")
    
    # 6. Finalizar sessão
    sdk.end_session(session_id)
    
    return relatorio


if __name__ == "__main__":
    exemplo_uso()
